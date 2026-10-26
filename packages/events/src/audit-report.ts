import type { CompanyId, EventEnvelope, EventType } from '@work-dns/shared-types';
import { verifyCheckpoints } from './checkpoint.js';
import type { Checkpoint, CheckpointSource } from './checkpoint.js';
import { verifyEventChain } from './hash-chain.js';

export interface EventFilter {
  deviceId?: string;
  /** Matches this domain and its subdomains. */
  domain?: string;
  types?: EventType[];
  /** Inclusive lower bound on occurredAt (ISO 8601). */
  from?: string;
  /** Exclusive upper bound on occurredAt (ISO 8601). */
  to?: string;
}

export type Integrity = 'verified' | 'partial' | 'failed';

export interface AuditReport {
  companyId: CompanyId;
  generatedAt: string;
  totalEvents: number;
  matchedEvents: number;
  filter: EventFilter;
  integrity: Integrity;
  chain: { valid: boolean; error: string | null };
  checkpoints:
    | { supplied: false }
    | {
        supplied: true;
        valid: boolean;
        error: string | null;
        checked: number;
        anchoredThroughSequence: number;
        unanchoredEvents: number;
      };
  byType: Record<string, number>;
  /** Sum of the merged attempt counts of matched dns_blocked events. */
  blockedAttempts: number;
  topDomains: Array<{ domain: string; attempts: number }>;
  /** Matched dns_blocked events with no verified OS user. */
  unattributedBlocks: number;
  caveats: string[];
}

export interface BuildReportOptions {
  filter?: EventFilter;
  checkpoints?: Checkpoint[] | null;
  publicKeys?: Record<string, string>;
  now?: () => Date;
  topN?: number;
}

export const CSV_COLUMNS = [
  'sequence',
  'occurredAt',
  'type',
  'deviceId',
  'domain',
  'loggedOsUser',
  'policyVersion',
  'reasonCode',
  'ruleId',
  'recordType',
  'count',
  'clientIp',
  'firstSeenAt',
  'eventId',
  'hash',
] as const;

function stringField(payload: unknown, key: string): string | undefined {
  if (typeof payload !== 'object' || payload === null) return undefined;
  const value = (payload as Record<string, unknown>)[key];
  return typeof value === 'string' ? value : undefined;
}

function numberField(payload: unknown, key: string): number | undefined {
  if (typeof payload !== 'object' || payload === null) return undefined;
  const value = (payload as Record<string, unknown>)[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function parseBound(name: string, value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) throw new RangeError(`${name} is not a valid date: ${value}`);
  return ms;
}

function normalizeDomain(value: string): string {
  const lowered = value.toLowerCase();
  return lowered.endsWith('.') ? lowered.slice(0, -1) : lowered;
}

function domainMatches(candidate: string | undefined, wanted: string): boolean {
  if (candidate === undefined) return false;
  const c = normalizeDomain(candidate);
  const w = normalizeDomain(wanted);
  return c === w || c.endsWith(`.${w}`);
}

export function filterEvents(events: EventEnvelope[], filter: EventFilter = {}): EventEnvelope[] {
  const from = parseBound('from', filter.from);
  const to = parseBound('to', filter.to);
  const types = filter.types === undefined ? undefined : new Set<string>(filter.types);
  return events.filter((event) => {
    if (filter.deviceId !== undefined && event.deviceId !== filter.deviceId) return false;
    if (types !== undefined && !types.has(event.type)) return false;
    if (filter.domain !== undefined && !domainMatches(stringField(event.payload, 'domain'), filter.domain)) return false;
    const at = Date.parse(event.occurredAt);
    if (from !== undefined && !(at >= from)) return false;
    if (to !== undefined && !(at < to)) return false;
    return true;
  });
}

function csvCell(value: string | number | null | undefined): string {
  if (value === undefined || value === null) return '';
  let text = String(value);
  // A cell that starts with = + - @ (or a control character) could run as a formula in a spreadsheet.
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  if (/[",\n\r]/.test(text)) text = `"${text.replace(/"/g, '""')}"`;
  return text;
}

export function eventsToCsv(events: EventEnvelope[]): string {
  const lines: string[] = [CSV_COLUMNS.join(',')];
  for (const event of events) {
    const p = event.payload;
    const cells = [
      event.sequenceNumber,
      event.occurredAt,
      event.type,
      event.deviceId,
      stringField(p, 'domain'),
      stringField(p, 'loggedOsUser'),
      numberField(p, 'policyVersion'),
      stringField(p, 'reasonCode'),
      stringField(p, 'ruleId'),
      stringField(p, 'recordType'),
      numberField(p, 'count'),
      stringField(p, 'clientIp'),
      stringField(p, 'firstSeenAt'),
      event.id,
      event.hash,
    ];
    lines.push(cells.map(csvCell).join(','));
  }
  return `${lines.join('\n')}\n`;
}

/**
 * Builds an audit report. Integrity is checked over the whole chain, never just the filtered rows.
 * 'verified' needs signed checkpoints and no events newer than the last one; 'partial' means nothing
 * contradicts the log but something is unprotected (the caveats say what); 'failed' means tampering.
 */
export function buildReport(source: CheckpointSource, companyId: CompanyId, options: BuildReportOptions = {}): AuditReport {
  const filter = options.filter ?? {};
  const all = source.readAll(companyId);
  const matched = filterEvents(all, filter);
  const caveats: string[] = [];

  const chainResult = verifyEventChain(all, { expectedCompanyId: companyId });
  const chain = { valid: chainResult.valid, error: chainResult.valid ? null : (chainResult.error ?? 'unknown error') };

  let checkpoints: AuditReport['checkpoints'] = { supplied: false };
  if (options.checkpoints === undefined || options.checkpoints === null) {
    caveats.push('No checkpoints were supplied: deleting the newest events cannot be detected, so integrity is only partly verified.');
  } else {
    const v = verifyCheckpoints(source, companyId, options.checkpoints, options.publicKeys ?? {});
    checkpoints = {
      supplied: true,
      valid: v.valid,
      error: v.valid ? null : (v.error ?? 'unknown error'),
      checked: v.checkpointsChecked,
      anchoredThroughSequence: v.anchoredThroughSequence,
      unanchoredEvents: v.unanchoredEvents,
    };
    if (v.valid) {
      caveats.push(
        'Integrity is relative to the checkpoint file supplied. Removing the newest checkpoints is only detectable against a copy kept outside the log writer\'s reach.'
      );
      if (v.unanchoredEvents > 0) {
        caveats.push(`${v.unanchoredEvents} event(s) newer than the last checkpoint are not yet protected against deletion.`);
      }
    }
  }

  let integrity: Integrity;
  if (!chain.valid || (checkpoints.supplied && !checkpoints.valid)) {
    integrity = 'failed';
  } else if (checkpoints.supplied && checkpoints.valid && checkpoints.checked > 0 && checkpoints.unanchoredEvents === 0) {
    integrity = 'verified';
  } else {
    integrity = 'partial';
  }

  const byType: Record<string, number> = {};
  const perDomain = new Map<string, number>();
  let blockedAttempts = 0;
  let unattributedBlocks = 0;
  for (const event of matched) {
    byType[event.type] = (byType[event.type] ?? 0) + 1;
    if (event.type !== 'dns_blocked') continue;
    const attempts = numberField(event.payload, 'count') ?? 1;
    blockedAttempts += attempts;
    const domain = stringField(event.payload, 'domain');
    if (domain !== undefined) {
      const key = normalizeDomain(domain);
      perDomain.set(key, (perDomain.get(key) ?? 0) + attempts);
    }
    const user = stringField(event.payload, 'loggedOsUser');
    if (user === undefined || user === '' || user === 'unknown') unattributedBlocks += 1;
  }
  if (unattributedBlocks > 0) {
    caveats.push(`${unattributedBlocks} blocked entr(ies) carry no verified OS user (loggedOsUser is "unknown"): they identify a device, not a person.`);
  }

  const topDomains = [...perDomain.entries()]
    .map(([domain, attempts]) => ({ domain, attempts }))
    .sort((a, b) => b.attempts - a.attempts || a.domain.localeCompare(b.domain))
    .slice(0, options.topN ?? 10);

  return {
    companyId,
    generatedAt: (options.now ?? (() => new Date()))().toISOString(),
    totalEvents: all.length,
    matchedEvents: matched.length,
    filter,
    integrity,
    chain,
    checkpoints,
    byType,
    blockedAttempts,
    topDomains,
    unattributedBlocks,
    caveats,
  };
}

export function formatReportText(report: AuditReport): string {
  const lines: string[] = [];
  lines.push(`Audit report for ${report.companyId}`);
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push(`Events: ${report.matchedEvents} matched of ${report.totalEvents} total`);
  lines.push(`Integrity: ${report.integrity.toUpperCase()}`);
  lines.push(`  Chain: ${report.chain.valid ? 'valid' : `BROKEN: ${report.chain.error ?? 'unknown error'}`}`);
  const cp = report.checkpoints;
  if (!cp.supplied) {
    lines.push('  Checkpoints: not supplied');
  } else if (cp.valid) {
    lines.push(`  Checkpoints: valid (${cp.checked} checked, anchored through event ${cp.anchoredThroughSequence}, ${cp.unanchoredEvents} newer)`);
  } else {
    lines.push(`  Checkpoints: INVALID: ${cp.error ?? 'unknown error'}`);
  }
  lines.push(`Blocked attempts (matched): ${report.blockedAttempts}`);
  if (report.topDomains.length > 0) {
    lines.push('Top blocked domains:');
    for (const d of report.topDomains) lines.push(`  ${String(d.attempts).padStart(6)}  ${d.domain}`);
  }
  const types = Object.keys(report.byType).sort();
  if (types.length > 0) {
    lines.push('Events by type:');
    for (const t of types) lines.push(`  ${String(report.byType[t]).padStart(6)}  ${t}`);
  }
  if (report.caveats.length > 0) {
    lines.push('Caveats:');
    for (const c of report.caveats) lines.push(`  - ${c}`);
  }
  return `${lines.join('\n')}\n`;
}
