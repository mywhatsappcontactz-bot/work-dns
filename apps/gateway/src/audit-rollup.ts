import type { AuditEventStore } from '@work-dns/events';
import type { DnsBlockedPayload } from '@work-dns/shared-types';
import { toPayload } from './audit-sink.js';
import type { BlockedAttemptRecord, BlockedAttemptSink } from './event-queue.js';

type RollupLog = (level: 'info' | 'error', message: string, fields?: Record<string, unknown>) => void;

export const DEFAULT_ROLLUP_WINDOW_MS = 300_000;

export interface RollupOptions {
  /** How long repeats of one attempt are rolled up after its first sighting (default 5 minutes). */
  windowMs?: number;
  /** Open windows kept in memory. Beyond this, new attempts are written in full (default 10000). */
  maxKeys?: number;
  /** Processed record ids remembered so a retried batch is not counted twice (default 20000). */
  maxSeenIds?: number;
  /** How often closed windows are written out (default 30 seconds). */
  sweepIntervalMs?: number;
  /** Clock in epoch milliseconds (injectable for tests). */
  now?: () => number;
  log?: RollupLog;
}

export interface RollupAuditSink {
  sink: BlockedAttemptSink;
  /** Starts the periodic sweep that writes out closed windows. */
  start(): void;
  /** Writes a roll-up entry for every window that has closed. */
  flushDue(): void;
  /** Writes a roll-up entry for every open window, ending it now. Use at shutdown. */
  flushAll(): void;
  /** Stops the sweep and writes out every open window. */
  stop(): void;
  openWindows(): number;
}

interface RollupWindow {
  first: BlockedAttemptRecord;
  startMs: number;
  endMs: number;
  pending: number;
  firstRepeatAt: string | undefined;
  lastSeenAt: string | undefined;
}

function defaultLog(level: 'info' | 'error', message: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ level, message, ...fields });
  if (level === 'error') {
    console.error(line);
  } else {
    console.log(line);
  }
}

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function positive(name: string, value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new RangeError(`createRollupAuditSink: ${name} must be greater than zero`);
  }
  return value;
}

function keyOf(r: BlockedAttemptRecord): string {
  return JSON.stringify([r.companyId, r.deviceId, r.domain, r.reasonCode, r.policyVersion, r.loggedOsUser]);
}

function later(current: string | undefined, candidate: string): string {
  if (current === undefined) return candidate;
  return Date.parse(candidate) > Date.parse(current) ? candidate : current;
}

/**
 * Writes the first attempt of each (device, domain, reason, policy, user) at once and rolls repeats inside
 * the next window into one summary entry. Counts are never dropped silently: a failed write keeps the
 * counts and retries. Limit: counts still held in memory are lost if the gateway crashes (the first
 * sighting is already stored). The store assigns sequence numbers and hashes, never this code.
 */
export function createRollupAuditSink(
  store: Pick<AuditEventStore, 'append' | 'hasEvent'>,
  options: RollupOptions = {}
): RollupAuditSink {
  const windowMs = positive('windowMs', options.windowMs ?? DEFAULT_ROLLUP_WINDOW_MS);
  const maxKeys = positive('maxKeys', options.maxKeys ?? 10_000);
  const maxSeenIds = positive('maxSeenIds', options.maxSeenIds ?? 20_000);
  const sweepIntervalMs = positive('sweepIntervalMs', options.sweepIntervalMs ?? 30_000);
  const now = options.now ?? Date.now;
  const log = options.log ?? defaultLog;

  const windows = new Map<string, RollupWindow>();
  const seen = new Set<string>();
  let timer: NodeJS.Timeout | null = null;

  const remember = (id: string): void => {
    seen.add(id);
    if (seen.size > maxSeenIds) {
      const oldest = seen.values().next();
      if (!oldest.done) seen.delete(oldest.value);
    }
  };

  const writeFirstSighting = (record: BlockedAttemptRecord): void => {
    if (store.hasEvent(record.id)) return;
    store.append({
      id: record.id,
      type: 'dns_blocked',
      companyId: record.companyId,
      deviceId: record.deviceId,
      payload: toPayload(record),
    });
  };

  const writeRollup = (w: RollupWindow, endMs: number): void => {
    const id = `rollup:${w.first.id}`;
    if (store.hasEvent(id)) return;
    const payload: DnsBlockedPayload = {
      domain: w.first.domain,
      loggedOsUser: w.first.loggedOsUser,
      policyVersion: w.first.policyVersion,
      reasonCode: w.first.reasonCode,
      rollup: true,
      count: w.pending,
      firstSeenAt: w.firstRepeatAt ?? w.first.occurredAt,
      lastSeenAt: w.lastSeenAt ?? w.first.occurredAt,
      windowStart: new Date(w.startMs).toISOString(),
      windowEnd: new Date(endMs).toISOString(),
      ...(w.first.clientIp !== undefined ? { clientIp: w.first.clientIp } : {}),
    };
    store.append({ id, type: 'dns_blocked', companyId: w.first.companyId, deviceId: w.first.deviceId, payload });
  };

  /** Writes the roll-up if any repeats were counted, then forgets the window. Throws if the write fails; the window is kept. */
  const closeWindow = (key: string, w: RollupWindow, endMs: number): void => {
    if (w.pending > 0) writeRollup(w, endMs);
    windows.delete(key);
  };

  const handle = (record: BlockedAttemptRecord): void => {
    const nowMs = now();
    const key = keyOf(record);
    let w = windows.get(key);
    if (w !== undefined && nowMs >= w.endMs) {
      closeWindow(key, w, w.endMs);
      w = undefined;
    }
    if (w !== undefined) {
      w.pending += record.count;
      if (w.firstRepeatAt === undefined) w.firstRepeatAt = record.occurredAt;
      w.lastSeenAt = later(w.lastSeenAt, record.lastSeenAt ?? record.occurredAt);
      return;
    }
    writeFirstSighting(record);
    // At the cap no window is opened, so the next attempt is written in full: more volume, nothing lost.
    if (windows.size < maxKeys) {
      windows.set(key, {
        first: record,
        startMs: nowMs,
        endMs: nowMs + windowMs,
        pending: 0,
        firstRepeatAt: undefined,
        lastSeenAt: undefined,
      });
    }
  };

  const sink: BlockedAttemptSink = async (records) => {
    for (const record of records) {
      if (seen.has(record.id)) continue; // a retried batch: this record was already handled
      handle(record);
      remember(record.id);
    }
  };

  const flushDue = (): void => {
    const nowMs = now();
    for (const [key, w] of [...windows]) {
      if (nowMs < w.endMs) continue;
      try {
        closeWindow(key, w, w.endMs);
      } catch (err) {
        log('error', 'could not write a rollup entry; will retry', { domain: w.first.domain, repeats: w.pending, error: errorMessageOf(err) });
      }
    }
  };

  const flushAll = (): void => {
    const nowMs = now();
    for (const [key, w] of [...windows]) {
      try {
        closeWindow(key, w, Math.min(w.endMs, nowMs));
      } catch (err) {
        log('error', 'could not write a rollup entry at shutdown: these repeat counts are lost', {
          domain: w.first.domain,
          repeats: w.pending,
          error: errorMessageOf(err),
        });
      }
    }
  };

  return {
    sink,
    start: () => {
      if (timer) return;
      timer = setInterval(flushDue, sweepIntervalMs);
      timer.unref?.();
    },
    flushDue,
    flushAll,
    stop: () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
      flushAll();
    },
    openWindows: () => windows.size,
  };
}
