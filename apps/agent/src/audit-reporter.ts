import type { GatewayStateChange } from './dns-stub.js';

/** Keep in sync with apps/agent/package.json. */
export const AGENT_VERSION = '0.1.0';

export interface AuditOutboxLike {
  add(type: string, payload: Record<string, unknown>): string;
}

type ReporterLog = (level: 'error', message: string, fields?: Record<string, unknown>) => void;

export interface AgentAuditReporterOptions {
  outbox: AuditOutboxLike;
  /** The stub's fail-open limit, reported when fail-open starts. */
  failOpenMaxMinutes: number;
  /** Called after an event is recorded, to prompt a delivery attempt (for example sender.kick). */
  onRecorded?: () => void;
  log?: ReporterLog;
}

const DEVICE_NAME = /^[A-Za-z0-9._:-]{1,64}$/;
const MAX_DEVICES = 16;

function defaultLog(level: 'error', message: string, fields: Record<string, unknown> = {}): void {
  console.error(JSON.stringify({ level, message, ...fields }));
}

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Drops names the gateway would refuse; an empty result becomes ["unknown"]. */
function cleanDevices(names: readonly string[]): string[] {
  const clean = names.filter((name) => DEVICE_NAME.test(name)).slice(0, MAX_DEVICES);
  return clean.length > 0 ? clean : ['unknown'];
}

/**
 * Turns things the agent observes into audit events in exactly the shape the gateway accepts
 * (apps/gateway/src/agent-events.ts rejects unknown fields). Recording never throws: a problem
 * with the outbox is logged, because reporting must not break DNS enforcement or shutdown.
 */
export class AgentAuditReporter {
  private readonly outbox: AuditOutboxLike;
  private readonly failOpenMaxMinutes: number;
  private readonly onRecorded: (() => void) | undefined;
  private readonly log: ReporterLog;
  private failOpenEnteredAt: string | null = null;

  constructor(options: AgentAuditReporterOptions) {
    if (!Number.isFinite(options.failOpenMaxMinutes) || options.failOpenMaxMinutes <= 0) {
      throw new RangeError('AgentAuditReporter: failOpenMaxMinutes must be greater than zero');
    }
    this.outbox = options.outbox;
    this.failOpenMaxMinutes = options.failOpenMaxMinutes;
    this.onRecorded = options.onRecorded;
    this.log = options.log ?? defaultLog;
  }

  public agentStarted(info: { loggedOsUser?: string; policyVersion?: number } = {}): void {
    this.record('agent_started', {
      agentVersion: AGENT_VERSION,
      os: process.platform,
      loggedOsUser: info.loggedOsUser ?? 'unknown',
      policyVersion: info.policyVersion ?? 0,
    });
  }

  public agentStopped(reason: 'signal' | 'crash_recovered' | 'error' | 'unknown', dnsRestored: boolean): void {
    this.record('agent_stopped', { reason, dnsRestored });
  }

  public enforcementApplied(devices: readonly string[], method = 'nmcli-runtime'): void {
    this.record('enforcement_applied', { networkDevices: cleanDevices(devices), method });
  }

  /** detectedAt is when the agent noticed the reset, not when NetworkManager made it. */
  public enforcementReset(detectedAt: Date, reappliedAt: Date): void {
    this.record('enforcement_reset', { detectedAt: detectedAt.toISOString(), reappliedAt: reappliedAt.toISOString() });
  }

  public enforcementRestored(
    devices: readonly string[],
    trigger: 'shutdown' | 'crash_recovery' | 'manual' | 'startup_failure',
    success: boolean
  ): void {
    this.record('enforcement_restored', { networkDevices: cleanDevices(devices), trigger, success });
  }

  public gatewayStateChanged(change: GatewayStateChange): void {
    if (change.from === 'ONLINE' && change.to === 'FAIL_OPEN_ACTIVE') {
      this.failOpenEnteredAt = change.at;
      this.record('fail_open_entered', { reason: 'gateway_unreachable', maxMinutes: this.failOpenMaxMinutes });
      return;
    }
    if (change.from === 'FAIL_OPEN_ACTIVE' && change.to === 'FAIL_CLOSED') {
      const durationSeconds = this.secondsSince(this.failOpenEnteredAt, change.at);
      this.failOpenEnteredAt = null;
      this.record('fail_open_exited', { durationSeconds, cause: 'time_limit_reached' });
      return;
    }
    if (change.from === 'FAIL_OPEN_ACTIVE' && change.to === 'ONLINE') {
      const durationSeconds = change.outageSeconds ?? this.secondsSince(this.failOpenEnteredAt, change.at);
      this.failOpenEnteredAt = null;
      this.record('fail_open_exited', { durationSeconds, cause: 'gateway_recovered' });
    }
    // FAIL_CLOSED to ONLINE has no event type on the gateway yet: a known gap.
  }

  private secondsSince(startIso: string | null, endIso: string): number {
    if (startIso === null) return 0;
    const ms = Date.parse(endIso) - Date.parse(startIso);
    return Number.isFinite(ms) ? Math.max(0, Math.round(ms / 1000)) : 0;
  }

  private record(type: string, payload: Record<string, unknown>): void {
    try {
      this.outbox.add(type, payload);
    } catch (err) {
      this.log('error', 'could not record an audit event', { type, error: errorMessageOf(err) });
      return;
    }
    try {
      this.onRecorded?.();
    } catch (err) {
      this.log('error', 'audit delivery prompt failed', { error: errorMessageOf(err) });
    }
  }
}
