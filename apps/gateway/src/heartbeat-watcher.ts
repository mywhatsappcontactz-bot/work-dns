import type { AuditEventStore } from '@work-dns/events';
import type { CompanyId, DeviceId, HeartbeatMissedPayload, HeartbeatResumedPayload } from '@work-dns/shared-types';
import type { AuthenticatedDeviceContext } from './auth.js';

type HeartbeatLog = (level: 'info' | 'error', message: string, fields?: Record<string, unknown>) => void;

export const DEFAULT_HEARTBEAT_THRESHOLD_MS = 300_000;

export interface HeartbeatWatcherOptions {
  /** Silence longer than this is reported (default 5 minutes). */
  thresholdMs?: number;
  /** How often silent devices are looked for (default half the threshold, between 1 and 30 seconds). */
  sweepIntervalMs?: number;
  /** Devices tracked at once (default 10000). */
  maxDevices?: number;
  /** Clock in epoch milliseconds (injectable for tests). */
  now?: () => number;
  log?: HeartbeatLog;
}

interface TrackedDevice {
  companyId: CompanyId;
  deviceId: DeviceId;
  lastSeenMs: number;
  /** Whether lastSeenMs came from a real request or from the gateway's own start. */
  lastSeenFrom: 'request' | 'gateway_start';
  state: 'ok' | 'silent' | 'resuming';
  /** lastSeenMs at the moment the silence was reported. */
  outageStartMs: number;
  /** Where outageStartMs came from. */
  outageStartFrom: 'request' | 'gateway_start';
  /** When the device was first heard from again. */
  resumedAtMs: number;
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
    throw new RangeError(`HeartbeatWatcher: ${name} must be greater than zero`);
  }
  return value;
}

const iso = (ms: number): string => new Date(ms).toISOString();
const keyOf = (context: AuthenticatedDeviceContext): string => `${context.companyId}\u0000${context.deviceId}`;

/**
 * Notices devices that have gone quiet. Any authenticated request counts as a sign of life. The gateway
 * writes one heartbeat_missed entry per outage (a witnessed entry: the gateway saw the silence) and one
 * heartbeat_resumed entry when the device returns. Silence is ambiguous: a closed laptop and a killed agent
 * look the same, so a reader must weigh it against the surrounding entries.
 * Limits: state is in memory, so after a gateway restart every active device counts as seen "now" and a
 * long outage can be reported twice. stop() writes nothing, so gateway downtime is never blamed on devices.
 */
export class HeartbeatWatcher {
  private readonly store: Pick<AuditEventStore, 'append' | 'hasEvent'>;
  private readonly thresholdMs: number;
  private readonly sweepIntervalMs: number;
  private readonly maxDevices: number;
  private readonly now: () => number;
  private readonly log: HeartbeatLog;
  private readonly tracked = new Map<string, TrackedDevice>();
  private timer: NodeJS.Timeout | null = null;
  private warnedFull = false;

  constructor(store: Pick<AuditEventStore, 'append' | 'hasEvent'>, options: HeartbeatWatcherOptions = {}) {
    this.store = store;
    this.thresholdMs = positive('thresholdMs', options.thresholdMs ?? DEFAULT_HEARTBEAT_THRESHOLD_MS);
    this.sweepIntervalMs = positive(
      'sweepIntervalMs',
      options.sweepIntervalMs ?? Math.max(1_000, Math.min(30_000, Math.floor(this.thresholdMs / 2)))
    );
    this.maxDevices = positive('maxDevices', options.maxDevices ?? 10_000);
    this.now = options.now ?? Date.now;
    this.log = options.log ?? defaultLog;
  }

  /** Starts watching every active device, counting each as seen now. Call once at startup. */
  public seed(contexts: readonly AuthenticatedDeviceContext[]): void {
    const nowMs = this.now();
    for (const context of contexts) {
      if (context.status !== 'active') continue;
      this.track(context, nowMs, 'gateway_start');
    }
  }

  /** Records a sign of life. Cheap and never throws: it runs on every authenticated request. */
  public touch(context: AuthenticatedDeviceContext): void {
    if (context.status !== 'active') return;
    const nowMs = this.now();
    const entry = this.track(context, nowMs);
    if (entry === undefined) return;
    entry.lastSeenMs = nowMs;
    entry.lastSeenFrom = 'request';
    if (entry.state === 'silent') {
      entry.state = 'resuming';
      entry.resumedAtMs = nowMs;
      this.tryResume(entry);
    }
  }

  /** Reports devices that have been silent too long, and retries any entry that failed to write. */
  public sweep(): void {
    const nowMs = this.now();
    for (const entry of this.tracked.values()) {
      if (entry.state === 'resuming') {
        this.tryResume(entry);
        continue;
      }
      if (entry.state === 'ok' && nowMs - entry.lastSeenMs >= this.thresholdMs) {
        this.declareMissed(entry, nowMs);
      }
    }
  }

  public start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => this.sweep(), this.sweepIntervalMs);
    this.timer.unref?.();
  }

  /** Stops the sweep. Writes nothing: a stopped gateway must not blame devices for its own downtime. */
  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  public trackedDevices(): number {
    return this.tracked.size;
  }

  /** Devices currently reported silent (including ones whose resume entry is still being written). */
  public silentDevices(): number {
    let count = 0;
    for (const entry of this.tracked.values()) {
      if (entry.state !== 'ok') count += 1;
    }
    return count;
  }

  private track(
    context: AuthenticatedDeviceContext,
    nowMs: number,
    from: 'request' | 'gateway_start' = 'request'
  ): TrackedDevice | undefined {
    const key = keyOf(context);
    const existing = this.tracked.get(key);
    if (existing !== undefined) return existing;
    if (this.tracked.size >= this.maxDevices) {
      if (!this.warnedFull) {
        this.warnedFull = true;
        this.log('error', 'too many devices to track heartbeats: some devices are not watched', { maxDevices: this.maxDevices });
      }
      return undefined;
    }
    const entry: TrackedDevice = {
      companyId: context.companyId,
      deviceId: context.deviceId,
      lastSeenMs: nowMs,
      lastSeenFrom: from,
      state: 'ok',
      outageStartMs: 0,
      outageStartFrom: from,
      resumedAtMs: 0,
    };
    this.tracked.set(key, entry);
    return entry;
  }

  private declareMissed(entry: TrackedDevice, nowMs: number): void {
    const id = `hb-missed:${entry.companyId}:${entry.deviceId}:${entry.lastSeenMs}`;
    const payload: HeartbeatMissedPayload = {
      lastSeenAt: iso(entry.lastSeenMs),
      thresholdSeconds: Math.round(this.thresholdMs / 1000),
      detectedAt: iso(nowMs),
      lastSeenSource: entry.lastSeenFrom,
    };
    try {
      if (!this.store.hasEvent(id)) {
        this.store.append({ id, type: 'heartbeat_missed', companyId: entry.companyId, deviceId: entry.deviceId, payload });
      }
      entry.state = 'silent';
      entry.outageStartMs = entry.lastSeenMs;
      entry.outageStartFrom = entry.lastSeenFrom;
    } catch (err) {
      this.log('error', 'could not record a missed heartbeat; will retry', { deviceId: entry.deviceId, error: errorMessageOf(err) });
    }
  }

  private tryResume(entry: TrackedDevice): void {
    const id = `hb-resumed:${entry.companyId}:${entry.deviceId}:${entry.outageStartMs}`;
    const payload: HeartbeatResumedPayload = {
      lastSeenAt: iso(entry.outageStartMs),
      resumedAt: iso(entry.resumedAtMs),
      gapSeconds: Math.max(0, Math.round((entry.resumedAtMs - entry.outageStartMs) / 1000)),
      lastSeenSource: entry.outageStartFrom,
    };
    try {
      if (!this.store.hasEvent(id)) {
        this.store.append({ id, type: 'heartbeat_resumed', companyId: entry.companyId, deviceId: entry.deviceId, payload });
      }
      entry.state = 'ok';
    } catch (err) {
      this.log('error', 'could not record a resumed heartbeat; will retry', { deviceId: entry.deviceId, error: errorMessageOf(err) });
    }
  }
}
