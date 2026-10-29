import { randomUUID } from 'node:crypto';
import { CompanyId, DeviceId } from '@work-dns/shared-types';

/**
 * A plain blocked-attempt record. Sequence numbers and hash-chain fields are NOT
 * assigned here: the backend must assign them inside a database transaction per
 * company (see docs/api-tasks.md). Chains kept in gateway memory reset on restart
 * and fork across instances.
 */
export interface BlockedAttemptRecord {
  id: string;
  companyId: CompanyId;
  deviceId: DeviceId;
  domain: string;
  loggedOsUser: string;
  policyVersion: number;
  reasonCode: string;
  clientIp?: string;
  occurredAt: string;
  /** Number of identical attempts coalesced into this record while it was queued. */
  count: number;
  /** When the most recent attempt merged into this record happened. Unset until a second attempt is merged. */
  lastSeenAt?: string;
}

export type BlockedAttemptSink = (records: BlockedAttemptRecord[]) => Promise<void>;

export interface GatewayEventQueueOptions {
  sink?: BlockedAttemptSink;
  maxQueueSize?: number;
  maxBatchSize?: number;
  flushIntervalMs?: number;
}

const DEFAULT_MAX_QUEUE_SIZE = 10_000;
const DEFAULT_MAX_BATCH_SIZE = 100;
const DEFAULT_FLUSH_INTERVAL_MS = 5_000;
const DROP_LOG_EVERY = 1_000;

function keyOf(r: Pick<BlockedAttemptRecord, 'companyId' | 'deviceId' | 'domain'>): string {
  return JSON.stringify([r.companyId, r.deviceId, r.domain]);
}

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function log(level: 'error' | 'warn', message: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ level, message, ...fields });
  if (level === 'error') {
    console.error(line);
  } else {
    console.warn(line);
  }
}

export class GatewayEventQueue {
  private queue: BlockedAttemptRecord[] = [];
  /** Queued (not in-flight) records by key, used to coalesce repeats. */
  private pending = new Map<string, BlockedAttemptRecord>();
  private readonly sink: BlockedAttemptSink | undefined;
  private readonly maxQueueSize: number;
  private readonly maxBatchSize: number;
  private readonly flushIntervalMs: number;
  private timer: NodeJS.Timeout | null = null;
  private flushing = false;
  private inFlight: Promise<void> | null = null;
  private droppedCount = 0;
  private consecutiveFailures = 0;
  private warnedNoSink = false;

  constructor(options: GatewayEventQueueOptions = {}) {
    this.sink = options.sink;
    this.maxQueueSize = options.maxQueueSize ?? DEFAULT_MAX_QUEUE_SIZE;
    this.maxBatchSize = options.maxBatchSize ?? DEFAULT_MAX_BATCH_SIZE;
    this.flushIntervalMs = options.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS;
  }

  /**
   * Records a blocked attempt. Synchronous and non-blocking; never throws for
   * a full queue (drops are counted and logged instead).
   */
  public enqueueBlockedAttempt(params: {
    companyId: CompanyId;
    deviceId: DeviceId;
    domain: string;
    loggedOsUser: string;
    policyVersion: number;
    reasonCode: string;
    clientIp?: string;
  }): void {
    if (!this.sink && !this.warnedNoSink) {
      this.warnedNoSink = true;
      log('warn', 'GatewayEventQueue has no sink configured: blocked-attempt events are held in memory only and dropped once the queue is full');
    }

    const key = keyOf(params);
    const existing = this.pending.get(key);
    if (existing) {
      existing.count += 1;
      existing.lastSeenAt = new Date().toISOString();
      return;
    }

    if (this.queue.length >= this.maxQueueSize) {
      this.droppedCount += 1;
      if (this.droppedCount === 1 || this.droppedCount % DROP_LOG_EVERY === 0) {
        log('error', 'blocked-attempt queue full: event dropped', {
          droppedTotal: this.droppedCount,
          maxQueueSize: this.maxQueueSize,
        });
      }
      return;
    }

    const record: BlockedAttemptRecord = {
      id: randomUUID(),
      companyId: params.companyId,
      deviceId: params.deviceId,
      domain: params.domain,
      loggedOsUser: params.loggedOsUser,
      policyVersion: params.policyVersion,
      reasonCode: params.reasonCode,
      ...(params.clientIp !== undefined ? { clientIp: params.clientIp } : {}),
      occurredAt: new Date().toISOString(),
      count: 1,
    };
    this.queue.push(record);
    this.pending.set(key, record);

    if (this.queue.length >= this.maxBatchSize) {
      void this.flushNow();
    }
  }

  /**
   * Sends one batch to the sink. Never throws: on failure the batch is put back
   * at the front of the queue and the error is logged. Without a sink it does
   * nothing, so events are retained, not discarded.
   */
  public async flushNow(): Promise<void> {
    if (!this.sink || this.flushing || this.queue.length === 0) {
      return;
    }

    this.flushing = true;
    const batch = this.queue.splice(0, this.maxBatchSize);
    for (const record of batch) {
      this.pending.delete(keyOf(record));
    }

    const sink = this.sink;
    const run = (async (): Promise<void> => {
    try {
      await sink(batch);
      this.consecutiveFailures = 0;
    } catch (err) {
      this.consecutiveFailures += 1;
      this.queue.unshift(...batch);
      const overflow = this.queue.splice(this.maxQueueSize);
      if (overflow.length > 0) {
        this.droppedCount += overflow.length;
        for (const record of overflow) {
          this.pending.delete(keyOf(record));
        }
      }
      log('error', 'failed to deliver blocked-attempt batch; will retry', {
        error: errorMessageOf(err),
        batchSize: batch.length,
        consecutiveFailures: this.consecutiveFailures,
        queued: this.queue.length,
        droppedTotal: this.droppedCount,
      });
    } finally {
      this.flushing = false;
      this.inFlight = null;
    }
    })();
    this.inFlight = run;
    await run;
  }

  /** Starts periodic flushing. Safe to call more than once. */
  public start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.flushNow();
    }, this.flushIntervalMs);
    this.timer.unref?.();
  }

  /** Stops periodic flushing and drains the queue while batches keep succeeding. */
  public async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    let guard = 0;
    let failures = 0;
    while (this.sink && guard < 10_000) {
      guard += 1;
      if (this.inFlight) {
        await this.inFlight; // wait for any background flush before deciding we are done
        continue;
      }
      if (this.queue.length === 0) break;
      const before = this.queue.length;
      await this.flushNow();
      if (this.queue.length >= before) {
        failures += 1; // a failed batch is put back: stop after a few attempts
        if (failures >= 3) break;
      } else {
        failures = 0;
      }
    }
  }

  public getQueuedCount(): number {
    return this.queue.length;
  }

  public getDroppedCount(): number {
    return this.droppedCount;
  }

  public getConsecutiveFailures(): number {
    return this.consecutiveFailures;
  }
}
