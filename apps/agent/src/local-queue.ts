import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export type OfflineAction = 'FAIL_OPEN_ALLOWED' | 'OFFLINE_BLOCKED' | 'AUTH_REJECTED';

const ACTIONS: ReadonlySet<string> = new Set(['FAIL_OPEN_ALLOWED', 'OFFLINE_BLOCKED', 'AUTH_REJECTED']);
const DEFAULT_MAX_QUEUE_SIZE = 5_000;
const DEFAULT_DEDUPE_WINDOW_MS = 60_000;
const LOG_EVERY = 100;

export interface QueuedOfflineEvent {
  id: string;
  domain: string;
  timestamp: string;
  actionTaken: OfflineAction;
  reason: string;
  /** Times this domain and action repeated inside the dedupe window while queued. */
  occurrences: number;
}

export interface LocalEventQueueOptions {
  filePath?: string;
  maxQueueSize?: number;
  dedupeWindowMs?: number;
  /** Clock in epoch milliseconds (injectable for tests). */
  now?: () => number;
}

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function logError(message: string, fields: Record<string, unknown> = {}): void {
  console.error(JSON.stringify({ level: 'error', message, ...fields }));
}

/** Returns null for an invalid line; the caller counts invalid lines and reports them. */
function parseLine(line: string): QueuedOfflineEvent | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  const r = value as Record<string, unknown>;
  if (
    typeof r.id !== 'string' ||
    typeof r.domain !== 'string' ||
    typeof r.timestamp !== 'string' ||
    typeof r.reason !== 'string' ||
    typeof r.actionTaken !== 'string' ||
    !ACTIONS.has(r.actionTaken)
  ) {
    return null;
  }
  const occurrences =
    typeof r.occurrences === 'number' && Number.isInteger(r.occurrences) && r.occurrences >= 1 ? r.occurrences : 1;
  return {
    id: r.id,
    domain: r.domain,
    timestamp: r.timestamp,
    actionTaken: r.actionTaken as OfflineAction,
    reason: r.reason,
    occurrences,
  };
}

/**
 * Durable local queue for events that could not reach the server (append-only JSON lines).
 * Nothing here is silent: persistence failures and dropped events are counted and logged.
 * NOTE: the file is plain text owned by the local user. It is a delivery buffer, not tamper-proof evidence.
 */
export class LocalEventQueue {
  private readonly filePath: string;
  private readonly maxQueueSize: number;
  private readonly dedupeWindowMs: number;
  private readonly now: () => number;
  private items: QueuedOfflineEvent[] = [];
  private readonly recent = new Map<string, { item: QueuedOfflineEvent; seenMs: number }>();
  private flushing = false;
  private droppedCount = 0;
  private persistFailures = 0;

  constructor(options?: string | LocalEventQueueOptions) {
    const opts: LocalEventQueueOptions = typeof options === 'string' ? { filePath: options } : (options ?? {});
    const maxQueueSize = opts.maxQueueSize ?? DEFAULT_MAX_QUEUE_SIZE;
    if (!Number.isInteger(maxQueueSize) || maxQueueSize < 1) {
      throw new RangeError('LocalEventQueue: maxQueueSize must be a positive integer');
    }
    this.maxQueueSize = maxQueueSize;
    this.dedupeWindowMs = opts.dedupeWindowMs ?? DEFAULT_DEDUPE_WINDOW_MS;
    this.now = opts.now ?? Date.now;

    if (opts.filePath) {
      this.filePath = opts.filePath;
      this.ensureDir(path.dirname(this.filePath), false);
    } else {
      const dir = path.join(os.homedir(), '.config', 'work-dns');
      this.ensureDir(dir, true);
      this.filePath = path.join(dir, 'offline-events.jsonl');
    }
    this.loadFromDisk();
  }

  /** Appends an offline or fail-open event. Repeats inside the dedupe window increment `occurrences`. */
  public enqueue(event: Omit<QueuedOfflineEvent, 'id' | 'timestamp' | 'occurrences'>): void {
    const nowMs = this.now();
    const key = `${event.actionTaken}|${event.domain}`;
    const existing = this.recent.get(key);
    if (existing && nowMs - existing.seenMs < this.dedupeWindowMs) {
      existing.item.occurrences += 1; // persisted at the next compaction
      return;
    }

    while (this.items.length >= this.maxQueueSize) {
      const oldest = this.items.shift();
      if (!oldest) break;
      this.forget(oldest);
      this.droppedCount += 1;
      if (this.droppedCount === 1 || this.droppedCount % LOG_EVERY === 0) {
        logError('offline event queue full: oldest event dropped', {
          droppedTotal: this.droppedCount,
          maxQueueSize: this.maxQueueSize,
        });
      }
    }

    const item: QueuedOfflineEvent = {
      id: randomUUID(),
      domain: event.domain,
      timestamp: new Date(nowMs).toISOString(),
      actionTaken: event.actionTaken,
      reason: event.reason,
      occurrences: 1,
    };
    this.items.push(item);
    this.recent.set(key, { item, seenMs: nowMs });
    this.append(item);
  }

  /**
   * Delivers queued events in batches. Only events the transmitter accepted are removed;
   * events added while a batch was in flight are kept. If the transmitter throws, nothing is
   * removed and the error propagates to the caller.
   */
  public async flush(
    transmitter: (events: QueuedOfflineEvent[]) => Promise<void>,
    batchSize = 500
  ): Promise<number> {
    if (!Number.isInteger(batchSize) || batchSize < 1) {
      throw new RangeError('LocalEventQueue.flush: batchSize must be a positive integer');
    }
    if (this.flushing) return 0;
    this.flushing = true;
    let delivered = 0;
    try {
      // Only events queued when the flush started are delivered by this call; later arrivals
      // wait for the next flush, so one call cannot run forever on a busy device.
      let remaining = this.items.length;
      while (remaining > 0 && this.items.length > 0) {
        const inFlight = this.items.slice(0, Math.min(batchSize, remaining));
        // Repeats arriving while these are in flight must become new events, not change sent ones.
        for (const item of inFlight) {
          this.forget(item);
        }
        const batch = inFlight.map((event) => ({ ...event }));
        await transmitter(batch);
        const ids = new Set(batch.map((event) => event.id));
        this.items = this.items.filter((event) => {
          if (ids.has(event.id)) {
            this.forget(event);
            return false;
          }
          return true;
        });
        delivered += batch.length;
        remaining -= batch.length;
        this.rewrite();
      }
      return delivered;
    } finally {
      this.flushing = false;
    }
  }

  public getCount(): number {
    return this.items.length;
  }

  public getItems(): QueuedOfflineEvent[] {
    return this.items.map((event) => ({ ...event }));
  }

  public getDroppedCount(): number {
    return this.droppedCount;
  }

  public getPersistFailureCount(): number {
    return this.persistFailures;
  }

  public clear(): void {
    this.items = [];
    this.recent.clear();
    this.rewrite();
  }

  private forget(item: QueuedOfflineEvent): void {
    const key = `${item.actionTaken}|${item.domain}`;
    const entry = this.recent.get(key);
    if (entry && entry.item.id === item.id) {
      this.recent.delete(key);
    }
  }

  private ensureDir(dir: string, tighten: boolean): void {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (tighten) {
      const st = fs.lstatSync(dir);
      if (st.isSymbolicLink() || !st.isDirectory()) {
        throw new Error(`Queue directory ${dir} must be a real directory, not a symlink`);
      }
      fs.chmodSync(dir, 0o700);
    }
  }

  private loadFromDisk(): void {
    let raw: string;
    try {
      raw = fs.readFileSync(this.filePath, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        fs.writeFileSync(this.filePath, '', { mode: 0o600, flag: 'a' });
        return;
      }
      throw err;
    }
    fs.chmodSync(this.filePath, 0o600);

    const loaded: QueuedOfflineEvent[] = [];
    let invalid = 0;
    for (const line of raw.split('\n')) {
      if (line.trim() === '') continue;
      const event = parseLine(line);
      if (event) {
        loaded.push(event);
      } else {
        invalid += 1;
      }
    }

    let needsRewrite = false;
    if (invalid > 0) {
      const aside = `${this.filePath}.corrupt-${this.now()}`;
      fs.copyFileSync(this.filePath, aside);
      fs.chmodSync(aside, 0o600);
      logError('offline event queue file had invalid lines; original preserved and valid events kept', {
        preservedAs: aside,
        invalidLines: invalid,
        validEvents: loaded.length,
      });
      needsRewrite = true;
    }
    if (loaded.length > this.maxQueueSize) {
      const dropped = loaded.length - this.maxQueueSize;
      loaded.splice(0, dropped);
      this.droppedCount += dropped;
      logError('offline event queue file exceeded maxQueueSize: oldest events dropped', { dropped });
      needsRewrite = true;
    }
    this.items = loaded;
    if (needsRewrite) {
      this.rewrite();
    }
  }

  private append(item: QueuedOfflineEvent): void {
    try {
      fs.appendFileSync(this.filePath, JSON.stringify(item) + '\n', { mode: 0o600 });
    } catch (err) {
      this.recordPersistFailure('append', err);
    }
  }

  /** Atomic rewrite (temp file then rename) of the whole queue. */
  private rewrite(): void {
    const tmp = `${this.filePath}.tmp-${process.pid}-${randomUUID()}`;
    let fd: number | undefined;
    try {
      fd = fs.openSync(tmp, 'wx', 0o600);
      fs.writeFileSync(fd, this.items.map((item) => JSON.stringify(item) + '\n').join(''));
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      if (fd !== undefined) {
        try {
          fs.closeSync(fd);
        } catch (closeErr) {
          logError('failed to close temp queue file', { error: errorMessageOf(closeErr) });
        }
      }
      try {
        fs.rmSync(tmp, { force: true });
      } catch (rmErr) {
        logError('failed to remove temp queue file', { error: errorMessageOf(rmErr) });
      }
      this.recordPersistFailure('rewrite', err);
    }
  }

  private recordPersistFailure(operation: string, err: unknown): void {
    this.persistFailures += 1;
    if (this.persistFailures === 1 || this.persistFailures % LOG_EVERY === 0) {
      logError('offline event queue could not be persisted; events are held in memory only', {
        operation,
        failuresTotal: this.persistFailures,
        error: errorMessageOf(err),
      });
    }
  }
}
