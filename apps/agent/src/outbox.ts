import { randomBytes, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export interface OutboxEvent {
  id: string;
  type: string;
  deviceReportedAt: string;
  payload: Record<string, unknown>;
}

export interface AgentOutboxOptions {
  /** Where pending events are kept (default: ~/.config/work-dns/agent-outbox.jsonl). */
  filePath?: string;
  /** Where events the gateway refused are kept for review (default: beside the outbox). */
  quarantinePath?: string;
  maxEvents?: number;
  /** Clock (injectable for tests). */
  now?: () => Date;
}

const DEFAULT_MAX_EVENTS = 5_000;
const LOG_EVERY = 100;
const ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function logError(message: string, fields: Record<string, unknown> = {}): void {
  console.error(JSON.stringify({ level: 'error', message, ...fields }));
}

function ensureOwnerOnlyDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new Error(`Outbox path ${dir} must be a real directory, not a symlink`);
  }
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new Error(`Outbox directory ${dir} is not owned by the current user`);
  }
  if ((st.mode & 0o077) !== 0) {
    fs.chmodSync(dir, 0o700);
  }
}

function parseEvent(line: string): OutboxEvent | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const r = value as Record<string, unknown>;
  if (
    typeof r.id !== 'string' ||
    !ID_PATTERN.test(r.id) ||
    typeof r.type !== 'string' ||
    typeof r.deviceReportedAt !== 'string' ||
    typeof r.payload !== 'object' ||
    r.payload === null ||
    Array.isArray(r.payload)
  ) {
    return null;
  }
  return { id: r.id, type: r.type, deviceReportedAt: r.deviceReportedAt, payload: r.payload as Record<string, unknown> };
}

/**
 * Durable, bounded buffer for audit events waiting to reach the gateway. An event is written to disk
 * before any delivery attempt and removed only after the gateway has confirmed it. Events the gateway
 * refuses move to a quarantine file, never into the void. The files are owner-only plain text: this is
 * a delivery buffer, not tamper-proof evidence (anyone with root on the device can edit it).
 */
export class AgentOutbox {
  private readonly filePath: string;
  private readonly quarantinePath: string;
  private readonly maxEvents: number;
  private readonly now: () => Date;
  private items: OutboxEvent[] = [];
  private dropped = 0;
  private quarantined = 0;
  private persistFailures = 0;

  constructor(options: AgentOutboxOptions = {}) {
    const maxEvents = options.maxEvents ?? DEFAULT_MAX_EVENTS;
    if (!Number.isInteger(maxEvents) || maxEvents < 1) {
      throw new RangeError('AgentOutbox: maxEvents must be a positive integer');
    }
    this.maxEvents = maxEvents;
    this.now = options.now ?? (() => new Date());
    this.filePath = options.filePath ?? path.join(os.homedir(), '.config', 'work-dns', 'agent-outbox.jsonl');
    this.quarantinePath = options.quarantinePath ?? path.join(path.dirname(this.filePath), 'agent-outbox-quarantine.jsonl');
    ensureOwnerOnlyDir(path.dirname(this.filePath));
    ensureOwnerOnlyDir(path.dirname(this.quarantinePath));
    this.load();
  }

  /** Records an event for delivery and returns its id. Never throws for a disk problem: it is logged and counted. */
  public add(type: string, payload: Record<string, unknown>): string {
    const event: OutboxEvent = { id: randomUUID(), type, deviceReportedAt: this.now().toISOString(), payload };
    while (this.items.length >= this.maxEvents) {
      this.items.shift();
      this.dropped += 1;
      if (this.dropped === 1 || this.dropped % LOG_EVERY === 0) {
        logError('audit event outbox full: oldest event dropped', { droppedTotal: this.dropped, maxEvents: this.maxEvents });
      }
    }
    this.items.push(event);
    try {
      this.appendLine(this.filePath, `${JSON.stringify(event)}\n`);
    } catch (err) {
      this.persistFailures += 1;
      logError('could not save an audit event to disk; it is held in memory only', {
        error: errorMessageOf(err),
        persistFailures: this.persistFailures,
      });
    }
    return event.id;
  }

  /** Returns copies of the oldest pending events. */
  public peek(limit: number): OutboxEvent[] {
    return this.items.slice(0, Math.max(0, limit)).map((event) => structuredClone(event));
  }

  /** Removes events the gateway has confirmed. */
  public acknowledge(ids: string[]): void {
    const confirmed = new Set(ids);
    const before = this.items.length;
    this.items = this.items.filter((event) => !confirmed.has(event.id));
    if (this.items.length !== before) this.rewrite();
  }

  /** Moves one event to the quarantine file. The quarantine record is written before the event leaves the outbox. */
  public quarantine(id: string, reason: string): boolean {
    const event = this.items.find((candidate) => candidate.id === id);
    if (event === undefined) return false;
    this.appendLine(this.quarantinePath, `${JSON.stringify({ at: this.now().toISOString(), reason, event })}\n`);
    this.items = this.items.filter((candidate) => candidate.id !== id);
    this.quarantined += 1;
    this.rewrite();
    return true;
  }

  public count(): number {
    return this.items.length;
  }

  public getDroppedCount(): number {
    return this.dropped;
  }

  public getQuarantinedCount(): number {
    return this.quarantined;
  }

  public getPersistFailures(): number {
    return this.persistFailures;
  }

  private load(): void {
    let raw: string;
    try {
      raw = fs.readFileSync(this.filePath, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw err;
    }
    let needsRewrite = false;
    const seen = new Set<string>();
    for (const line of raw.split('\n')) {
      if (line.trim() === '') continue;
      const event = parseEvent(line);
      if (event === null) {
        this.appendLine(
          this.quarantinePath,
          `${JSON.stringify({ at: this.now().toISOString(), reason: 'unreadable line in the outbox file', raw: line.slice(0, 2000) })}\n`
        );
        this.quarantined += 1;
        needsRewrite = true;
        logError('unreadable line in the audit event outbox moved to quarantine', { quarantinePath: this.quarantinePath });
        continue;
      }
      if (seen.has(event.id)) {
        needsRewrite = true;
        continue;
      }
      seen.add(event.id);
      this.items.push(event);
    }
    while (this.items.length > this.maxEvents) {
      this.items.shift();
      this.dropped += 1;
      needsRewrite = true;
    }
    if (this.dropped > 0) {
      logError('audit event outbox on disk exceeded its limit: oldest events dropped', { droppedTotal: this.dropped });
    }
    if (needsRewrite) this.rewrite();
  }

  private appendLine(file: string, text: string): void {
    const fd = fs.openSync(file, 'a', 0o600);
    try {
      fs.writeSync(fd, text);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }

  private rewrite(): void {
    const content = this.items.map((event) => JSON.stringify(event)).join('\n') + (this.items.length > 0 ? '\n' : '');
    const tmpPath = `${this.filePath}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
    let fd: number | undefined;
    try {
      fd = fs.openSync(tmpPath, 'wx', 0o600);
      fs.writeSync(fd, content);
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(tmpPath, this.filePath);
    } catch (err) {
      this.persistFailures += 1;
      logError('could not update the audit event outbox on disk; a restart may resend events (the gateway ignores repeats)', {
        error: errorMessageOf(err),
      });
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch { /* best-effort cleanup; the original error is logged above */ }
      }
      try { fs.rmSync(tmpPath, { force: true }); } catch { /* best-effort cleanup; the original error is logged above */ }
    }
  }
}
