import type { AgentOutbox, OutboxEvent } from './outbox.js';

type SenderLog = (level: 'info' | 'error', message: string, fields?: Record<string, unknown>) => void;

export interface AgentEventSenderOptions {
  outbox: AgentOutbox;
  /** The configured gateway URL. The events URL is built from its origin only, so the token goes nowhere else. */
  gatewayUrl: string;
  deviceToken: string;
  fetchImpl?: typeof fetch;
  intervalMs?: number; // default 5000
  requestTimeoutMs?: number; // default 10000
  maxBatch?: number; // default 50, the gateway's limit
  baseBackoffMs?: number; // default 1000
  maxBackoffMs?: number; // default 60000
  /** Injectable for tests. */
  random?: () => number;
  log?: SenderLog;
}

export type FlushResult = 'idle' | 'delivered' | 'failed';

const MAX_RESPONSE_BYTES = 65_536;
const GATEWAY_BATCH_LIMIT = 50;

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function defaultLog(level: 'info' | 'error', message: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ level, message, ...fields });
  if (level === 'error') {
    console.error(line);
  } else {
    console.log(line);
  }
}

function deriveEventsUrl(gatewayUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(gatewayUrl);
  } catch {
    throw new Error(`Invalid gateway URL: ${gatewayUrl}`);
  }
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) {
    throw new Error(`Gateway URL must use https (http is allowed only for loopback): ${gatewayUrl}`);
  }
  return new URL('/api/v1/agent-events', parsed.origin).toString();
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

/**
 * Delivers outbox events to the gateway. An event leaves the outbox only when the gateway returns a
 * JSON receipt whose counts add up to the batch: a captive portal's 200 login page is not a receipt.
 * A rejection counts only if it is the gateway's own JSON error. Events the gateway names as invalid
 * are quarantined, never dropped and never retried forever.
 */
export class AgentEventSender {
  private readonly outbox: AgentOutbox;
  private readonly eventsUrl: string;
  private readonly deviceToken: string;
  private readonly fetchImpl: typeof fetch;
  private readonly intervalMs: number;
  private readonly requestTimeoutMs: number;
  private readonly maxBatch: number;
  private readonly baseBackoffMs: number;
  private readonly maxBackoffMs: number;
  private readonly random: () => number;
  private readonly log: SenderLog;

  private started = false;
  private stopped = false;
  private aborting = false;
  private timer: NodeJS.Timeout | null = null;
  private running: Promise<FlushResult> | null = null;
  private currentAbort: AbortController | null = null;
  private batchSize: number;
  private consecutiveFailures = 0;
  private lastFailureKey: string | null = null;

  constructor(options: AgentEventSenderOptions) {
    if (options.deviceToken.trim().length === 0) {
      throw new Error('AgentEventSender: a device token is required');
    }
    this.outbox = options.outbox;
    this.eventsUrl = deriveEventsUrl(options.gatewayUrl);
    this.deviceToken = options.deviceToken;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.intervalMs = options.intervalMs ?? 5_000;
    this.requestTimeoutMs = options.requestTimeoutMs ?? 10_000;
    const maxBatch = options.maxBatch ?? GATEWAY_BATCH_LIMIT;
    if (!Number.isInteger(maxBatch) || maxBatch < 1 || maxBatch > GATEWAY_BATCH_LIMIT) {
      throw new RangeError(`AgentEventSender: maxBatch must be an integer from 1 to ${GATEWAY_BATCH_LIMIT}`);
    }
    this.maxBatch = maxBatch;
    this.batchSize = maxBatch;
    this.baseBackoffMs = options.baseBackoffMs ?? 1_000;
    this.maxBackoffMs = options.maxBackoffMs ?? 60_000;
    this.random = options.random ?? Math.random;
    this.log = options.log ?? defaultLog;
  }

  public start(): void {
    if (this.started) throw new Error('AgentEventSender is already started');
    this.started = true;
    this.schedule(this.intervalMs);
  }

  /** Asks for a prompt delivery attempt (debounced). It does not cut a backoff in progress short. */
  public kick(): void {
    if (!this.started || this.stopped || this.consecutiveFailures > 0) return;
    this.schedule(250);
  }

  /** Stops the timer, optionally makes one last delivery attempt of up to finalFlushMs, then waits for any send in progress. */
  public async stop(options: { finalFlushMs?: number } = {}): Promise<void> {
    this.stopped = true;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    const finalFlushMs = options.finalFlushMs ?? 0;
    if (finalFlushMs > 0 && this.outbox.count() > 0) {
      const flush = this.flushOnce();
      let timedOut = false;
      const deadline = setTimeout(() => {
        timedOut = true;
        this.aborting = true;
        this.currentAbort?.abort();
      }, finalFlushMs);
      try {
        await flush;
      } finally {
        clearTimeout(deadline);
      }
      if (timedOut) {
        this.log('error', 'final delivery of audit events timed out; the remaining events stay in the outbox', {
          remaining: this.outbox.count(),
        });
      }
    } else if (this.running) {
      await this.running;
    }
  }

  /** One delivery pass: sends batches until the outbox is empty or a send fails. Only one pass runs at a time. */
  public flushOnce(): Promise<FlushResult> {
    if (this.running) return this.running;
    const run = this.doFlush().finally(() => {
      this.running = null;
    });
    this.running = run;
    return run;
  }

  private schedule(delayMs: number): void {
    if (this.stopped) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      void this.tick();
    }, delayMs);
    this.timer.unref?.();
  }

  private async tick(): Promise<void> {
    this.timer = null;
    if (this.stopped) return;
    await this.flushOnce();
    if (!this.stopped) this.schedule(this.nextDelayMs());
  }

  private nextDelayMs(): number {
    if (this.consecutiveFailures === 0) return this.intervalMs;
    const exponential = Math.min(this.maxBackoffMs, this.baseBackoffMs * 2 ** (this.consecutiveFailures - 1));
    return Math.round(exponential * (0.8 + 0.4 * this.random()));
  }

  private async doFlush(): Promise<FlushResult> {
    let delivered = 0;
    try {
      for (;;) {
        if (this.aborting) return 'failed';
        const batch = this.outbox.peek(this.batchSize);
        if (batch.length === 0) return delivered > 0 ? 'delivered' : 'idle';
        const outcome = await this.sendBatch(batch);
        if (outcome === 'failed') return 'failed';
        if (outcome === 'acked') {
          delivered += batch.length;
          this.batchSize = this.maxBatch;
        }
      }
    } catch (err) {
      return this.fail('unexpected', 'audit event delivery failed unexpectedly; events stay queued', { error: errorMessageOf(err) });
    }
  }

  private fail(key: string, message: string, fields: Record<string, unknown>): 'failed' {
    this.consecutiveFailures += 1;
    if (this.lastFailureKey !== key) {
      this.lastFailureKey = key;
      this.log('error', message, fields);
    }
    return 'failed';
  }

  private quarantineEvent(event: OutboxEvent, reason: string): 'adjusted' {
    this.outbox.quarantine(event.id, reason);
    this.log('error', 'audit event rejected by the gateway and moved to quarantine', { eventType: event.type, id: event.id, reason });
    return 'adjusted';
  }

  private async sendBatch(batch: OutboxEvent[]): Promise<'acked' | 'adjusted' | 'failed'> {
    const controller = new AbortController();
    this.currentAbort = controller;
    const timeout = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    let status = 0;
    let contentType = '';
    let bodyText = '';
    try {
      const response = await this.fetchImpl(this.eventsUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.deviceToken}` },
        body: JSON.stringify({ events: batch }),
        signal: controller.signal,
        redirect: 'error',
      });
      status = response.status;
      contentType = (response.headers.get('content-type') ?? '').split(';')[0]!.trim().toLowerCase();
      const declared = response.headers.get('content-length');
      if (declared !== null && Number(declared) > MAX_RESPONSE_BYTES) throw new Error('gateway response too large');
      const bytes = Buffer.from(await response.arrayBuffer());
      if (bytes.length > MAX_RESPONSE_BYTES) throw new Error('gateway response too large');
      bodyText = bytes.toString('utf8');
    } catch (err) {
      return this.fail('network', 'could not deliver audit events to the gateway; they stay queued', { error: errorMessageOf(err) });
    } finally {
      clearTimeout(timeout);
      this.currentAbort = null;
    }

    const json = contentType === 'application/json' ? parseJsonObject(bodyText) : null;

    if (status === 200) {
      const accepted = json?.accepted;
      const duplicates = json?.duplicates;
      if (isCount(accepted) && isCount(duplicates) && accepted + duplicates === batch.length) {
        this.outbox.acknowledge(batch.map((event) => event.id));
        this.consecutiveFailures = 0;
        if (this.lastFailureKey !== null) {
          this.lastFailureKey = null;
          this.log('info', 'audit event delivery recovered', {});
        }
        return 'acked';
      }
      return this.fail('bad-200', 'the gateway answered 200 without a matching receipt (captive portal or proxy?); events stay queued', {
        status,
        contentType,
      });
    }

    if (status === 400 || status === 413) {
      const errorText = json?.error;
      if (typeof errorText !== 'string') {
        return this.fail(`http-${status}-unrecognised`, "a 4xx answer that is not the gateway's own error (captive portal or proxy?); events stay queued", {
          status,
          contentType,
        });
      }
      const detailRaw = json?.detail;
      const detail = typeof detailRaw === 'string' ? detailRaw.slice(0, 200) : errorText.slice(0, 200);
      const index = json?.index;
      if (status === 400 && typeof index === 'number' && Number.isInteger(index) && index >= 0 && index < batch.length) {
        return this.quarantineEvent(batch[index]!, detail);
      }
      if (batch.length > 1) {
        this.batchSize = Math.max(1, Math.ceil(batch.length / 2));
        return 'adjusted';
      }
      return this.quarantineEvent(batch[0]!, detail);
    }

    if (status === 401 || status === 403) {
      return this.fail('auth', 'the gateway rejected the device token; audit events stay queued', { status });
    }
    return this.fail(`http-${status}`, 'the gateway did not accept the audit events; they stay queued', { status });
  }
}
