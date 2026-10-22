import dgram from 'node:dgram';
import dnsPacket from 'dns-packet';
import { PlatformAdapter, NotificationOptions } from './platform/adapter.js';
import { LocalEventQueue, QueuedOfflineEvent } from './local-queue.js';
import { buildErrorResponse } from './dns-response.js';

const DNS_MESSAGE_TYPE = 'application/dns-message';
const HEADER_LENGTH = 12;
const MAX_DNS_MESSAGE_BYTES = 16_384;
const MAX_TRACKED_KEYS = 1_000;
const LOG_COOLDOWN_MS = 5_000;
const DEFAULT_NOTIFICATION_COOLDOWN_MS = 30_000;

export interface DnsStubConfig {
  loopbackPort: number; // 53 in production; 0 or a high port for tests
  loopbackHost?: string; // default 127.0.0.1
  gatewayUrl: string; // https, or http only for loopback development
  deviceToken: string;
  gatewayTimeoutMs?: number; // default 2000
  failOpenMaxMinutes?: number; // default 15
  fallbackUpstreamDoh?: string; // default https://1.1.1.1/dns-query
  maxConcurrentQueries?: number; // default 256
  notificationCooldownMs?: number; // default 30000
  /** Page where staff can request access. No link is offered when unset. */
  requestAccessUrl?: string;
  /** Delivers queued offline events when the gateway comes back. Without it they stay queued locally. */
  eventSink?: (events: QueuedOfflineEvent[]) => Promise<void>;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
  /** Clock in epoch milliseconds (injectable for tests). */
  now?: () => number;
}

export type GatewayState = 'ONLINE' | 'FAIL_OPEN_ACTIVE' | 'FAIL_CLOSED';

type FailureKind = 'unreachable' | 'auth' | 'rejected' | 'bad_response';

class GatewayFailure extends Error {
  readonly kind: FailureKind;
  readonly status: number | undefined;

  constructor(kind: FailureKind, message: string, status?: number) {
    super(message);
    this.kind = kind;
    this.status = status;
  }
}

interface QuerySignature {
  id: number;
  name: string;
  type: string;
  className: string;
}

interface DnsHttpResult {
  status: number;
  contentType: string;
  policyAction: string | null;
  body: Buffer;
}

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function logError(message: string, fields: Record<string, unknown> = {}): void {
  console.error(JSON.stringify({ level: 'error', message, ...fields }));
}

function normalizeName(name: string): string {
  const lowered = name.toLowerCase();
  return lowered.endsWith('.') ? lowered.slice(0, -1) : lowered;
}

function assertGatewayUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid gateway URL: ${url}`);
  }
  if (parsed.protocol === 'https:') return;
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname);
  if (parsed.protocol === 'http:' && loopback) return;
  throw new Error(`Gateway URL must use https (http is allowed only for loopback): ${url}`);
}

function assertHttpsUrl(url: string, label: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid ${label} URL: ${url}`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error(`${label} URL must use https: ${url}`);
  }
}

export class DnsStubServer {
  private socket: dgram.Socket | null = null;
  private readonly platformAdapter: PlatformAdapter;
  private readonly localQueue: LocalEventQueue;

  private readonly loopbackPort: number;
  private readonly loopbackHost: string;
  private readonly gatewayUrl: string;
  private readonly deviceToken: string;
  private readonly gatewayTimeoutMs: number;
  private readonly failOpenMaxMs: number;
  private readonly fallbackUrl: string;
  private readonly maxConcurrentQueries: number;
  private readonly notificationCooldownMs: number;
  private readonly requestAccessUrl: string | undefined;
  private readonly eventSink: ((events: QueuedOfflineEvent[]) => Promise<void>) | undefined;
  private readonly fetchImpl: typeof fetch | undefined;
  private readonly now: () => number;

  private state: GatewayState = 'ONLINE';
  private failOpenStartMs: number | null = null;
  private inFlight = 0;
  private readonly lastNotificationMs = new Map<string, number>();
  private readonly lastLogMs = new Map<string, number>();

  constructor(config: DnsStubConfig, platformAdapter: PlatformAdapter, localQueue: LocalEventQueue) {
    if (!config.deviceToken || config.deviceToken.trim().length === 0) {
      throw new Error('DnsStubServer: deviceToken is required');
    }
    if (!Number.isInteger(config.loopbackPort) || config.loopbackPort < 0 || config.loopbackPort > 65_535) {
      throw new RangeError('DnsStubServer: loopbackPort must be an integer between 0 and 65535');
    }
    const failOpenMinutes = config.failOpenMaxMinutes ?? 15;
    if (!Number.isFinite(failOpenMinutes) || failOpenMinutes <= 0) {
      throw new RangeError('DnsStubServer: failOpenMaxMinutes must be greater than zero');
    }
    const maxConcurrent = config.maxConcurrentQueries ?? 256;
    if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1) {
      throw new RangeError('DnsStubServer: maxConcurrentQueries must be a positive integer');
    }
    assertGatewayUrl(config.gatewayUrl);
    const fallbackUrl = config.fallbackUpstreamDoh ?? 'https://1.1.1.1/dns-query';
    assertHttpsUrl(fallbackUrl, 'fallback upstream');

    this.platformAdapter = platformAdapter;
    this.localQueue = localQueue;
    this.loopbackPort = config.loopbackPort;
    this.loopbackHost = config.loopbackHost ?? '127.0.0.1';
    this.gatewayUrl = config.gatewayUrl;
    this.deviceToken = config.deviceToken;
    this.gatewayTimeoutMs = config.gatewayTimeoutMs ?? 2_000;
    this.failOpenMaxMs = failOpenMinutes * 60_000;
    this.fallbackUrl = fallbackUrl;
    this.maxConcurrentQueries = maxConcurrent;
    this.notificationCooldownMs = config.notificationCooldownMs ?? DEFAULT_NOTIFICATION_COOLDOWN_MS;
    this.requestAccessUrl = config.requestAccessUrl;
    this.eventSink = config.eventSink;
    this.fetchImpl = config.fetchImpl;
    this.now = config.now ?? Date.now;
  }

  public start(): Promise<void> {
    if (this.socket) {
      return Promise.reject(new Error('DnsStubServer is already started'));
    }
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket('udp4');
      const onStartError = (err: Error): void => {
        this.socket = null;
        try {
          socket.close();
        } catch (closeErr) {
          logError('failed to close socket after start error', { error: errorMessageOf(closeErr) });
        }
        reject(err);
      };
      socket.once('error', onStartError);
      socket.on('message', (msg, rinfo) => {
        void this.onDatagram(socket, msg, rinfo);
      });
      socket.bind(this.loopbackPort, this.loopbackHost, () => {
        socket.off('error', onStartError);
        socket.on('error', (err: Error) => logError('dns stub socket error', { error: err.message }));
        resolve();
      });
      this.socket = socket;
    });
  }

  public stop(): Promise<void> {
    const socket = this.socket;
    this.socket = null;
    if (!socket) return Promise.resolve();
    return new Promise((resolve) => socket.close(() => resolve()));
  }

  /** Actual bound port (useful when started with port 0). */
  public getPort(): number | null {
    if (!this.socket) return null;
    try {
      return this.socket.address().port;
    } catch {
      return null; // socket not bound yet
    }
  }

  public getState(): GatewayState {
    return this.state;
  }

  /** Resolves one raw DNS query. Never throws: every failure becomes a real DNS error response. */
  public async handleQuery(queryBuffer: Buffer): Promise<Buffer> {
    const id = queryBuffer.length >= 2 ? queryBuffer.readUInt16BE(0) : 0;
    try {
      return await this.process(queryBuffer, id);
    } catch (err) {
      logError('unexpected error while handling DNS query', { error: errorMessageOf(err) });
      return buildErrorResponse({ id }, 'SERVFAIL');
    }
  }

  private async onDatagram(socket: dgram.Socket, msg: Buffer, rinfo: dgram.RemoteInfo): Promise<void> {
    const response = await this.handleQuery(msg);
    socket.send(response, rinfo.port, rinfo.address, (err) => {
      if (err) {
        logError('failed to send DNS response', { error: err.message });
      }
    });
  }

  private async process(queryBuffer: Buffer, id: number): Promise<Buffer> {
    if (queryBuffer.length < HEADER_LENGTH || queryBuffer.length > MAX_DNS_MESSAGE_BYTES) {
      return buildErrorResponse({ id }, 'FORMERR');
    }
    const parsed = this.parseQuery(queryBuffer);
    if (!parsed) {
      return buildErrorResponse({ id }, 'FORMERR');
    }
    const { packet, signature } = parsed;

    if (this.inFlight >= this.maxConcurrentQueries) {
      this.logLimited('overload', 'too many concurrent DNS queries: query refused', {
        maxConcurrentQueries: this.maxConcurrentQueries,
      });
      return buildErrorResponse(packet, 'SERVFAIL');
    }

    this.inFlight += 1;
    try {
      return await this.resolveQuery(queryBuffer, packet, signature);
    } finally {
      this.inFlight -= 1;
    }
  }

  /** Malformed or unsupported queries are answered with FORMERR by the caller. */
  private parseQuery(buf: Buffer): { packet: dnsPacket.Packet; signature: QuerySignature } | null {
    let packet: dnsPacket.Packet;
    try {
      packet = dnsPacket.decode(buf);
    } catch {
      return null;
    }
    const questions = packet.questions ?? [];
    const question = questions[0];
    if (packet.type !== 'query' || questions.length !== 1 || !question || !question.name) {
      return null;
    }
    return {
      packet,
      signature: {
        id: packet.id ?? 0,
        name: normalizeName(question.name),
        type: String(question.type),
        className: String(question.class ?? 'IN'),
      },
    };
  }

  private async resolveQuery(queryBuffer: Buffer, packet: dnsPacket.Packet, signature: QuerySignature): Promise<Buffer> {
    let result: { response: Buffer; isBlock: boolean };
    try {
      result = await this.queryGateway(queryBuffer, signature);
    } catch (err) {
      return this.handleGatewayFailure(err, queryBuffer, packet, signature);
    }

    if (this.state !== 'ONLINE') {
      this.recoverFromOutage();
    }
    if (result.isBlock) {
      this.notify(`block|${signature.name}`, this.blockNotification(signature.name));
    }
    return result.response;
  }

  private async handleGatewayFailure(
    err: unknown,
    queryBuffer: Buffer,
    packet: dnsPacket.Packet,
    signature: QuerySignature
  ): Promise<Buffer> {
    if (!(err instanceof GatewayFailure)) {
      throw err;
    }

    switch (err.kind) {
      case 'unreachable':
        return this.handleGatewayUnreachable(queryBuffer, packet, signature, err);

      case 'auth':
        // A rejected token must never fall back to unfiltered DNS.
        this.logLimited('auth', 'gateway rejected this device token', { status: err.status, detail: err.message });
        this.localQueue.enqueue({
          domain: signature.name,
          actionTaken: 'AUTH_REJECTED',
          reason: `Gateway rejected the device token (HTTP ${err.status ?? 'unknown'})`,
        });
        this.notify('auth-rejected', {
          title: 'Work DNS — Device not authorized',
          message: 'This device was rejected by the DNS gateway. Contact your administrator.',
        });
        return buildErrorResponse(packet, 'SERVFAIL');

      default:
        // Rate limits, client errors and invalid responses: never fall back, so none of them is a bypass.
        this.logLimited(err.kind, 'gateway request failed without fallback', {
          kind: err.kind,
          status: err.status,
          detail: err.message,
        });
        return buildErrorResponse(packet, 'SERVFAIL');
    }
  }

  /** Only network errors, timeouts and 5xx responses reach this path. */
  private async handleGatewayUnreachable(
    queryBuffer: Buffer,
    packet: dnsPacket.Packet,
    signature: QuerySignature,
    failure: GatewayFailure
  ): Promise<Buffer> {
    const nowMs = this.now();
    this.logLimited('unreachable', 'gateway unreachable', { detail: failure.message });

    if (this.state === 'ONLINE') {
      this.state = 'FAIL_OPEN_ACTIVE';
      this.failOpenStartMs = nowMs;
      this.notify('gateway-offline', {
        title: 'Work DNS — Gateway offline',
        message: 'Filtering is temporarily unavailable. Browsing continues for a limited time and attempts are recorded.',
      });
    }

    const elapsed = nowMs - (this.failOpenStartMs ?? nowMs);
    if (elapsed > this.failOpenMaxMs) {
      if (this.state !== 'FAIL_CLOSED') {
        this.state = 'FAIL_CLOSED';
        logError('fail-open time limit exceeded: blocking all DNS until the gateway returns');
        this.notify('gateway-closed', {
          title: 'Work DNS — Browsing paused',
          message: 'The DNS gateway has been unreachable for too long. Contact your administrator.',
        });
      }
      this.localQueue.enqueue({
        domain: signature.name,
        actionTaken: 'OFFLINE_BLOCKED',
        reason: 'Fail-open time limit exceeded while the gateway was unreachable',
      });
      return buildErrorResponse(packet, 'SERVFAIL');
    }

    this.localQueue.enqueue({
      domain: signature.name,
      actionTaken: 'FAIL_OPEN_ALLOWED',
      reason: 'Gateway unreachable; allowed under the temporary fail-open policy',
    });
    try {
      return await this.queryFallback(queryBuffer, signature);
    } catch (err) {
      this.logLimited('fallback', 'fallback resolver failed', { error: errorMessageOf(err) });
      return buildErrorResponse(packet, 'SERVFAIL');
    }
  }

  private recoverFromOutage(): void {
    this.state = 'ONLINE';
    this.failOpenStartMs = null;
    this.notify('gateway-restored', {
      title: 'Work DNS — Connection restored',
      message: 'The DNS gateway is reachable again and filtering is active.',
    });

    const sink = this.eventSink;
    if (!sink) {
      if (this.localQueue.getCount() > 0) {
        this.logLimited('no-sink', 'no event sink configured: offline events stay queued on this device', {
          queued: this.localQueue.getCount(),
        });
      }
      return;
    }
    this.localQueue.flush(sink).catch((err: unknown) => {
      logError('failed to deliver queued offline events; they stay queued', { error: errorMessageOf(err) });
    });
  }

  private async queryGateway(
    queryBuffer: Buffer,
    signature: QuerySignature
  ): Promise<{ response: Buffer; isBlock: boolean }> {
    const result = await this.postDns(this.gatewayUrl, queryBuffer, {
      Authorization: `Bearer ${this.deviceToken}`,
    });

    if (result.status === 401 || result.status === 403) {
      throw new GatewayFailure('auth', `gateway returned HTTP ${result.status}`, result.status);
    }
    if (result.status >= 500) {
      throw new GatewayFailure('unreachable', `gateway returned HTTP ${result.status}`, result.status);
    }
    if (result.status !== 200) {
      throw new GatewayFailure('rejected', `gateway returned HTTP ${result.status}`, result.status);
    }
    if (result.contentType !== DNS_MESSAGE_TYPE) {
      throw new GatewayFailure('bad_response', `gateway returned unexpected content type "${result.contentType}"`);
    }
    this.validateResponse(result.body, signature);

    const rcode = (result.body[3] ?? 0) & 0x0f;
    // The header alone never triggers a notification: it must agree with a real NXDOMAIN answer.
    return { response: result.body, isBlock: result.policyAction === 'BLOCK' && rcode === 3 };
  }

  private async queryFallback(queryBuffer: Buffer, signature: QuerySignature): Promise<Buffer> {
    const result = await this.postDns(this.fallbackUrl, queryBuffer, {});
    if (result.status !== 200) {
      throw new GatewayFailure('rejected', `fallback resolver returned HTTP ${result.status}`, result.status);
    }
    if (result.contentType !== DNS_MESSAGE_TYPE) {
      throw new GatewayFailure('bad_response', `fallback resolver returned unexpected content type "${result.contentType}"`);
    }
    this.validateResponse(result.body, signature);
    return result.body;
  }

  private validateResponse(response: Buffer, expected: QuerySignature): void {
    if (response.length < HEADER_LENGTH) {
      throw new GatewayFailure('bad_response', 'response shorter than the 12-byte DNS header');
    }
    let decoded: dnsPacket.Packet;
    try {
      decoded = dnsPacket.decode(response);
    } catch (err) {
      throw new GatewayFailure('bad_response', `response is not a valid DNS message: ${errorMessageOf(err)}`);
    }
    if (decoded.type !== 'response') {
      throw new GatewayFailure('bad_response', 'message is not a response');
    }
    if (decoded.id !== expected.id) {
      throw new GatewayFailure('bad_response', `response id mismatch: expected ${expected.id}, got ${decoded.id}`);
    }
    const questions = decoded.questions ?? [];
    const question = questions[0];
    if (
      questions.length !== 1 ||
      !question ||
      normalizeName(question.name) !== expected.name ||
      String(question.type) !== expected.type ||
      String(question.class ?? 'IN') !== expected.className
    ) {
      throw new GatewayFailure('bad_response', 'response question does not match the query');
    }
  }

  private async postDns(url: string, body: Buffer, headers: Record<string, string>): Promise<DnsHttpResult> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.gatewayTimeoutMs);
    try {
      const doFetch = this.fetchImpl ?? globalThis.fetch;
      let response: Awaited<ReturnType<typeof fetch>>;
      try {
        response = await doFetch(url, {
          method: 'POST',
          headers: { 'Content-Type': DNS_MESSAGE_TYPE, Accept: DNS_MESSAGE_TYPE, ...headers },
          body,
          signal: controller.signal,
          redirect: 'error',
        });
      } catch (err) {
        throw new GatewayFailure('unreachable', `request to ${url} failed: ${errorMessageOf(err)}`);
      }

      const declared = response.headers.get('content-length');
      if (declared !== null && Number(declared) > MAX_DNS_MESSAGE_BYTES) {
        throw new GatewayFailure('bad_response', `response from ${url} is too large (${declared} bytes)`);
      }
      let bytes: Buffer;
      try {
        bytes = Buffer.from(await response.arrayBuffer());
      } catch (err) {
        throw new GatewayFailure('unreachable', `reading the response from ${url} failed: ${errorMessageOf(err)}`);
      }
      if (bytes.length > MAX_DNS_MESSAGE_BYTES) {
        throw new GatewayFailure('bad_response', `response from ${url} is too large (${bytes.length} bytes)`);
      }

      return {
        status: response.status,
        contentType: (response.headers.get('content-type') ?? '').split(';')[0]!.trim().toLowerCase(),
        policyAction: response.headers.get('x-policy-action'),
        body: bytes,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  private blockNotification(domain: string): NotificationOptions {
    return {
      title: 'Work DNS — Access blocked',
      message: `Access to ${domain} is restricted by company policy.`,
      ...(this.requestAccessUrl !== undefined
        ? {
            actionLabel: 'Request access',
            actionUrl: `${this.requestAccessUrl}?domain=${encodeURIComponent(domain)}`,
          }
        : {}),
    };
  }

  /** Shows a notification at most once per key per cooldown. Failures are logged, never thrown. */
  private notify(key: string, options: NotificationOptions): void {
    const nowMs = this.now();
    const last = this.lastNotificationMs.get(key);
    if (last !== undefined && nowMs - last < this.notificationCooldownMs) return;
    if (this.lastNotificationMs.size >= MAX_TRACKED_KEYS) this.lastNotificationMs.clear();
    this.lastNotificationMs.set(key, nowMs);
    this.platformAdapter.showNotification(options).catch((err: unknown) => {
      logError('failed to show notification', { error: errorMessageOf(err) });
    });
  }

  /** Logs at most once per key per cooldown so a flood of failures cannot flood the log. */
  private logLimited(key: string, message: string, fields: Record<string, unknown> = {}): void {
    const nowMs = this.now();
    const last = this.lastLogMs.get(key);
    if (last !== undefined && nowMs - last < LOG_COOLDOWN_MS) return;
    if (this.lastLogMs.size >= MAX_TRACKED_KEYS) this.lastLogMs.clear();
    this.lastLogMs.set(key, nowMs);
    logError(message, fields);
  }
}
