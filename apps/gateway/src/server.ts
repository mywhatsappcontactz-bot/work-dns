import http from 'node:http';
import { isIP } from 'node:net';
import { DeviceAuthenticator } from './auth.js';
import { DnsHandler, MAX_DNS_PACKET_SIZE } from './dns-handler.js';
import { IpRateLimiter } from './ip-rate-limiter.js';

export interface DohServerConfig {
  port: number;
  host?: string;
  /**
   * Set true ONLY when running behind a reverse proxy you control that appends the real
   * client address to X-Forwarded-For. The last entry is then used as the client IP.
   */
  trustProxy?: boolean;
  /** Per-client-IP limit applied before authentication. */
  ipRateLimit?: { burst: number; refillPerSecond: number; maxEntries?: number };
  requestTimeoutMs?: number;
}

const DEFAULT_IP_RATE_LIMIT = { burst: 1000, refillPerSecond: 500, maxEntries: 10_000 };
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const HEADERS_TIMEOUT_MS = 5_000;
const KEEP_ALIVE_TIMEOUT_MS = 5_000;
const FORCE_CLOSE_AFTER_MS = 5_000;
const MAX_FORWARDED_ADDRESS_LENGTH = 64;
const AUTH_LOG_INTERVAL_MS = 1_000;

class HttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function logLine(level: 'error' | 'warn', message: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ level, message, ...fields });
  if (level === 'error') {
    console.error(line);
  } else {
    console.warn(line);
  }
}

export class DohServer {
  private server: http.Server | null = null;
  private readonly authenticator: DeviceAuthenticator;
  private readonly handler: DnsHandler;
  private ipLimiter: IpRateLimiter | null = null;
  private trustProxy = false;
  private lastAuthLogMs = 0;
  private suppressedAuthLogs = 0;

  constructor(authenticator: DeviceAuthenticator, handler: DnsHandler) {
    this.authenticator = authenticator;
    this.handler = handler;
  }

  public start(config: DohServerConfig): Promise<void> {
    if (this.server) {
      return Promise.reject(new Error('DohServer is already started'));
    }

    const host = config.host ?? '127.0.0.1';
    if (host !== '127.0.0.1' && host !== '::1' && host !== 'localhost') {
      logLine('warn', 'DohServer is binding to a non-loopback address over plain HTTP: put a TLS reverse proxy in front', { host });
    }

    const limit = config.ipRateLimit ?? DEFAULT_IP_RATE_LIMIT;
    this.ipLimiter = new IpRateLimiter({
      burst: limit.burst,
      refillPerSecond: limit.refillPerSecond,
      ...(limit.maxEntries !== undefined ? { maxEntries: limit.maxEntries } : {}),
    });
    this.trustProxy = config.trustProxy === true;

    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        this.handleRequest(req, res).catch((err: unknown) => this.handleUnexpectedError(res, err));
      });
      const requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
      server.requestTimeout = requestTimeoutMs;
      server.headersTimeout = Math.min(HEADERS_TIMEOUT_MS, requestTimeoutMs);
      server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT_MS;
      server.maxHeadersCount = 50;

      const onStartError = (err: Error): void => {
        this.server = null;
        reject(err);
      };
      server.once('error', onStartError);
      server.listen(config.port, host, () => {
        server.off('error', onStartError);
        server.on('error', (err: Error) => logLine('error', 'http server error', { error: err.message }));
        resolve();
      });
      this.server = server;
    });
  }

  public stop(): Promise<void> {
    const server = this.server;
    if (!server) {
      return Promise.resolve();
    }
    this.server = null;
    return new Promise((resolve) => {
      const force = setTimeout(() => server.closeAllConnections(), FORCE_CLOSE_AFTER_MS);
      force.unref();
      server.close(() => {
        clearTimeout(force);
        resolve();
      });
      server.closeIdleConnections();
    });
  }

  /** Actual listening port (useful when started with port 0). */
  public getPort(): number | null {
    const address = this.server?.address();
    return address && typeof address === 'object' ? address.port : null;
  }

  private clientIpOf(req: http.IncomingMessage): string {
    const socketIp = req.socket.remoteAddress ?? 'unknown';
    if (!this.trustProxy) {
      return socketIp;
    }
    const forwarded = req.headers['x-forwarded-for'];
    const raw = Array.isArray(forwarded) ? forwarded.join(',') : forwarded;
    if (!raw) {
      return socketIp;
    }
    const parts = raw.split(',').map((part) => part.trim()).filter((part) => part.length > 0);
    const last = parts[parts.length - 1];
    if (last && last.length <= MAX_FORWARDED_ADDRESS_LENGTH && isIP(last) !== 0) {
      return last;
    }
    return socketIp;
  }

  private logAuthFailure(clientIp: string, status: number | undefined, detail: string | undefined): void {
    const now = Date.now();
    if (now - this.lastAuthLogMs < AUTH_LOG_INTERVAL_MS) {
      this.suppressedAuthLogs += 1;
      return;
    }
    logLine('warn', 'authentication failed', {
      clientIp,
      status,
      detail,
      suppressedSinceLastLog: this.suppressedAuthLogs,
    });
    this.lastAuthLogMs = now;
    this.suppressedAuthLogs = 0;
  }

  private sendJson(
    res: http.ServerResponse,
    status: number,
    body: Record<string, unknown>,
    extraHeaders: http.OutgoingHttpHeaders = {},
    closeConnection = false
  ): void {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    const payload = JSON.stringify(body);
    res.writeHead(status, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...(closeConnection ? { Connection: 'close' } : {}),
      ...extraHeaders,
    });
    res.end(payload);
  }

  private handleUnexpectedError(res: http.ServerResponse, err: unknown): void {
    if (err instanceof HttpError) {
      this.sendJson(res, err.status, { error: err.message }, {}, err.status === 413);
      return;
    }
    logLine('error', 'unhandled error while processing request', { error: errorMessageOf(err) });
    this.sendJson(res, 500, { error: 'Internal Server Error' });
  }

  private readBody(req: http.IncomingMessage, maxBytes: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const declared = req.headers['content-length'];
      if (declared !== undefined) {
        const length = Number(declared);
        if (!Number.isFinite(length) || length < 0) {
          reject(new HttpError(400, 'Invalid Content-Length'));
          return;
        }
        if (length > maxBytes) {
          reject(new HttpError(413, 'Payload Too Large'));
          return;
        }
      }

      const chunks: Buffer[] = [];
      let total = 0;
      let settled = false;
      const settle = (action: () => void): void => {
        if (settled) return;
        settled = true;
        action();
      };

      req.on('data', (chunk: Buffer) => {
        if (settled) return; // keep draining, but stop buffering
        total += chunk.length;
        if (total > maxBytes) {
          settle(() => reject(new HttpError(413, 'Payload Too Large')));
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => settle(() => resolve(Buffer.concat(chunks, total))));
      req.on('error', (err) => settle(() => reject(err)));
      req.on('close', () => settle(() => reject(new HttpError(400, 'Request aborted'))));
    });
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const rawUrl = req.url ?? '/';
    if (!rawUrl.startsWith('/') || rawUrl.startsWith('//')) {
      this.sendJson(res, 400, { error: 'Bad Request' });
      return;
    }
    const queryIndex = rawUrl.indexOf('?');
    const pathname = queryIndex === -1 ? rawUrl : rawUrl.slice(0, queryIndex);
    const search = queryIndex === -1 ? '' : rawUrl.slice(queryIndex + 1);

    const clientIp = this.clientIpOf(req);

    // Per-client limit before any authentication work.
    if (this.ipLimiter && !this.ipLimiter.allow(clientIp)) {
      this.sendJson(res, 429, { error: 'Too Many Requests' }, { 'Retry-After': '1' });
      return;
    }

    if (pathname === '/health') {
      if (req.method !== 'GET') {
        this.sendJson(res, 405, { error: 'Method Not Allowed' }, { Allow: 'GET' });
        return;
      }
      this.sendJson(res, 200, { status: 'ok' });
      return;
    }

    if (pathname !== '/dns-query') {
      this.sendJson(res, 404, { error: 'Not Found' });
      return;
    }

    // 1. Authenticate. Clients always get the same body; details are logged, never returned.
    const authResult = this.authenticator.authenticateHeader(req.headers['authorization']);
    if (!authResult.authenticated || !authResult.context) {
      if (authResult.errorStatus === 429) {
        this.sendJson(res, 429, { error: 'Too Many Requests' }, { 'Retry-After': '1' });
        return;
      }
      this.logAuthFailure(clientIp, authResult.errorStatus, authResult.errorMessage);
      this.sendJson(res, 401, { error: 'Unauthorized' }, { 'WWW-Authenticate': 'Bearer' });
      return;
    }

    // 2. Obtain the DNS message (RFC 8484 POST body or GET ?dns=base64url).
    let dnsMessage: Buffer;
    if (req.method === 'POST') {
      const mediaType = (req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
      if (mediaType !== 'application/dns-message') {
        this.sendJson(res, 415, { error: 'Unsupported Media Type: expected application/dns-message' });
        return;
      }
      dnsMessage = await this.readBody(req, MAX_DNS_PACKET_SIZE);
    } else if (req.method === 'GET') {
      const dnsParam = new URLSearchParams(search).get('dns');
      if (!dnsParam) {
        this.sendJson(res, 400, { error: 'Missing dns query parameter' });
        return;
      }
      if (dnsParam.length > Math.ceil((MAX_DNS_PACKET_SIZE * 4) / 3)) {
        this.sendJson(res, 413, { error: 'Payload Too Large' });
        return;
      }
      if (!/^[A-Za-z0-9_-]+$/.test(dnsParam)) {
        this.sendJson(res, 400, { error: 'dns parameter must be unpadded base64url' });
        return;
      }
      dnsMessage = Buffer.from(dnsParam, 'base64url');
    } else {
      this.sendJson(res, 405, { error: 'Method Not Allowed' }, { Allow: 'POST, GET' });
      return;
    }

    // 3. Resolve.
    const result = await this.handler.handleDnsMessage(dnsMessage, authResult.context, clientIp);
    if (result.statusCode !== 200 || !result.responseBuffer) {
      this.sendJson(res, result.statusCode, { error: result.errorMessage ?? 'Bad Request' });
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'application/dns-message',
      'Content-Length': result.responseBuffer.length,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Policy-Action': result.action,
      'X-Resolution-Microseconds': Math.round(result.latencyMicroseconds),
    });
    res.end(result.responseBuffer);
  }
}
