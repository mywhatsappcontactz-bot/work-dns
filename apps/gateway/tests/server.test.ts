import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import http from 'node:http';
import dnsPacket from 'dns-packet';
import { PolicyEngine } from '@work-dns/policy-engine';
import { PolicyDefinition, DomainAllowRule } from '@work-dns/shared-types';
import { DeviceAuthenticator } from '../src/auth.js';
import { DnsHandler } from '../src/dns-handler.js';
import { DohServer, DohServerConfig } from '../src/server.js';
import type { UpstreamResolver } from '../src/upstream.js';
import type { GatewayEventQueue } from '../src/event-queue.js';

const TOKEN = 'device-secret-bearer-token-abc-1234567890';

interface TestResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

function request(
  port: number,
  opts: {
    method?: string;
    path?: string;
    headers?: http.OutgoingHttpHeaders;
    body?: Buffer | string;
    chunks?: Buffer[];
  } = {}
): Promise<TestResponse> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, method: opts.method ?? 'GET', path: opts.path ?? '/', headers: opts.headers ?? {} },
      (res) => {
        const parts: Buffer[] = [];
        res.on('data', (c: Buffer) => parts.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(parts) }));
      }
    );
    req.on('error', reject);
    for (const chunk of opts.chunks ?? []) {
      req.write(chunk);
    }
    if (opts.body !== undefined) {
      req.write(opts.body);
    }
    req.end();
  });
}

function makeQuery(name: string): Buffer {
  return Buffer.from(
    dnsPacket.encode({
      type: 'query',
      id: 11,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{ type: 'A', name }],
    })
  );
}

const authHeaders = (extra: http.OutgoingHttpHeaders = {}): http.OutgoingHttpHeaders => ({
  authorization: `Bearer ${TOKEN}`,
  'content-type': 'application/dns-message',
  ...extra,
});

describe('DohServer', () => {
  let server: DohServer;
  let port: number;
  let auth: DeviceAuthenticator;
  let handler: DnsHandler;
  let upstream: { resolve: ReturnType<typeof vi.fn> };
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  async function start(extra: Partial<DohServerConfig> = {}): Promise<void> {
    server = new DohServer(auth, handler);
    await server.start({ port: 0, host: '127.0.0.1', ...extra });
    port = server.getPort()!;
  }

  beforeEach(() => {
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    auth = new DeviceAuthenticator();
    auth.registerTokenHash(DeviceAuthenticator.hashToken(TOKEN), {
      deviceId: 'dev-1',
      companyId: 'comp-100',
      deviceGroupId: null,
      status: 'active',
    });

    upstream = { resolve: vi.fn().mockResolvedValue(Buffer.from('upstream-answer')) };
    handler = new DnsHandler({
      policyEngine: new PolicyEngine(),
      upstreamResolver: upstream as unknown as UpstreamResolver,
      eventQueue: { enqueueBlockedAttempt: vi.fn() } as unknown as GatewayEventQueue,
    });
    const policy: PolicyDefinition = {
      id: 'pol-1',
      companyId: 'comp-100',
      version: 1,
      mode: 'strict',
      defaultActionDuringEnforcedHours: 'BLOCK',
      defaultActionOutsideEnforcedHours: 'BLOCK',
      timezone: 'Africa/Lagos',
      rules: [
        { id: 'r1', type: 'domain_allow', pattern: '*.google.com', effect: 'ALLOW', priority: 1 } as DomainAllowRule,
      ],
      updatedAt: new Date().toISOString(),
    };
    handler.updateCompiledPolicy(policy);
  });

  afterEach(async () => {
    await server.stop();
    errorSpy.mockRestore();
    warnSpy.mockRestore();
  });

  it('serves an allowed query over POST with safe response headers', async () => {
    await start();
    const res = await request(port, { method: 'POST', path: '/dns-query', headers: authHeaders(), body: makeQuery('mail.google.com') });
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/dns-message');
    expect(res.headers['x-policy-action']).toBe('ALLOW');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.body.toString()).toBe('upstream-answer');
  });

  it('answers blocked queries with a real NXDOMAIN and X-Policy-Action BLOCK', async () => {
    await start();
    const res = await request(port, { method: 'POST', path: '/dns-query', headers: authHeaders(), body: makeQuery('facebook.com') });
    expect(res.status).toBe(200);
    expect(res.headers['x-policy-action']).toBe('BLOCK');
    expect(dnsPacket.decode(res.body).rcode).toBe('NXDOMAIN');
  });

  it('returns the same generic 401 body for missing, unknown and revoked tokens', async () => {
    await start();
    const base = { method: 'POST', path: '/dns-query', body: makeQuery('mail.google.com') };
    const missing = await request(port, { ...base, headers: { 'content-type': 'application/dns-message' } });
    const unknown = await request(port, { ...base, headers: authHeaders({ authorization: 'Bearer not-a-registered-token' }) });
    auth.revokeTokenHash(DeviceAuthenticator.hashToken(TOKEN));
    const revoked = await request(port, { ...base, headers: authHeaders() });

    for (const res of [missing, unknown, revoked]) {
      expect(res.status).toBe(401);
      expect(res.body.toString()).toBe(JSON.stringify({ error: 'Unauthorized' }));
      expect(res.headers['www-authenticate']).toBe('Bearer');
    }
    expect(upstream.resolve).not.toHaveBeenCalled();
  });

  it('accepts a lowercase bearer scheme', async () => {
    await start();
    const res = await request(port, {
      method: 'POST',
      path: '/dns-query',
      headers: authHeaders({ authorization: `bearer ${TOKEN}` }),
      body: makeQuery('mail.google.com'),
    });
    expect(res.status).toBe(200);
  });

  it('rejects non DNS content types (415) and accepts media type parameters', async () => {
    await start();
    const wrong = await request(port, { method: 'POST', path: '/dns-query', headers: authHeaders({ 'content-type': 'text/plain' }), body: makeQuery('mail.google.com') });
    expect(wrong.status).toBe(415);
    const withParam = await request(port, {
      method: 'POST',
      path: '/dns-query',
      headers: authHeaders({ 'content-type': 'application/dns-message; foo=bar' }),
      body: makeQuery('mail.google.com'),
    });
    expect(withParam.status).toBe(200);
  });

  it('rejects oversized bodies with 413 whether declared or streamed', async () => {
    await start();
    const declared = await request(port, {
      method: 'POST',
      path: '/dns-query',
      headers: authHeaders({ 'content-length': '5000' }),
      body: Buffer.alloc(10),
    });
    expect(declared.status).toBe(413);

    const streamed = await request(port, {
      method: 'POST',
      path: '/dns-query',
      headers: authHeaders({ 'transfer-encoding': 'chunked' }),
      chunks: [Buffer.alloc(3000), Buffer.alloc(3000)],
    });
    expect(streamed.status).toBe(413);
    expect(upstream.resolve).not.toHaveBeenCalled();
  });

  it('supports GET with unpadded base64url and rejects malformed values', async () => {
    await start();
    const encoded = makeQuery('mail.google.com').toString('base64url');
    const ok = await request(port, { path: `/dns-query?dns=${encoded}`, headers: { authorization: `Bearer ${TOKEN}` } });
    expect(ok.status).toBe(200);

    const bad = await request(port, { path: '/dns-query?dns=***', headers: { authorization: `Bearer ${TOKEN}` } });
    expect(bad.status).toBe(400);
    const padded = await request(port, { path: `/dns-query?dns=${encoded}%3D`, headers: { authorization: `Bearer ${TOKEN}` } });
    expect(padded.status).toBe(400);
    const missing = await request(port, { path: '/dns-query', headers: { authorization: `Bearer ${TOKEN}` } });
    expect(missing.status).toBe(400);
  });

  it('returns 405 with an Allow header for other methods', async () => {
    await start();
    const res = await request(port, { method: 'PUT', path: '/dns-query', headers: authHeaders(), body: makeQuery('mail.google.com') });
    expect(res.status).toBe(405);
    expect(res.headers['allow']).toBe('POST, GET');
  });

  it('returns 404 for unknown paths and 400 for protocol-relative paths', async () => {
    await start();
    expect((await request(port, { path: '/nope' })).status).toBe(404);
    expect((await request(port, { path: '//evil.example/dns-query' })).status).toBe(400);
  });

  it('serves /health without revealing service details', async () => {
    await start();
    const res = await request(port, { path: '/health' });
    expect(res.status).toBe(200);
    expect(res.body.toString()).toBe(JSON.stringify({ status: 'ok' }));
  });

  it('limits requests per client IP before authentication', async () => {
    await start({ ipRateLimit: { burst: 3, refillPerSecond: 0 } });
    for (let i = 0; i < 3; i++) {
      expect((await request(port, { path: '/health' })).status).toBe(200);
    }
    const limited = await request(port, { path: '/health' });
    expect(limited.status).toBe(429);
    expect(limited.headers['retry-after']).toBe('1');
  });

  it('contains handler failures: generic 500 and the server keeps serving', async () => {
    await start();
    vi.spyOn(handler, 'handleDnsMessage').mockRejectedValueOnce(new Error('boom-internal-detail'));
    const failed = await request(port, { method: 'POST', path: '/dns-query', headers: authHeaders(), body: makeQuery('mail.google.com') });
    expect(failed.status).toBe(500);
    expect(failed.body.toString()).toBe(JSON.stringify({ error: 'Internal Server Error' }));
    expect(failed.body.toString()).not.toContain('boom');
    expect(errorSpy).toHaveBeenCalled();

    const next = await request(port, { method: 'POST', path: '/dns-query', headers: authHeaders(), body: makeQuery('mail.google.com') });
    expect(next.status).toBe(200);
  });

  it('uses the socket address and ignores X-Forwarded-For by default', async () => {
    await start();
    const spy = vi.spyOn(handler, 'handleDnsMessage');
    await request(port, {
      method: 'POST',
      path: '/dns-query',
      headers: authHeaders({ 'x-forwarded-for': '1.2.3.4' }),
      body: makeQuery('mail.google.com'),
    });
    expect(String(spy.mock.calls[0]![2])).toMatch(/127\.0\.0\.1$/);
  });

  it('with trustProxy uses the last X-Forwarded-For entry and falls back on invalid values', async () => {
    await start({ trustProxy: true });
    const spy = vi.spyOn(handler, 'handleDnsMessage');
    await request(port, {
      method: 'POST',
      path: '/dns-query',
      headers: authHeaders({ 'x-forwarded-for': '1.2.3.4, 9.9.9.9' }),
      body: makeQuery('mail.google.com'),
    });
    expect(spy.mock.calls[0]![2]).toBe('9.9.9.9');

    await request(port, {
      method: 'POST',
      path: '/dns-query',
      headers: authHeaders({ 'x-forwarded-for': 'not-an-ip' }),
      body: makeQuery('mail.google.com'),
    });
    expect(String(spy.mock.calls[1]![2])).toMatch(/127\.0\.0\.1$/);
  });

  it('releases the port on stop()', async () => {
    await start();
    await server.stop();
    await expect(request(port, { path: '/health' })).rejects.toThrow();
  });
});
