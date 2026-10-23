import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import http from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import dnsPacket from 'dns-packet';
import { DeviceAuthenticator } from '../src/auth.js';
import { startGateway, RunningGateway } from '../src/main.js';

function dnsQuery(name: string): Buffer {
  return Buffer.from(
    dnsPacket.encode({ type: 'query', id: 21, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'A', name }] })
  );
}

function upstreamAnswer(name: string): Buffer {
  return Buffer.from(
    dnsPacket.encode({
      type: 'response',
      id: 0,
      flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
      questions: [{ type: 'A', name }],
      answers: [{ type: 'A', name, ttl: 300, data: '93.184.216.34' }],
    })
  );
}

const fakeFetch = (async (_url: string, init: { body: Buffer }) => {
  const name = dnsPacket.decode(init.body).questions![0]!.name;
  const body = upstreamAnswer(name);
  return {
    status: 200,
    headers: new Headers({ 'content-type': 'application/dns-message' }),
    arrayBuffer: async () => new Uint8Array(body).buffer,
  };
}) as unknown as typeof fetch;

function post(port: number, token: string | null, body: Buffer): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const headers: http.OutgoingHttpHeaders = { 'content-type': 'application/dns-message' };
    if (token !== null) headers.authorization = `Bearer ${token}`;
    const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/dns-query', headers }, (res) => {
      const parts: Buffer[] = [];
      res.on('data', (chunk: Buffer) => parts.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(parts) }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

describe('startGateway', () => {
  let dir: string;
  let token: string;
  let tokensFile: string;
  let policiesFile: string;
  let env: NodeJS.ProcessEnv;
  let running: RunningGateway | null;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  const tokenEntry = (companyId: string) => ({
    tokenHash: DeviceAuthenticator.hashToken(token),
    deviceId: 'dev-1',
    companyId,
    deviceGroupId: null,
    status: 'active',
  });

  const writeTokens = (entries: unknown, mode = 0o600): void => {
    fs.writeFileSync(tokensFile, JSON.stringify(entries), { mode });
    fs.chmodSync(tokensFile, mode);
  };

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'work-dns-gateway-'));
    token = randomBytes(32).toString('base64url');
    tokensFile = path.join(dir, 'tokens.json');
    policiesFile = path.join(dir, 'policies.json');
    writeTokens([tokenEntry('comp-100')]);
    fs.writeFileSync(
      policiesFile,
      JSON.stringify([
        {
          id: 'pol-1',
          companyId: 'comp-100',
          version: 1,
          mode: 'strict',
          defaultActionDuringEnforcedHours: 'BLOCK',
          defaultActionOutsideEnforcedHours: 'BLOCK',
          timezone: 'Africa/Lagos',
          rules: [{ id: 'r1', type: 'domain_allow', pattern: '*.google.com', effect: 'ALLOW', priority: 1 }],
          updatedAt: '2026-10-21T00:00:00.000Z',
        },
      ])
    );
    env = { GATEWAY_PORT: '0', GATEWAY_TOKENS_FILE: tokensFile, GATEWAY_POLICIES_FILE: policiesFile };
    running = null;
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(async () => {
    if (running) await running.stop();
    logSpy.mockRestore();
    warnSpy.mockRestore();
    errorSpy.mockRestore();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('serves allowed queries, blocks others with NXDOMAIN and rejects unknown tokens', async () => {
    running = await startGateway(env, { fetchImpl: fakeFetch });
    expect(running.port).toBeGreaterThan(0);

    const allowed = await post(running.port, token, dnsQuery('mail.google.com'));
    expect(allowed.status).toBe(200);
    expect(allowed.headers['x-policy-action']).toBe('ALLOW');
    expect(dnsPacket.decode(allowed.body).answers).toHaveLength(1);

    const blocked = await post(running.port, token, dnsQuery('facebook.com'));
    expect(blocked.status).toBe(200);
    expect(blocked.headers['x-policy-action']).toBe('BLOCK');
    expect(dnsPacket.decode(blocked.body).rcode).toBe('NXDOMAIN');

    expect((await post(running.port, 'not-a-registered-token', dnsQuery('mail.google.com'))).status).toBe(401);
    expect((await post(running.port, null, dnsQuery('mail.google.com'))).status).toBe(401);
  });

  it('never logs the raw token', async () => {
    running = await startGateway(env, { fetchImpl: fakeFetch });
    await post(running.port, token, dnsQuery('mail.google.com'));
    await post(running.port, 'wrong-token-value', dnsQuery('mail.google.com'));
    const logged = [...logSpy.mock.calls, ...warnSpy.mock.calls, ...errorSpy.mock.calls].flat().join('\n');
    expect(logged).not.toContain(token);
    expect(logged).not.toContain('wrong-token-value');
  });

  it('warns about companies that have device tokens but no policy', async () => {
    writeTokens([tokenEntry('comp-without-policy')]);
    running = await startGateway(env, { fetchImpl: fakeFetch });
    expect(warnSpy.mock.calls.some((call) => String(call[0]).includes('no policy'))).toBe(true);

    const result = await post(running.port, token, dnsQuery('mail.google.com'));
    expect(result.headers['x-policy-action']).toBe('BLOCK');
  });

  it('refuses to start with invalid configuration and reports every problem', async () => {
    await expect(startGateway({})).rejects.toThrow(/GATEWAY_TOKENS_FILE[\s\S]*GATEWAY_POLICIES_FILE/);
  });

  it.skipIf(process.platform === 'win32')('refuses to start when the tokens file is readable by others', async () => {
    writeTokens([tokenEntry('comp-100')], 0o644);
    await expect(startGateway(env, { fetchImpl: fakeFetch })).rejects.toThrow(/chmod 600/);
  });

  it('refuses to start with a malformed policy file', async () => {
    fs.writeFileSync(policiesFile, '{not json');
    await expect(startGateway(env, { fetchImpl: fakeFetch })).rejects.toThrow(/not valid JSON/);
  });

  it('stop() is idempotent and releases the port', async () => {
    const gateway = await startGateway(env, { fetchImpl: fakeFetch });
    const { port } = gateway;
    await Promise.all([gateway.stop(), gateway.stop()]);
    await gateway.stop();
    await expect(post(port, token, dnsQuery('mail.google.com'))).rejects.toThrow();
  });
});
