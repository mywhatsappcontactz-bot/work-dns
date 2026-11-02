import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import dnsPacket from 'dns-packet';
import { DnsStubServer, USER_HEADER } from '../src/dns-stub.js';
import { LocalEventQueue } from '../src/local-queue.js';
import { MockPlatformAdapter } from '../src/platform/mock-adapter.js';

const GATEWAY = 'http://127.0.0.1:8053/dns-query';
const FALLBACK = 'https://fallback.test/dns-query';

const query = (name = 'example.org') =>
    Buffer.from(dnsPacket.encode({ type: 'query', id: 4242, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'A', name }] }));

describe('DnsStubServer console user header', () => {
    let dir: string;
    let gatewayUp: boolean;
    let requests: Array<{ url: string; headers: Record<string, string> }>;

    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
        const target = String(url);
        requests.push({ url: target, headers: { ...(init?.headers as Record<string, string>) } });
        if (target === GATEWAY && !gatewayUp) return new Response('', { status: 503 });
        const echo = Buffer.from(init!.body as Buffer);
        echo[2] = (echo[2] ?? 0) | 0x80; // mark the echoed query as a response
        return new Response(echo, { status: 200, headers: { 'content-type': 'application/dns-message' } });
    }) as typeof fetch;

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-userhdr-'));
        gatewayUp = true;
        requests = [];
        vi.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        vi.restoreAllMocks();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    const make = (consoleUser?: () => string) =>
        new DnsStubServer(
            {
                loopbackPort: 0,
                gatewayUrl: GATEWAY,
                deviceToken: 'tok',
                fallbackUpstreamDoh: FALLBACK,
                fetchImpl,
                ...(consoleUser === undefined ? {} : { consoleUser }),
            },
            new MockPlatformAdapter(),
            new LocalEventQueue({ filePath: path.join(dir, 'q.jsonl') })
        );

    it('sends the console user to the gateway next to the token', async () => {
        await make(() => 'berlin').handleQuery(query());
        expect(requests).toHaveLength(1);
        expect(requests[0]!.url).toBe(GATEWAY);
        expect(requests[0]!.headers[USER_HEADER]).toBe('berlin');
        expect(requests[0]!.headers.Authorization).toBe('Bearer tok');
    });

    it('asks the provider again for every query', async () => {
        let current = 'berlin';
        const stub = make(() => current);
        await stub.handleQuery(query('a.example.org'));
        current = 'alice';
        await stub.handleQuery(query('b.example.org'));
        expect(requests.map((r) => r.headers[USER_HEADER])).toEqual(['berlin', 'alice']);
    });

    it('sends no header when the user is unknown', async () => {
        await make(() => 'unknown').handleQuery(query());
        expect(requests[0]!.headers).not.toHaveProperty(USER_HEADER);
    });

    it('sends no header when no provider is configured', async () => {
        await make().handleQuery(query());
        expect(requests[0]!.headers).not.toHaveProperty(USER_HEADER);
    });

    it('never sends the user to the fallback resolver', async () => {
        gatewayUp = false;
        const stub = make(() => 'berlin');
        await stub.handleQuery(query());
        expect(requests[0]!.url).toBe(GATEWAY);
        expect(requests[0]!.headers[USER_HEADER]).toBe('berlin');
        const toFallback = requests.filter((r) => r.url === FALLBACK);
        expect(toFallback.length).toBeGreaterThan(0);
        for (const request of toFallback) {
            expect(request.headers).not.toHaveProperty(USER_HEADER);
            expect(request.headers).not.toHaveProperty('Authorization');
        }
    });

    it('drops an unsafe name instead of breaking the request or tripping fail-open', async () => {
        const stub = make(() => 'bad name\r\nX-Evil: 1');
        const response = await stub.handleQuery(query());
        expect(response.length).toBeGreaterThanOrEqual(12);
        expect(stub.getState()).toBe('ONLINE');
        expect(requests[0]!.headers).not.toHaveProperty(USER_HEADER);
        expect(Object.keys(requests[0]!.headers).some((key) => key.toLowerCase() === 'x-evil')).toBe(false);
    });

    it('keeps resolving, and says so, when the provider throws', async () => {
        const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const stub = make(() => {
            throw new Error('logind exploded');
        });
        const response = await stub.handleQuery(query());
        expect(response.length).toBeGreaterThanOrEqual(12);
        expect(stub.getState()).toBe('ONLINE');
        expect(requests[0]!.headers).not.toHaveProperty(USER_HEADER);
        expect(spy.mock.calls.some((call) => String(call[0]).includes('console user lookup failed'))).toBe(true);
    });
});
