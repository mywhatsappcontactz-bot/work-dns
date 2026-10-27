import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import dnsPacket from 'dns-packet';
import { DnsStubServer } from '../src/dns-stub.js';
import type { GatewayStateChange } from '../src/dns-stub.js';
import { LocalEventQueue } from '../src/local-queue.js';
import { MockPlatformAdapter } from '../src/platform/mock-adapter.js';

const GATEWAY = 'http://127.0.0.1:8053/dns-query';

const query = () =>
    Buffer.from(dnsPacket.encode({ type: 'query', id: 4242, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'A', name: 'example.org' }] }));

describe('DnsStubServer onStateChange', () => {
    let dir: string;
    let nowMs: number;
    let gatewayUp: boolean;
    let changes: GatewayStateChange[];

    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
        if (String(url).startsWith('http://127.0.0.1:8053') && !gatewayUp) {
            return new Response('', { status: 503 });
        }
        const echo = Buffer.from(init!.body as Buffer);
        echo[2] = (echo[2] ?? 0) | 0x80; // mark the echoed query as a response
        return new Response(echo, { status: 200, headers: { 'content-type': 'application/dns-message' } });
    }) as typeof fetch;

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-stub-'));
        nowMs = Date.UTC(2026, 9, 24, 12, 0, 0);
        gatewayUp = true;
        changes = [];
        vi.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        vi.restoreAllMocks();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    const make = (onStateChange: (change: GatewayStateChange) => void) =>
        new DnsStubServer(
            { loopbackPort: 0, gatewayUrl: GATEWAY, deviceToken: 'tok', failOpenMaxMinutes: 1, fetchImpl, now: () => nowMs, onStateChange },
            new MockPlatformAdapter(),
            new LocalEventQueue({ filePath: path.join(dir, 'q.jsonl') })
        );

    it('reports fail-open entered, fail-closed entered, and recovery with the outage length', async () => {
        const stub = make((change) => {
            changes.push(change);
        });
        gatewayUp = false;
        await stub.handleQuery(query());
        expect(stub.getState()).toBe('FAIL_OPEN_ACTIVE');
        expect(changes.map((c) => `${c.from}>${c.to}`)).toEqual(['ONLINE>FAIL_OPEN_ACTIVE']);

        nowMs += 2 * 60_000;
        await stub.handleQuery(query());
        expect(changes.map((c) => `${c.from}>${c.to}`)).toEqual(['ONLINE>FAIL_OPEN_ACTIVE', 'FAIL_OPEN_ACTIVE>FAIL_CLOSED']);

        nowMs += 60_000;
        gatewayUp = true;
        await stub.handleQuery(query());
        expect(stub.getState()).toBe('ONLINE');
        expect(changes[2]).toMatchObject({ from: 'FAIL_CLOSED', to: 'ONLINE', outageSeconds: 180 });
    });

    it('a throwing callback does not break DNS resolution', async () => {
        const stub = make(() => {
            throw new Error('boom');
        });
        gatewayUp = false;
        const response = await stub.handleQuery(query());
        expect(response.length).toBeGreaterThanOrEqual(12);
        expect(stub.getState()).toBe('FAIL_OPEN_ACTIVE');
    });

    it('stays quiet while nothing changes', async () => {
        const stub = make((change) => {
            changes.push(change);
        });
        for (let i = 0; i < 3; i += 1) await stub.handleQuery(query());
        expect(changes).toEqual([]);
        expect(stub.getState()).toBe('ONLINE');
    });
});
