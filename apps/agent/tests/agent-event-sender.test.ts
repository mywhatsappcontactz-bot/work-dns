import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AgentOutbox } from '../src/outbox.js';
import { AgentEventSender } from '../src/event-sender.js';

const GW = 'http://127.0.0.1:8053/dns-query';
const EVENTS_URL = 'http://127.0.0.1:8053/api/v1/agent-events';

type Sent = Array<{ id: string; type: string }>;

function reply(status: number, body: string, contentType = 'application/json'): Response {
    return {
        status,
        headers: new Headers({ 'content-type': contentType }),
        arrayBuffer: async () => new TextEncoder().encode(body).buffer,
    } as unknown as Response;
}
const receipt = (n: number) => reply(200, JSON.stringify({ accepted: n, duplicates: 0 }));
const rejectAt = (index: number) =>
    reply(400, JSON.stringify({ error: 'Invalid event batch', detail: 'type cannot be submitted by a device', index }));

function fakeGateway(handler: (events: Sent, call: number) => Response | Promise<Response>) {
    const requests: Array<{ url: string; init: RequestInit; events: Sent }> = [];
    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body)) as { events: Sent };
        requests.push({ url: String(url), init: init!, events: body.events });
        return handler(body.events, requests.length);
    }) as typeof fetch;
    return { fetchImpl, requests };
}

describe('AgentEventSender', () => {
    let dir: string;
    let quarantineFile: string;
    let logs: Array<{ level: string; message: string }>;

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-sender-'));
        quarantineFile = path.join(dir, 'quarantine.jsonl');
        logs = [];
    });

    afterEach(() => {
        vi.useRealTimers();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    function build(fetchImpl: typeof fetch, extra: Record<string, unknown> = {}) {
        const outbox = new AgentOutbox({ filePath: path.join(dir, 'outbox.jsonl'), quarantinePath: quarantineFile });
        const sender = new AgentEventSender({
            outbox,
            gatewayUrl: GW,
            deviceToken: 'secret-token',
            fetchImpl,
            baseBackoffMs: 1000,
            maxBackoffMs: 8000,
            random: () => 0.5,
            log: (level, message) => {
                logs.push({ level, message });
            },
            ...extra,
        });
        return { outbox, sender };
    }

    const fill = (outbox: AgentOutbox, count: number) =>
        Array.from({ length: count }, (_, n) => outbox.add('enforcement_reset', { n }));

    it('posts to the derived URL with the token only in the header, and acknowledges a matching receipt', async () => {
        const gw = fakeGateway((events) => receipt(events.length));
        const { outbox, sender } = build(gw.fetchImpl);
        fill(outbox, 2);
        expect(await sender.flushOnce()).toBe('delivered');
        expect(gw.requests).toHaveLength(1);
        const { url, init } = gw.requests[0]!;
        expect(url).toBe(EVENTS_URL);
        expect(init.method).toBe('POST');
        expect(init.redirect).toBe('error');
        expect(init.headers).toMatchObject({ Authorization: 'Bearer secret-token', 'Content-Type': 'application/json' });
        expect(String(init.body)).not.toContain('secret-token');
        expect(outbox.count()).toBe(0);
    });

    it('sends at most 50 events per request', async () => {
        const gw = fakeGateway((events) => receipt(events.length));
        const { outbox, sender } = build(gw.fetchImpl);
        fill(outbox, 60);
        expect(await sender.flushOnce()).toBe('delivered');
        expect(gw.requests.map((r) => r.events.length)).toEqual([50, 10]);
    });

    it('keeps events when the receipt does not add up', async () => {
        const gw = fakeGateway(() => reply(200, JSON.stringify({ accepted: 1, duplicates: 0 })));
        const { outbox, sender } = build(gw.fetchImpl);
        fill(outbox, 2);
        expect(await sender.flushOnce()).toBe('failed');
        expect(outbox.count()).toBe(2);
        expect(logs.some((l) => l.level === 'error')).toBe(true);
    });

    it('keeps events when a captive portal answers 200 with an HTML page', async () => {
        const gw = fakeGateway(() => reply(200, '<html>Please log in</html>', 'text/html'));
        const { outbox, sender } = build(gw.fetchImpl);
        fill(outbox, 2);
        expect(await sender.flushOnce()).toBe('failed');
        expect(outbox.count()).toBe(2);
    });

    it('does not treat a captive portal 400 as the gateway rejecting events', async () => {
        const gw = fakeGateway(() => reply(400, '<html>blocked</html>', 'text/html'));
        const { outbox, sender } = build(gw.fetchImpl);
        fill(outbox, 2);
        expect(await sender.flushOnce()).toBe('failed');
        expect(outbox.count()).toBe(2);
        expect(outbox.getQuarantinedCount()).toBe(0);
        expect(fs.existsSync(quarantineFile)).toBe(false);
    });

    it('quarantines the exact event the gateway names and delivers the rest', async () => {
        let badId = '';
        const gw = fakeGateway((events, call) => {
            if (call === 1) {
                badId = events[1]!.id;
                return rejectAt(1);
            }
            return receipt(events.length);
        });
        const { outbox, sender } = build(gw.fetchImpl);
        fill(outbox, 3);
        expect(await sender.flushOnce()).toBe('delivered');
        expect(gw.requests.map((r) => r.events.length)).toEqual([3, 2]);
        expect(gw.requests[1]!.events.map((e) => e.id)).not.toContain(badId);
        expect(outbox.count()).toBe(0);
        expect(outbox.getQuarantinedCount()).toBe(1);
        expect(fs.readFileSync(quarantineFile, 'utf8')).toContain(badId);
        expect(logs.some((l) => /quarantine/.test(l.message))).toBe(true);
    });

    it('isolates a bad event by halving the batch when the gateway names no position', async () => {
        let badId = '';
        const gw = fakeGateway((events) =>
            events.some((e) => e.id === badId) ? reply(400, JSON.stringify({ error: 'Invalid JSON' })) : receipt(events.length)
        );
        const { outbox, sender } = build(gw.fetchImpl);
        const ids = fill(outbox, 5);
        badId = ids[2]!;
        expect(await sender.flushOnce()).toBe('delivered');
        expect(outbox.count()).toBe(0);
        expect(outbox.getQuarantinedCount()).toBe(1);
        expect(fs.readFileSync(quarantineFile, 'utf8')).toContain(badId);
    });

    it('keeps events when the gateway rejects the token, logging once per streak', async () => {
        const gw = fakeGateway(() => reply(401, JSON.stringify({ error: 'Unauthorized' })));
        const { outbox, sender } = build(gw.fetchImpl);
        fill(outbox, 2);
        expect(await sender.flushOnce()).toBe('failed');
        expect(await sender.flushOnce()).toBe('failed');
        expect(outbox.count()).toBe(2);
        expect(logs.filter((l) => l.level === 'error')).toHaveLength(1);
    });

    it('keeps events when the network fails', async () => {
        const fetchImpl = (async () => {
            throw new TypeError('fetch failed');
        }) as unknown as typeof fetch;
        const { outbox, sender } = build(fetchImpl);
        fill(outbox, 2);
        expect(await sender.flushOnce()).toBe('failed');
        expect(outbox.count()).toBe(2);
    });

    it('recovers after a failure and says so once', async () => {
        let up = false;
        const gw = fakeGateway((events) => (up ? receipt(events.length) : reply(503, '', 'text/plain')));
        const { outbox, sender } = build(gw.fetchImpl);
        fill(outbox, 2);
        expect(await sender.flushOnce()).toBe('failed');
        up = true;
        expect(await sender.flushOnce()).toBe('delivered');
        expect(logs.filter((l) => l.level === 'info' && /recovered/.test(l.message))).toHaveLength(1);
    });

    it('retries on a timer with exponential backoff and stops cleanly', async () => {
        vi.useFakeTimers();
        const gw = fakeGateway((events, call) => (call < 3 ? reply(503, '', 'text/plain') : receipt(events.length)));
        const { outbox, sender } = build(gw.fetchImpl, { intervalMs: 5000 });
        fill(outbox, 1);
        sender.start();
        await vi.advanceTimersByTimeAsync(4999);
        expect(gw.requests).toHaveLength(0);
        await vi.advanceTimersByTimeAsync(1);
        expect(gw.requests).toHaveLength(1);
        await vi.advanceTimersByTimeAsync(999);
        expect(gw.requests).toHaveLength(1);
        await vi.advanceTimersByTimeAsync(1);
        expect(gw.requests).toHaveLength(2);
        await vi.advanceTimersByTimeAsync(1999);
        expect(gw.requests).toHaveLength(2);
        await vi.advanceTimersByTimeAsync(1);
        expect(gw.requests).toHaveLength(3);
        expect(outbox.count()).toBe(0);
        await sender.stop();
    });

    it('refuses a gateway URL that is neither https nor loopback http, and a blank token', () => {
        const gw = fakeGateway(() => receipt(0));
        const outbox = new AgentOutbox({ filePath: path.join(dir, 'o.jsonl'), quarantinePath: quarantineFile });
        const make = (gatewayUrl: string, deviceToken = 't') =>
            () => new AgentEventSender({ outbox, gatewayUrl, deviceToken, fetchImpl: gw.fetchImpl });
        expect(make('http://gw.example.com/dns-query')).toThrow(/https/);
        expect(make('https://gw.example.com/dns-query')).not.toThrow();
        expect(make(GW, '  ')).toThrow(/token/);
    });

    it('stop() makes one final delivery attempt', async () => {
        const gw = fakeGateway((events) => receipt(events.length));
        const { outbox, sender } = build(gw.fetchImpl);
        fill(outbox, 2);
        sender.start();
        await sender.stop({ finalFlushMs: 1000 });
        expect(outbox.count()).toBe(0);
    });

    it('stop() gives up after its deadline and keeps the events', async () => {
        const hang = ((_url: unknown, init?: RequestInit) =>
            new Promise((_resolve, reject) => {
                init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
            })) as unknown as typeof fetch;
        const { outbox, sender } = build(hang);
        fill(outbox, 2);
        await sender.stop({ finalFlushMs: 50 });
        expect(outbox.count()).toBe(2);
        expect(logs.some((l) => /timed out/.test(l.message))).toBe(true);
    });
});
