import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { SqliteEventStore } from '@work-dns/events';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import type { AuthenticatedDeviceContext, DeviceAuthenticator } from '../src/auth.js';
import type { DnsHandler } from '../src/dns-handler.js';
import { DohServer } from '../src/server.js';
import {
    ALLOWED_AGENT_EVENT_TYPES,
    MAX_EVENTS_PER_BATCH,
    createAgentEventIngest,
    validateAgentEventBatch,
} from '../src/agent-events.js';

const NOW = new Date('2026-10-24T12:00:00.000Z');
const T0 = '2026-10-24T11:59:00.000Z';
const COMP_A = 'comp-a' as CompanyId;
const COMP_B = 'comp-b' as CompanyId;
const ctxA = { deviceId: 'dev-a' as DeviceId, companyId: COMP_A } as unknown as AuthenticatedDeviceContext;
const ctxB = { deviceId: 'dev-b' as DeviceId, companyId: COMP_B } as unknown as AuthenticatedDeviceContext;

const SAMPLES: Record<string, Record<string, unknown>> = {
    agent_started: { agentVersion: '0.1.0', os: 'linux', loggedOsUser: 'berlin', policyVersion: 1 },
    agent_stopped: { reason: 'signal', dnsRestored: true },
    enforcement_applied: { networkDevices: ['wlp58s0'], method: 'nmcli-runtime' },
    enforcement_reset: { detectedAt: T0, reappliedAt: '2026-10-24T11:59:01.600Z', windowSeconds: 1.6 },
    enforcement_restored: { networkDevices: ['wlp58s0'], trigger: 'crash_recovery', success: true },
    fail_open_entered: { reason: 'gateway_unreachable', maxMinutes: 15 },
    fail_open_exited: { durationSeconds: 42, cause: 'gateway_recovered' },
    offline_query: { domain: 'example.org', action: 'FAIL_OPEN_ALLOWED', reason: 'gateway unreachable', occurrences: 2 },
};

const ev = (id: string, type = 'enforcement_reset', payload: Record<string, unknown> = SAMPLES[type]!) => ({
    id,
    type,
    deviceReportedAt: T0,
    payload,
});

describe('validateAgentEventBatch', () => {
    it('accepts one event of every allowed type', () => {
        expect(ALLOWED_AGENT_EVENT_TYPES).toHaveLength(8);
        const events = ALLOWED_AGENT_EVENT_TYPES.map((type, i) => ev(`id-${i}`, type));
        const result = validateAgentEventBatch({ events }, NOW);
        expect(result.ok).toBe(true);
        expect(result.ok && result.events).toHaveLength(8);
    });

    it('rejects event types a device must not submit', () => {
        const forbidden = ['dns_blocked', 'policy_changed', 'device_enrolled', 'admin_login', 'device_revoked', 'retention_expired', 'auth_rejected', 'heartbeat_missed', 'access_approved', '__proto__'];
        for (const type of forbidden) {
            const result = validateAgentEventBatch({ events: [ev('x1', type, {})] }, NOW);
            expect(result.ok, type).toBe(false);
            expect(!result.ok && result.index).toBe(0);
        }
    });

    it('rejects unknown payload fields and unknown event keys', () => {
        const extraField = validateAgentEventBatch({ events: [ev('x1', 'agent_stopped', { reason: 'signal', dnsRestored: true, sneaky: 1 })] }, NOW);
        expect(extraField.ok).toBe(false);
        const extraKey = validateAgentEventBatch({ events: [{ ...ev('x1'), companyId: 'comp-b' }] }, NOW);
        expect(extraKey.ok).toBe(false);
    });

    it('rejects a missing required field', () => {
        const result = validateAgentEventBatch({ events: [ev('x1', 'agent_stopped', { reason: 'signal' })] }, NOW);
        expect(result.ok).toBe(false);
        expect(!result.ok && result.error).toMatch(/dnsRestored is required/);
    });

    it('rejects a bad enum value, a negative number and a control character', () => {
        expect(validateAgentEventBatch({ events: [ev('x1', 'agent_stopped', { reason: 'bored', dnsRestored: true })] }, NOW).ok).toBe(false);
        expect(validateAgentEventBatch({ events: [ev('x1', 'fail_open_entered', { reason: 'gateway_unreachable', maxMinutes: -1 })] }, NOW).ok).toBe(false);
        expect(validateAgentEventBatch({ events: [ev('x1', 'offline_query', { ...SAMPLES.offline_query!, domain: 'a\u0000b.com' })] }, NOW).ok).toBe(false);
    });

    it('rejects device times more than 5 minutes ahead or more than 30 days old', () => {
        const future = { ...ev('x1'), deviceReportedAt: '2026-10-24T12:10:00.000Z' };
        const ancient = { ...ev('x2'), deviceReportedAt: '2026-09-01T00:00:00.000Z' };
        const garbage = { ...ev('x3'), deviceReportedAt: 'yesterday' };
        expect(validateAgentEventBatch({ events: [future] }, NOW).ok).toBe(false);
        expect(validateAgentEventBatch({ events: [ancient] }, NOW).ok).toBe(false);
        expect(validateAgentEventBatch({ events: [garbage] }, NOW).ok).toBe(false);
    });

    it('rejects a duplicate id inside one batch', () => {
        const result = validateAgentEventBatch({ events: [ev('same'), ev('same')] }, NOW);
        expect(result.ok).toBe(false);
        expect(!result.ok && result.index).toBe(1);
    });

    it('rejects an empty batch, an oversized batch and a non-object body', () => {
        expect(validateAgentEventBatch({ events: [] }, NOW).ok).toBe(false);
        const many = Array.from({ length: MAX_EVENTS_PER_BATCH + 1 }, (_, i) => ev(`id-${i}`));
        expect(validateAgentEventBatch({ events: many }, NOW).ok).toBe(false);
        expect(validateAgentEventBatch([], NOW).ok).toBe(false);
        expect(validateAgentEventBatch(null, NOW).ok).toBe(false);
    });
});

describe('createAgentEventIngest', () => {
    let dir: string;
    let store: SqliteEventStore;
    let ingest: ReturnType<typeof createAgentEventIngest>;

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-ingest-'));
        store = new SqliteEventStore(path.join(dir, 'audit.db'), { now: () => new Date(NOW) });
        ingest = createAgentEventIngest(store, { now: () => new Date(NOW) });
    });

    afterEach(() => {
        store.close();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    it('stores events under the authenticated identity, marked as device-reported, with server time', () => {
        const outcome = ingest(ctxA, { events: [ev('x1'), ev('x2', 'agent_started')] });
        expect(outcome).toEqual({ ok: true, accepted: 2, duplicates: 0 });
        const events = store.readAll(COMP_A);
        expect(events).toHaveLength(2);
        expect(events[0]).toMatchObject({ id: 'dev-a:x1', type: 'enforcement_reset', deviceId: 'dev-a', occurredAt: '2026-10-24T12:00:00.000Z' });
        expect(events[0]!.payload).toMatchObject({ source: 'device_reported', deviceReportedAt: T0, windowSeconds: 1.6 });
        expect(store.verify(COMP_A, { expectedLength: 2 }).valid).toBe(true);
    });

    it('treats a retried batch as duplicates, not new events', () => {
        const batch = { events: [ev('x1'), ev('x2')] };
        expect(ingest(ctxA, batch)).toEqual({ ok: true, accepted: 2, duplicates: 0 });
        expect(ingest(ctxA, batch)).toEqual({ ok: true, accepted: 0, duplicates: 2 });
        expect(store.readAll(COMP_A)).toHaveLength(2);
    });

    it('lets two devices use the same client id without colliding', () => {
        expect(ingest(ctxA, { events: [ev('same-id')] })).toMatchObject({ ok: true, accepted: 1 });
        expect(ingest(ctxB, { events: [ev('same-id')] })).toMatchObject({ ok: true, accepted: 1 });
        expect(store.readAll(COMP_A)[0]!.id).toBe('dev-a:same-id');
        expect(store.readAll(COMP_B)[0]!.id).toBe('dev-b:same-id');
    });

    it('stores nothing when any event in the batch is invalid', () => {
        const outcome = ingest(ctxA, { events: [ev('ok1'), ev('bad', 'dns_blocked', {})] });
        expect(outcome.ok).toBe(false);
        expect(store.readAll(COMP_A)).toHaveLength(0);
    });
});

function rawHead(port: number, head: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1');
        let data = '';
        socket.on('connect', () => socket.write(head));
        socket.on('data', (chunk) => {
            data += chunk.toString('latin1');
            socket.destroy();
        });
        socket.on('close', () => resolve(data));
        socket.on('error', reject);
    });
}

describe('POST /api/v1/agent-events', () => {
    let dir: string;
    let store: SqliteEventStore;
    let server: DohServer;
    let port: number;

    const CONTEXTS: Record<string, AuthenticatedDeviceContext> = { 'Bearer a': ctxA, 'Bearer b': ctxB };
    const fakeAuth = {
        authenticateHeader: (header?: string) => {
            const context = header === undefined ? undefined : CONTEXTS[header];
            return context ? { authenticated: true, context } : { authenticated: false, errorStatus: 401, errorMessage: 'bad token' };
        },
    } as unknown as DeviceAuthenticator;

    async function boot(auditEnabled: boolean): Promise<void> {
        const ingest = auditEnabled ? createAgentEventIngest(store, { now: () => new Date(NOW) }) : undefined;
        server = new DohServer(fakeAuth, {} as unknown as DnsHandler, ingest === undefined ? {} : { agentEvents: ingest });
        await server.start({ port: 0, host: '127.0.0.1' });
        port = server.getPort()!;
    }

    const url = () => `http://127.0.0.1:${port}/api/v1/agent-events`;
    const post = (body: unknown, headers: Record<string, string> = {}) =>
        fetch(url(), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: 'Bearer a', ...headers },
            body: typeof body === 'string' ? body : JSON.stringify(body),
        });

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-http-'));
        store = new SqliteEventStore(path.join(dir, 'audit.db'), { now: () => new Date(NOW) });
    });

    afterEach(async () => {
        await server.stop();
        store.close();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    it('stores a valid batch under the token identity and answers 200', async () => {
        await boot(true);
        const res = await post({ events: [ev('x1'), ev('x2', 'fail_open_entered')] });
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ accepted: 2, duplicates: 0 });
        expect(store.readAll(COMP_A).map((e) => e.id)).toEqual(['dev-a:x1', 'dev-a:x2']);
        expect(store.readAll(COMP_B)).toHaveLength(0);
    });

    it('refuses a request without a valid token and stores nothing', async () => {
        await boot(true);
        const res = await post({ events: [ev('x1')] }, { Authorization: 'Bearer nope' });
        expect(res.status).toBe(401);
        expect(store.readAll(COMP_A)).toHaveLength(0);
    });

    it('refuses GET with 405 after authenticating', async () => {
        await boot(true);
        const res = await fetch(url(), { method: 'GET', headers: { Authorization: 'Bearer a' } });
        expect(res.status).toBe(405);
    });

    it('refuses a non-JSON content type with 415', async () => {
        await boot(true);
        const res = await post({ events: [ev('x1')] }, { 'Content-Type': 'text/plain' });
        expect(res.status).toBe(415);
    });

    it('answers 400 for invalid JSON', async () => {
        await boot(true);
        const res = await post('{not json');
        expect(res.status).toBe(400);
    });

    it('answers 400 and stores nothing for a type a device may not submit', async () => {
        await boot(true);
        const res = await post({ events: [ev('x1'), ev('x2', 'dns_blocked', {})] });
        expect(res.status).toBe(400);
        const body = (await res.json()) as { detail: string; index: number };
        expect(body.index).toBe(1);
        expect(store.readAll(COMP_A)).toHaveLength(0);
    });

    it('answers 413 when the declared body is too large, before reading it', async () => {
        await boot(true);
        const head =
            'POST /api/v1/agent-events HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer a\r\nContent-Type: application/json\r\nContent-Length: 70000\r\n\r\n';
        const reply = await rawHead(port, head);
        expect(reply.startsWith('HTTP/1.1 413')).toBe(true);
    });

    it('answers 503 when the audit log is not enabled', async () => {
        await boot(false);
        const res = await post({ events: [ev('x1')] });
        expect(res.status).toBe(503);
    });
});
