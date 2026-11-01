import { describe, it, expect, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SqliteEventStore } from '@work-dns/events';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import type { AuthenticatedDeviceContext, DeviceAuthenticator } from '../src/auth.js';
import type { DnsHandler } from '../src/dns-handler.js';
import { HeartbeatWatcher } from '../src/heartbeat-watcher.js';
import { DohServer } from '../src/server.js';

const A = 'comp-a' as CompanyId;
const ctxA = { deviceId: 'dev-a' as DeviceId, companyId: A, deviceGroupId: null, status: 'active' } as AuthenticatedDeviceContext;
const T0 = Date.UTC(2026, 9, 29, 9, 0, 0);
const MIN = 60_000;
const iso = (ms: number) => new Date(ms).toISOString();

const fakeAuth = {
    authenticateHeader: (header?: string) =>
        header === 'Bearer a'
            ? { authenticated: true, context: ctxA }
            : { authenticated: false, errorStatus: 401, errorMessage: 'bad token' },
} as unknown as DeviceAuthenticator;
const fakeHandler = {
    handleDnsMessage: async () => ({ statusCode: 400, errorMessage: 'not a real handler' }),
} as unknown as DnsHandler;

describe('DohServer authenticated-request hook', () => {
    let server: DohServer | undefined;
    let store: SqliteEventStore | undefined;
    let dir: string | undefined;
    let port = 0;

    afterEach(async () => {
        await server?.stop();
        server = undefined;
        store?.close();
        store = undefined;
        if (dir !== undefined) fs.rmSync(dir, { recursive: true, force: true });
        dir = undefined;
        vi.restoreAllMocks();
    });

    async function boot(onAuthenticated?: (context: AuthenticatedDeviceContext) => void): Promise<void> {
        server = new DohServer(fakeAuth, fakeHandler, onAuthenticated === undefined ? {} : { onAuthenticated });
        await server.start({ port: 0, host: '127.0.0.1' });
        port = server.getPort()!;
    }

    const dnsRequest = (token: string) =>
        fetch(`http://127.0.0.1:${port}/dns-query`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/dns-message', Authorization: `Bearer ${token}` },
            body: Buffer.alloc(12),
        });
    const eventsRequest = (token: string) =>
        fetch(`http://127.0.0.1:${port}/api/v1/agent-events`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: '{}',
        });

    it('calls the hook for an authenticated DNS request', async () => {
        const calls: AuthenticatedDeviceContext[] = [];
        await boot((context) => {
            calls.push(context);
        });
        const res = await dnsRequest('a');
        expect(res.status).toBe(400);
        expect(calls).toHaveLength(1);
        expect(calls[0]).toBe(ctxA);
    });

    it('calls the hook for an authenticated device-events request, even when the audit log is off', async () => {
        const calls: AuthenticatedDeviceContext[] = [];
        await boot((context) => {
            calls.push(context);
        });
        const res = await eventsRequest('a');
        expect(res.status).toBe(503);
        expect(calls).toHaveLength(1);
    });

    it('does not call the hook for a bad token or for /health', async () => {
        const calls: AuthenticatedDeviceContext[] = [];
        await boot((context) => {
            calls.push(context);
        });
        expect((await dnsRequest('nope')).status).toBe(401);
        expect((await eventsRequest('nope')).status).toBe(401);
        expect((await fetch(`http://127.0.0.1:${port}/health`)).status).toBe(200);
        expect(calls).toHaveLength(0);
    });

    it('keeps serving and logs an error when the hook throws', async () => {
        const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
        await boot(() => {
            throw new Error('hook exploded');
        });
        const res = await dnsRequest('a');
        expect(res.status).toBe(400);
        expect(spy.mock.calls.some((call) => String(call[0]).includes('hook failed'))).toBe(true);
    });

    it('a real request resets the real watcher clock', async () => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-hbhook-'));
        store = new SqliteEventStore(path.join(dir, 'audit.db'));
        let nowMs = T0;
        const watcher = new HeartbeatWatcher(store, { thresholdMs: 5 * MIN, now: () => nowMs, log: () => {} });
        watcher.seed([ctxA]);
        await boot((context) => watcher.touch(context));

        nowMs = T0 + 4 * MIN;
        expect((await dnsRequest('a')).status).toBe(400);
        nowMs = T0 + 6 * MIN;
        watcher.sweep();
        expect(store.readAll(A)).toHaveLength(0);

        nowMs = T0 + 9 * MIN;
        watcher.sweep();
        const events = store.readAll(A);
        expect(events).toHaveLength(1);
        expect(events[0]).toMatchObject({ type: 'heartbeat_missed', deviceId: 'dev-a' });
        expect(events[0]!.payload.lastSeenAt).toBe(iso(T0 + 4 * MIN));
    });
});
