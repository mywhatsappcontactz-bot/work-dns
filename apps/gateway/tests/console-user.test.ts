import { describe, it, expect, afterEach, vi } from 'vitest';
import dnsPacket from 'dns-packet';
import { PolicyEngine } from '@work-dns/policy-engine';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import type { AuthenticatedDeviceContext, DeviceAuthenticator } from '../src/auth.js';
import { toPayload } from '../src/audit-sink.js';
import { createRollupAuditSink } from '../src/audit-rollup.js';
import { DnsHandler } from '../src/dns-handler.js';
import { GatewayEventQueue } from '../src/event-queue.js';
import type { BlockedAttemptRecord } from '../src/event-queue.js';
import { DohServer } from '../src/server.js';
import type { UpstreamResolver } from '../src/upstream.js';

const A = 'comp-a' as CompanyId;
const DEV = 'dev-a' as DeviceId;
const ctxA = { deviceId: DEV, companyId: A, deviceGroupId: null, status: 'active' } as AuthenticatedDeviceContext;

describe('event queue merge key', () => {
    it('keeps attempts by different users apart and merges attempts by the same user', async () => {
        vi.spyOn(console, 'warn').mockImplementation(() => {});
        const got: BlockedAttemptRecord[] = [];
        const queue = new GatewayEventQueue({
            sink: async (records) => {
                got.push(...records);
            },
        });
        const attempt = (user: string) => ({
            companyId: A,
            deviceId: DEV,
            domain: 'a.example.com',
            loggedOsUser: user,
            policyVersion: 1,
            reasonCode: 'DEFAULT_DENY_UNLISTED_DOMAIN',
        });
        queue.enqueueBlockedAttempt(attempt('berlin'));
        queue.enqueueBlockedAttempt(attempt('alice'));
        queue.enqueueBlockedAttempt(attempt('berlin'));
        await queue.flushNow();
        expect(got).toHaveLength(2);
        expect(got.find((r) => r.loggedOsUser === 'berlin')!.count).toBe(2);
        expect(got.find((r) => r.loggedOsUser === 'alice')!.count).toBe(1);
    });
});

describe('server reads the console user header', () => {
    let server: DohServer | undefined;

    afterEach(async () => {
        await server?.stop();
        server = undefined;
    });

    async function boot() {
        const calls: unknown[][] = [];
        const fakeAuth = {
            authenticateHeader: (header?: string) =>
                header === 'Bearer a'
                    ? { authenticated: true, context: ctxA }
                    : { authenticated: false, errorStatus: 401, errorMessage: 'bad token' },
        } as unknown as DeviceAuthenticator;
        const fakeHandler = {
            handleDnsMessage: async (...args: unknown[]) => {
                calls.push(args);
                return { statusCode: 400, errorMessage: 'stop here' };
            },
        } as unknown as DnsHandler;
        server = new DohServer(fakeAuth, fakeHandler);
        await server.start({ port: 0, host: '127.0.0.1' });
        const port = server.getPort()!;
        const send = (extra: HeadersInit) =>
            fetch(`http://127.0.0.1:${port}/dns-query`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/dns-message', Authorization: 'Bearer a', ...(extra as Record<string, string>) },
                body: Buffer.alloc(12),
            });
        return { calls, send, port };
    }

    it('passes a plain username to the handler', async () => {
        const { calls, send } = await boot();
        await send({ 'X-Work-Dns-User': 'berlin' });
        expect(calls).toHaveLength(1);
        expect(calls[0]![3]).toBe('berlin');
    });

    it('passes nothing when the header is absent', async () => {
        const { calls, send } = await boot();
        await send({});
        expect(calls[0]![3]).toBeUndefined();
    });

    it('ignores values that are not plain usernames', async () => {
        const { calls, send } = await boot();
        for (const bad of ['bad name', '-flag', 'semi;colon', 'x'.repeat(65), 'a,b']) {
            await send({ 'X-Work-Dns-User': bad });
        }
        expect(calls).toHaveLength(5);
        for (const call of calls) expect(call[3]).toBeUndefined();
    });

    it('ignores a repeated header', async () => {
        const { calls, port } = await boot();
        await fetch(`http://127.0.0.1:${port}/dns-query`, {
            method: 'POST',
            headers: [
                ['Content-Type', 'application/dns-message'],
                ['Authorization', 'Bearer a'],
                ['X-Work-Dns-User', 'berlin'],
                ['X-Work-Dns-User', 'alice'],
            ],
            body: Buffer.alloc(12),
        });
        expect(calls).toHaveLength(1);
        expect(calls[0]![3]).toBeUndefined();
    });
});

describe('handler records the claimed user on a blocked attempt', () => {
    const POLICY = {
        id: 'pol-demo',
        companyId: 'comp-a',
        version: 1,
        mode: 'strict',
        defaultActionDuringEnforcedHours: 'BLOCK',
        defaultActionOutsideEnforcedHours: 'BLOCK',
        timezone: 'Africa/Lagos',
        rules: [{ id: 'r1', type: 'domain_allow', pattern: '*.google.com', effect: 'ALLOW', priority: 1 }],
        updatedAt: '2026-10-22T20:02:42.788Z',
    };
    const query = Buffer.from(
        dnsPacket.encode({ type: 'query', id: 1, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'A', name: 'facebook.com' }] })
    );

    function build() {
        vi.spyOn(console, 'warn').mockImplementation(() => {});
        const queue = new GatewayEventQueue();
        const spy = vi.spyOn(queue, 'enqueueBlockedAttempt');
        const upstream = {
            resolve: async () => {
                throw new Error('a blocked domain must not reach the upstream');
            },
        } as unknown as UpstreamResolver;
        const handler = new DnsHandler({ policyEngine: new PolicyEngine(), upstreamResolver: upstream, eventQueue: queue });
        handler.updateCompiledPolicy(POLICY as never);
        return { handler, spy };
    }

    it('uses the user the server passed', async () => {
        const { handler, spy } = build();
        await handler.handleDnsMessage(query, ctxA, '127.0.0.1', 'berlin');
        expect(spy).toHaveBeenCalledWith(expect.objectContaining({ domain: 'facebook.com', loggedOsUser: 'berlin' }));
    });

    it('falls back to unknown when no user was passed', async () => {
        const { handler, spy } = build();
        await handler.handleDnsMessage(query, ctxA, '127.0.0.1');
        expect(spy).toHaveBeenCalledWith(expect.objectContaining({ loggedOsUser: 'unknown' }));
    });
});

describe('claim marker on audit payloads', () => {
    const record = (user: string): BlockedAttemptRecord => ({
        id: 'r1',
        companyId: A,
        deviceId: DEV,
        domain: 'a.example.com',
        loggedOsUser: user,
        policyVersion: 1,
        reasonCode: 'DEFAULT_DENY_UNLISTED_DOMAIN',
        occurredAt: '2026-11-02T10:00:00.000Z',
        count: 1,
    });

    it('marks a named user as device-reported and leaves unknown unmarked', () => {
        expect(toPayload(record('berlin')).loggedOsUserSource).toBe('device_reported');
        expect(toPayload(record('unknown'))).not.toHaveProperty('loggedOsUserSource');
    });

    it('carries the marker onto a rolled-up entry', async () => {
        const appended: Array<{ id: string; payload: Record<string, unknown> }> = [];
        let nowMs = Date.UTC(2026, 10, 2, 10, 0, 0);
        const rollup = createRollupAuditSink(
            {
                hasEvent: () => false,
                append: ((input: { id: string; payload: Record<string, unknown> }) => {
                    appended.push(input);
                }) as never,
            },
            { now: () => nowMs, log: () => {} }
        );
        await rollup.sink([{ ...record('berlin'), id: 'r1' }]);
        nowMs += 60_000;
        await rollup.sink([{ ...record('berlin'), id: 'r2' }]);
        rollup.flushAll();
        const entry = appended.find((e) => e.id === 'rollup:r1');
        expect(entry).toBeDefined();
        expect(entry!.payload.loggedOsUserSource).toBe('device_reported');
        expect(entry!.payload.loggedOsUser).toBe('berlin');
    });
});
