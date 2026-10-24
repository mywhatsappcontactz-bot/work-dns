import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SqliteEventStore } from '@work-dns/events';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import { createAuditSink } from '../src/audit-sink.js';
import { GatewayEventQueue } from '../src/event-queue.js';
import type { BlockedAttemptRecord } from '../src/event-queue.js';

const A = 'comp-a' as CompanyId;
const B = 'comp-b' as CompanyId;
const DEV = 'dev-1' as DeviceId;

function record(id: string, overrides: Partial<BlockedAttemptRecord> = {}): BlockedAttemptRecord {
    return {
        id,
        companyId: A,
        deviceId: DEV,
        domain: `${id}.example.com`,
        loggedOsUser: 'unknown',
        policyVersion: 1,
        reasonCode: 'DEFAULT_DENY',
        occurredAt: '2026-10-24T09:00:00.000Z',
        count: 1,
        ...overrides,
    };
}

describe('audit sink', () => {
    let dir: string;
    let store: SqliteEventStore;

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-sink-'));
        store = new SqliteEventStore(path.join(dir, 'audit.db'));
    });

    afterEach(() => {
        store.close();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    it('stores one dns_blocked event per record with the mapped payload', async () => {
        await createAuditSink(store)([record('r1', { count: 3, clientIp: '10.0.0.5' }), record('r2')]);
        const events = store.readAll(A);
        expect(events).toHaveLength(2);
        expect(events[0]).toMatchObject({ id: 'r1', type: 'dns_blocked', deviceId: DEV, sequenceNumber: 1 });
        expect(events[0]!.payload).toEqual({
            domain: 'r1.example.com',
            loggedOsUser: 'unknown',
            policyVersion: 1,
            reasonCode: 'DEFAULT_DENY',
            firstSeenAt: '2026-10-24T09:00:00.000Z',
            count: 3,
            clientIp: '10.0.0.5',
        });
        expect(events[1]!.payload).not.toHaveProperty('clientIp');
        expect(store.verify(A, { expectedLength: 2 }).valid).toBe(true);
    });

    it('running the same batch twice stores each record once', async () => {
        const sink = createAuditSink(store);
        const batch = [record('r1'), record('r2')];
        await sink(batch);
        await sink(batch);
        expect(store.readAll(A)).toHaveLength(2);
        expect(store.verify(A, { expectedLength: 2 }).valid).toBe(true);
    });

    it('a failure part-way is retried without duplicates', async () => {
        let failOn: string | null = 'r2';
        const flaky = {
            hasEvent: (id: string) => store.hasEvent(id),
            append: ((input: { id: string }) => {
                if (input.id === failOn) throw new Error('disk full');
                return store.append(input as never);
            }) as unknown as typeof store.append,
        };
        const sink = createAuditSink(flaky);
        const batch = [record('r1'), record('r2'), record('r3')];
        await expect(sink(batch)).rejects.toThrow(/disk full/);
        expect(store.readAll(A)).toHaveLength(1);
        failOn = null;
        await sink(batch);
        const events = store.readAll(A);
        expect(events.map((e) => e.id)).toEqual(['r1', 'r2', 'r3']);
        expect(store.verify(A, { expectedLength: 3 }).valid).toBe(true);
    });

    it('keeps a separate chain per company', async () => {
        await createAuditSink(store)([record('a1'), record('b1', { companyId: B }), record('a2')]);
        expect(store.readAll(A)).toHaveLength(2);
        expect(store.readAll(B)).toHaveLength(1);
        expect(store.verify(A).valid).toBe(true);
        expect(store.verify(B).valid).toBe(true);
    });

    it('works end to end through the real queue, merging repeated attempts', async () => {
        const queue = new GatewayEventQueue({ sink: createAuditSink(store) });
        const attempt = { companyId: A, deviceId: DEV, domain: 'facebook.com', loggedOsUser: 'unknown', policyVersion: 1, reasonCode: 'DEFAULT_DENY' };
        queue.enqueueBlockedAttempt(attempt);
        queue.enqueueBlockedAttempt(attempt);
        await queue.flushNow();
        const events = store.readAll(A);
        expect(events).toHaveLength(1);
        expect(events[0]!.payload).toMatchObject({ domain: 'facebook.com', count: 2 });
        expect(store.verify(A, { expectedLength: 1 }).valid).toBe(true);
    });
});
