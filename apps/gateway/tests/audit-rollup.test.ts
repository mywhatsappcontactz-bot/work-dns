import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SqliteEventStore } from '@work-dns/events';
import type { AuditEventStore } from '@work-dns/events';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import { createRollupAuditSink } from '../src/audit-rollup.js';
import type { RollupOptions } from '../src/audit-rollup.js';
import type { BlockedAttemptRecord } from '../src/event-queue.js';

const A = 'comp-a' as CompanyId;
const D1 = 'dev-1' as DeviceId;
const D2 = 'dev-2' as DeviceId;
const T0 = Date.UTC(2026, 9, 28, 10, 0, 0);
const iso = (ms: number) => new Date(ms).toISOString();
const MIN = 60_000;

describe('rollup audit sink', () => {
    let dir: string;
    let store: SqliteEventStore;
    let nowMs: number;
    let seq: number;
    let logs: string[];

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-rollup-'));
        store = new SqliteEventStore(path.join(dir, 'audit.db'));
        nowMs = T0;
        seq = 0;
        logs = [];
    });

    afterEach(() => {
        vi.useRealTimers();
        store.close();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    const rec = (domain: string, overrides: Partial<BlockedAttemptRecord> = {}): BlockedAttemptRecord => {
        seq += 1;
        return {
            id: `r${seq}`,
            companyId: A,
            deviceId: D1,
            domain,
            loggedOsUser: 'unknown',
            policyVersion: 1,
            reasonCode: 'DEFAULT_DENY_UNLISTED_DOMAIN',
            occurredAt: iso(nowMs),
            count: 1,
            ...overrides,
        };
    };

    const make = (extra: Partial<RollupOptions> = {}, target: Pick<AuditEventStore, 'append' | 'hasEvent'> = store) =>
        createRollupAuditSink(target, {
            now: () => nowMs,
            log: (_level, message) => {
                logs.push(message);
            },
            ...extra,
        });

    function failsOnce(match: (id: string) => boolean): Pick<AuditEventStore, 'append' | 'hasEvent'> {
        let armed = true;
        return {
            hasEvent: (id: string) => store.hasEvent(id),
            append: ((input: { id: string }) => {
                if (armed && match(input.id)) {
                    armed = false;
                    throw new Error('disk full');
                }
                return store.append(input as never);
            }) as unknown as typeof store.append,
        };
    }

    it('writes the first sighting at once and keeps its merged-attempt fields', async () => {
        const rollup = make();
        await rollup.sink([rec('a.example.com', { count: 2, lastSeenAt: iso(T0 + 3000) })]);
        const events = store.readAll(A);
        expect(events).toHaveLength(1);
        expect(events[0]!.id).toBe('r1');
        expect(events[0]!.payload).toMatchObject({ domain: 'a.example.com', count: 2, lastSeenAt: iso(T0 + 3000) });
        expect(events[0]!.payload).not.toHaveProperty('rollup');
        expect(rollup.openWindows()).toBe(1);
    });

    it('rolls repeats inside the window into one entry with the right counts and bounds', async () => {
        const rollup = make();
        await rollup.sink([rec('a.example.com')]);
        nowMs = T0 + MIN;
        await rollup.sink([rec('a.example.com', { count: 2, lastSeenAt: iso(nowMs + 5000) })]);
        nowMs = T0 + 2 * MIN;
        await rollup.sink([rec('a.example.com')]);
        expect(store.readAll(A)).toHaveLength(1);
        nowMs = T0 + 5 * MIN;
        rollup.flushDue();
        const events = store.readAll(A);
        expect(events).toHaveLength(2);
        expect(events[1]!.id).toBe('rollup:r1');
        expect(events[1]!.payload).toMatchObject({
            rollup: true,
            count: 3,
            firstSeenAt: iso(T0 + MIN),
            lastSeenAt: iso(T0 + 2 * MIN),
            windowStart: iso(T0),
            windowEnd: iso(T0 + 5 * MIN),
        });
        const total = events.reduce((sum, e) => sum + Number(e.payload.count), 0);
        expect(total).toBe(4);
        expect(rollup.openWindows()).toBe(0);
        expect(store.verify(A, { expectedLength: 2 }).valid).toBe(true);
    });

    it('writes nothing extra when nobody repeats the attempt', async () => {
        const rollup = make();
        await rollup.sink([rec('a.example.com')]);
        nowMs = T0 + 6 * MIN;
        rollup.flushDue();
        expect(store.readAll(A)).toHaveLength(1);
        expect(rollup.openWindows()).toBe(0);
    });

    it('closes an expired window itself when a later attempt arrives before any sweep', async () => {
        const rollup = make();
        await rollup.sink([rec('a.example.com')]);
        nowMs = T0 + MIN;
        await rollup.sink([rec('a.example.com')]);
        nowMs = T0 + 6 * MIN;
        await rollup.sink([rec('a.example.com')]);
        const events = store.readAll(A);
        expect(events.map((e) => e.id)).toEqual(['r1', 'rollup:r1', 'r3']);
        expect(events[1]!.payload).toMatchObject({ rollup: true, count: 1, windowEnd: iso(T0 + 5 * MIN) });
        expect(events[2]!.payload).not.toHaveProperty('rollup');
        expect(rollup.openWindows()).toBe(1);
    });

    it('keeps separate windows per device, domain, policy version and user', async () => {
        const rollup = make();
        await rollup.sink([
            rec('a.example.com'),
            rec('a.example.com', { deviceId: D2 }),
            rec('a.example.com', { policyVersion: 2 }),
            rec('a.example.com', { loggedOsUser: 'alice' }),
            rec('b.example.com'),
        ]);
        expect(store.readAll(A)).toHaveLength(5);
        expect(rollup.openWindows()).toBe(5);
        await rollup.sink([rec('a.example.com', { deviceId: D2 })]);
        expect(store.readAll(A)).toHaveLength(5);
    });

    it('does not count a retried batch twice', async () => {
        const rollup = make();
        const batch = [rec('a.example.com'), rec('a.example.com')];
        await rollup.sink(batch);
        await rollup.sink(batch);
        expect(store.readAll(A)).toHaveLength(1);
        nowMs = T0 + 5 * MIN;
        rollup.flushDue();
        const events = store.readAll(A);
        expect(events).toHaveLength(2);
        expect(events[1]!.payload.count).toBe(1);
    });

    it('recovers from a failure part-way through a batch without duplicates', async () => {
        const rollup = make({}, failsOnce((id) => id === 'r2'));
        const batch = [rec('a.example.com'), rec('b.example.com'), rec('c.example.com')];
        await expect(rollup.sink(batch)).rejects.toThrow(/disk full/);
        expect(store.readAll(A).map((e) => e.id)).toEqual(['r1']);
        await rollup.sink(batch);
        expect(store.readAll(A).map((e) => e.id)).toEqual(['r1', 'r2', 'r3']);
        expect(store.verify(A, { expectedLength: 3 }).valid).toBe(true);
    });

    it('stop() writes out open windows, ending them at the current time', async () => {
        const rollup = make();
        await rollup.sink([rec('a.example.com')]);
        nowMs = T0 + MIN;
        await rollup.sink([rec('a.example.com')]);
        nowMs = T0 + 2 * MIN;
        rollup.stop();
        const events = store.readAll(A);
        expect(events).toHaveLength(2);
        expect(events[1]!.payload).toMatchObject({ rollup: true, count: 1, windowStart: iso(T0), windowEnd: iso(T0 + 2 * MIN) });
        expect(rollup.openWindows()).toBe(0);
    });

    it('keeps the counts when a rollup write fails, reports it, and writes it on the next sweep', async () => {
        const rollup = make({}, failsOnce((id) => id.startsWith('rollup:')));
        await rollup.sink([rec('a.example.com')]);
        nowMs = T0 + MIN;
        await rollup.sink([rec('a.example.com', { count: 4 })]);
        nowMs = T0 + 5 * MIN;
        expect(() => rollup.flushDue()).not.toThrow();
        expect(logs).toContain('could not write a rollup entry; will retry');
        expect(store.readAll(A)).toHaveLength(1);
        expect(rollup.openWindows()).toBe(1);
        rollup.flushDue();
        const events = store.readAll(A);
        expect(events).toHaveLength(2);
        expect(events[1]!.payload.count).toBe(4);
    });

    it('writes new attempts in full once the open-window cap is reached, losing nothing', async () => {
        const rollup = make({ maxKeys: 1 });
        await rollup.sink([rec('a.example.com')]);
        await rollup.sink([rec('b.example.com')]);
        await rollup.sink([rec('b.example.com')]);
        expect(store.readAll(A)).toHaveLength(3);
        expect(rollup.openWindows()).toBe(1);
    });

    it('sweeps closed windows on its own timer after start()', async () => {
        vi.useFakeTimers();
        const rollup = make({ sweepIntervalMs: 1000 });
        rollup.start();
        await rollup.sink([rec('a.example.com')]);
        nowMs = T0 + MIN;
        await rollup.sink([rec('a.example.com')]);
        nowMs = T0 + 5 * MIN;
        await vi.advanceTimersByTimeAsync(1000);
        expect(store.readAll(A)).toHaveLength(2);
        rollup.stop();
    });

    it('rejects invalid options', () => {
        expect(() => createRollupAuditSink(store, { windowMs: 0 })).toThrow(RangeError);
        expect(() => createRollupAuditSink(store, { maxKeys: 0 })).toThrow(RangeError);
        expect(() => createRollupAuditSink(store, { sweepIntervalMs: -1 })).toThrow(RangeError);
    });
});
