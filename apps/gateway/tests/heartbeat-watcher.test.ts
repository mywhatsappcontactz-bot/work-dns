import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SqliteEventStore } from '@work-dns/events';
import type { AuditEventStore } from '@work-dns/events';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import type { AuthenticatedDeviceContext } from '../src/auth.js';
import { HeartbeatWatcher } from '../src/heartbeat-watcher.js';
import type { HeartbeatWatcherOptions } from '../src/heartbeat-watcher.js';

const A = 'comp-a' as CompanyId;
const B = 'comp-b' as CompanyId;
const T0 = Date.UTC(2026, 9, 29, 9, 0, 0);
const MIN = 60_000;
const iso = (ms: number) => new Date(ms).toISOString();

const ctx = (
    deviceId: string,
    companyId: CompanyId = A,
    status: AuthenticatedDeviceContext['status'] = 'active'
): AuthenticatedDeviceContext => ({ deviceId: deviceId as DeviceId, companyId, deviceGroupId: null, status });

describe('HeartbeatWatcher', () => {
    let dir: string;
    let store: SqliteEventStore;
    let nowMs: number;
    let logs: string[];

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-heartbeat-'));
        store = new SqliteEventStore(path.join(dir, 'audit.db'));
        nowMs = T0;
        logs = [];
    });

    afterEach(() => {
        vi.useRealTimers();
        store.close();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    const make = (extra: Partial<HeartbeatWatcherOptions> = {}, target: Pick<AuditEventStore, 'append' | 'hasEvent'> = store) =>
        new HeartbeatWatcher(target, {
            thresholdMs: 5 * MIN,
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

    it('seeds only active devices', () => {
        const watcher = make();
        watcher.seed([ctx('d1'), ctx('d2', A, 'suspended'), ctx('d3', A, 'revoked')]);
        expect(watcher.trackedDevices()).toBe(1);
    });

    it('reports a device exactly at the threshold, not before', () => {
        const watcher = make();
        watcher.seed([ctx('d1')]);
        nowMs = T0 + 5 * MIN - 1;
        watcher.sweep();
        expect(store.readAll(A)).toHaveLength(0);
        nowMs = T0 + 5 * MIN;
        watcher.sweep();
        const events = store.readAll(A);
        expect(events).toHaveLength(1);
        expect(events[0]).toMatchObject({ id: `hb-missed:comp-a:d1:${T0}`, type: 'heartbeat_missed', deviceId: 'd1' });
        expect(events[0]!.payload).toEqual({ lastSeenAt: iso(T0), thresholdSeconds: 300, detectedAt: iso(T0 + 5 * MIN) });
        expect(watcher.silentDevices()).toBe(1);
    });

    it('writes one entry per outage, however long it lasts', () => {
        const watcher = make();
        watcher.seed([ctx('d1')]);
        for (let minute = 5; minute <= 600; minute += 5) {
            nowMs = T0 + minute * MIN;
            watcher.sweep();
        }
        expect(store.readAll(A)).toHaveLength(1);
    });

    it('a sign of life restarts the clock', () => {
        const watcher = make();
        watcher.seed([ctx('d1')]);
        nowMs = T0 + 4 * MIN;
        watcher.touch(ctx('d1'));
        nowMs = T0 + 6 * MIN;
        watcher.sweep();
        expect(store.readAll(A)).toHaveLength(0);
        nowMs = T0 + 9 * MIN;
        watcher.sweep();
        const events = store.readAll(A);
        expect(events).toHaveLength(1);
        expect(events[0]!.payload.lastSeenAt).toBe(iso(T0 + 4 * MIN));
    });

    it('records the return, then reports a second outage separately', () => {
        const watcher = make();
        watcher.seed([ctx('d1')]);
        nowMs = T0 + 5 * MIN;
        watcher.sweep();
        nowMs = T0 + 8 * MIN;
        watcher.touch(ctx('d1'));
        let events = store.readAll(A);
        expect(events.map((e) => e.type)).toEqual(['heartbeat_missed', 'heartbeat_resumed']);
        expect(events[1]!.id).toBe(`hb-resumed:comp-a:d1:${T0}`);
        expect(events[1]!.payload).toEqual({ lastSeenAt: iso(T0), resumedAt: iso(T0 + 8 * MIN), gapSeconds: 480 });
        expect(watcher.silentDevices()).toBe(0);
        nowMs = T0 + 14 * MIN;
        watcher.sweep();
        events = store.readAll(A);
        expect(events).toHaveLength(3);
        expect(events[2]!.payload.lastSeenAt).toBe(iso(T0 + 8 * MIN));
        expect(new Set(events.map((e) => e.id)).size).toBe(3);
        expect(store.verify(A, { expectedLength: 3 }).valid).toBe(true);
    });

    it('starts watching an unseeded device on its first request and ignores non-active ones', () => {
        const watcher = make();
        watcher.touch(ctx('d1'));
        watcher.touch(ctx('d2', A, 'suspended'));
        expect(watcher.trackedDevices()).toBe(1);
        nowMs = T0 + 5 * MIN;
        watcher.sweep();
        expect(store.readAll(A).map((e) => e.deviceId)).toEqual(['d1']);
    });

    it('keeps a failed missed-heartbeat write for the next sweep, without duplicates', () => {
        const watcher = make({}, failsOnce((id) => id.startsWith('hb-missed:')));
        watcher.seed([ctx('d1')]);
        nowMs = T0 + 5 * MIN;
        expect(() => watcher.sweep()).not.toThrow();
        expect(logs).toContain('could not record a missed heartbeat; will retry');
        expect(store.readAll(A)).toHaveLength(0);
        expect(watcher.silentDevices()).toBe(0);
        watcher.sweep();
        watcher.sweep();
        expect(store.readAll(A)).toHaveLength(1);
    });

    it('never throws from touch when the resume write fails, and retries it on the next sweep', () => {
        const watcher = make({}, failsOnce((id) => id.startsWith('hb-resumed:')));
        watcher.seed([ctx('d1')]);
        nowMs = T0 + 5 * MIN;
        watcher.sweep();
        nowMs = T0 + 7 * MIN;
        expect(() => watcher.touch(ctx('d1'))).not.toThrow();
        expect(logs).toContain('could not record a resumed heartbeat; will retry');
        expect(store.readAll(A)).toHaveLength(1);
        watcher.sweep();
        const events = store.readAll(A);
        expect(events.map((e) => e.type)).toEqual(['heartbeat_missed', 'heartbeat_resumed']);
        expect(events[1]!.payload.gapSeconds).toBe(420);
    });

    it('tracks the same device name in two companies separately', () => {
        const watcher = make();
        watcher.seed([ctx('d1', A), ctx('d1', B)]);
        nowMs = T0 + 5 * MIN;
        watcher.sweep();
        expect(store.readAll(A)).toHaveLength(1);
        expect(store.readAll(B)).toHaveLength(1);
        expect(store.readAll(A)[0]!.id).not.toBe(store.readAll(B)[0]!.id);
    });

    it('stops tracking new devices at its cap and says so once', () => {
        const watcher = make({ maxDevices: 2 });
        watcher.seed([ctx('d1'), ctx('d2'), ctx('d3'), ctx('d4')]);
        expect(watcher.trackedDevices()).toBe(2);
        expect(logs.filter((m) => m.startsWith('too many devices'))).toHaveLength(1);
    });

    it('stop() writes nothing and ends the sweep', async () => {
        vi.useFakeTimers();
        const watcher = make({ sweepIntervalMs: 1000 });
        watcher.seed([ctx('d1')]);
        watcher.start();
        watcher.stop();
        nowMs = T0 + 10 * MIN;
        await vi.advanceTimersByTimeAsync(60_000);
        expect(store.readAll(A)).toHaveLength(0);
    });

    it('sweeps on its own timer after start()', async () => {
        vi.useFakeTimers();
        const watcher = make({ sweepIntervalMs: 1000 });
        watcher.seed([ctx('d1')]);
        watcher.start();
        nowMs = T0 + 5 * MIN;
        await vi.advanceTimersByTimeAsync(1000);
        expect(store.readAll(A)).toHaveLength(1);
        watcher.stop();
    });

    it('rejects invalid options', () => {
        expect(() => new HeartbeatWatcher(store, { thresholdMs: 0 })).toThrow(RangeError);
        expect(() => new HeartbeatWatcher(store, { sweepIntervalMs: -1 })).toThrow(RangeError);
        expect(() => new HeartbeatWatcher(store, { maxDevices: 0 })).toThrow(RangeError);
    });
});
