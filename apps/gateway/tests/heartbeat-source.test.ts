import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SqliteEventStore } from '@work-dns/events';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import type { AuthenticatedDeviceContext } from '../src/auth.js';
import { HeartbeatWatcher } from '../src/heartbeat-watcher.js';

const A = 'comp-a' as CompanyId;
const T0 = Date.UTC(2026, 9, 29, 9, 0, 0);
const MIN = 60_000;
const iso = (ms: number) => new Date(ms).toISOString();
const ctx = (deviceId: string): AuthenticatedDeviceContext => ({
    deviceId: deviceId as DeviceId,
    companyId: A,
    deviceGroupId: null,
    status: 'active',
});

describe('heartbeat last-seen source', () => {
    let dir: string;
    let store: SqliteEventStore;
    let nowMs: number;

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-hbsource-'));
        store = new SqliteEventStore(path.join(dir, 'audit.db'));
        nowMs = T0;
    });

    afterEach(() => {
        store.close();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    const make = () => new HeartbeatWatcher(store, { thresholdMs: 5 * MIN, now: () => nowMs, log: () => {} });

    it('marks a device that stayed silent since the gateway started', () => {
        const watcher = make();
        watcher.seed([ctx('d1')]);
        nowMs = T0 + 5 * MIN;
        watcher.sweep();
        const events = store.readAll(A);
        expect(events).toHaveLength(1);
        expect(events[0]!.payload).toMatchObject({ lastSeenAt: iso(T0), lastSeenSource: 'gateway_start' });
    });

    it('marks a device whose last sign of life was a real request', () => {
        const watcher = make();
        watcher.seed([ctx('d1')]);
        nowMs = T0 + MIN;
        watcher.touch(ctx('d1'));
        nowMs = T0 + 7 * MIN;
        watcher.sweep();
        expect(store.readAll(A)[0]!.payload).toMatchObject({ lastSeenAt: iso(T0 + MIN), lastSeenSource: 'request' });
    });

    it('marks a device that was first seen through a request, never seeded', () => {
        const watcher = make();
        watcher.touch(ctx('d1'));
        nowMs = T0 + 5 * MIN;
        watcher.sweep();
        expect(store.readAll(A)[0]!.payload).toMatchObject({ lastSeenSource: 'request' });
    });

    it('carries the source to the resumed entry, and a second outage starts from a real request', () => {
        const watcher = make();
        watcher.seed([ctx('d1')]);
        nowMs = T0 + 5 * MIN;
        watcher.sweep();
        nowMs = T0 + 8 * MIN;
        watcher.touch(ctx('d1'));
        nowMs = T0 + 14 * MIN;
        watcher.sweep();
        nowMs = T0 + 16 * MIN;
        watcher.touch(ctx('d1'));
        const events = store.readAll(A);
        expect(events.map((e) => e.type)).toEqual(['heartbeat_missed', 'heartbeat_resumed', 'heartbeat_missed', 'heartbeat_resumed']);
        expect(events.map((e) => e.payload.lastSeenSource)).toEqual(['gateway_start', 'gateway_start', 'request', 'request']);
        expect(events[2]!.payload.lastSeenAt).toBe(iso(T0 + 8 * MIN));
    });
});
