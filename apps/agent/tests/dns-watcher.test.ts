import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { DnsDriftWatcher, DriftResult } from '../src/dns-watcher.js';

function harness(checkImpl: (call: number) => Promise<DriftResult>) {
    let calls = 0;
    let activity: () => void = () => {};
    let exit: () => void = () => {};
    let monitorStarts = 0;
    let monitorStops = 0;
    const logs: Array<{ level: string; message: string }> = [];
    const watcher = new DnsDriftWatcher({
        check: () => {
            calls += 1;
            return checkImpl(calls);
        },
        startMonitor: (onActivity, onExit) => {
            monitorStarts += 1;
            activity = onActivity;
            exit = onExit;
            return {
                stop: () => {
                    monitorStops += 1;
                },
            };
        },
        intervalMs: 5000,
        debounceMs: 300,
        restartMonitorMs: 2000,
        log: (level, message) => {
            logs.push({ level, message });
        },
    });
    return {
        watcher,
        logs,
        calls: () => calls,
        activity: () => activity(),
        exit: () => exit(),
        starts: () => monitorStarts,
        stops: () => monitorStops,
    };
}

describe('DnsDriftWatcher', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('checks on every timer tick', async () => {
        const h = harness(async () => 'ok');
        h.watcher.start();
        await vi.advanceTimersByTimeAsync(5000);
        expect(h.calls()).toBe(1);
        await vi.advanceTimersByTimeAsync(10000);
        expect(h.calls()).toBe(3);
        await h.watcher.stop();
    });

    it('collapses a burst of monitor activity into one check after the debounce', async () => {
        const h = harness(async () => 'ok');
        h.watcher.start();
        for (let i = 0; i < 25; i += 1) {
            h.activity();
            await vi.advanceTimersByTimeAsync(50);
        }
        expect(h.calls()).toBe(0);
        await vi.advanceTimersByTimeAsync(300);
        expect(h.calls()).toBe(1);
        await h.watcher.stop();
    });

    it('never runs two checks at once and re-checks once after a slow check finishes', async () => {
        let release: () => void = () => {};
        const gate = new Promise<void>((resolve) => {
            release = resolve;
        });
        const h = harness(async (n) => {
            if (n === 1) await gate;
            return 'ok';
        });
        h.watcher.start();
        await vi.advanceTimersByTimeAsync(5000);
        expect(h.calls()).toBe(1);
        h.activity();
        await vi.advanceTimersByTimeAsync(300);
        expect(h.calls()).toBe(1);
        release();
        await vi.advanceTimersByTimeAsync(0);
        expect(h.calls()).toBe(2);
        await h.watcher.stop();
    });

    it('reports a failing check once, keeps running, and does not repeat the same message', async () => {
        const h = harness(async (n) => {
            if (n <= 2) throw new Error('nmcli exploded');
            return 'ok';
        });
        h.watcher.start();
        await vi.advanceTimersByTimeAsync(10000);
        expect(h.calls()).toBe(2);
        expect(h.logs.filter((l) => l.level === 'error')).toHaveLength(1);
        await vi.advanceTimersByTimeAsync(5000);
        expect(h.calls()).toBe(3);
        await h.watcher.stop();
    });

    it('reports an inactive result as an error, once per streak', async () => {
        const h = harness(async () => 'inactive');
        h.watcher.start();
        await vi.advanceTimersByTimeAsync(15000);
        expect(h.calls()).toBe(3);
        expect(h.logs.filter((l) => l.level === 'error')).toHaveLength(1);
        await h.watcher.stop();
    });

    it('logs every successful re-apply', async () => {
        const h = harness(async () => 'reapplied');
        h.watcher.start();
        await vi.advanceTimersByTimeAsync(10000);
        expect(h.logs.filter((l) => l.level === 'info')).toHaveLength(2);
        await h.watcher.stop();
    });

    it('stays quiet while no device is connected', async () => {
        const h = harness(async () => 'no-device');
        h.watcher.start();
        await vi.advanceTimersByTimeAsync(15000);
        expect(h.calls()).toBe(3);
        expect(h.logs).toHaveLength(0);
        await h.watcher.stop();
    });

    it('restarts the monitor after it exits', async () => {
        const h = harness(async () => 'ok');
        h.watcher.start();
        expect(h.starts()).toBe(1);
        h.exit();
        await vi.advanceTimersByTimeAsync(1999);
        expect(h.starts()).toBe(1);
        await vi.advanceTimersByTimeAsync(1);
        expect(h.starts()).toBe(2);
        expect(h.logs.some((l) => l.level === 'error')).toBe(true);
        await h.watcher.stop();
    });

    it('stop halts timers, checks and monitor restarts, and stops the monitor', async () => {
        const h = harness(async () => 'ok');
        h.watcher.start();
        await h.watcher.stop();
        expect(h.stops()).toBe(1);
        await vi.advanceTimersByTimeAsync(20000);
        expect(h.calls()).toBe(0);

        const h2 = harness(async () => 'ok');
        h2.watcher.start();
        h2.exit();
        await h2.watcher.stop();
        await vi.advanceTimersByTimeAsync(20000);
        expect(h2.starts()).toBe(1);
        expect(h2.calls()).toBe(0);
    });

    it('refuses to start twice', async () => {
        const h = harness(async () => 'ok');
        h.watcher.start();
        expect(() => h.watcher.start()).toThrow(/already started/);
        await h.watcher.stop();
    });
});
