import { describe, it, expect, afterEach, vi } from 'vitest';
import { runAgent } from '../src/main.js';
import type { AgentAdapter, AgentAudit, AgentDeps, AgentStub } from '../src/main.js';
import type { GatewayState } from '../src/dns-stub.js';
import type { DriftResult } from '../src/dns-watcher.js';

interface Options {
    state?: GatewayState;
    restoreFailures?: number;
    reporterThrows?: boolean;
    senderStopThrows?: boolean;
    enforcedDevicesThrows?: boolean;
}

function setup(options: Options = {}) {
    const events: string[] = [];
    const logs: string[] = [];
    const resets: Array<{ detectedAt: Date; reappliedAt: Date }> = [];
    let restored = false;
    let restoreFailuresLeft = options.restoreFailures ?? 0;
    let drift: DriftResult = 'ok';
    let activity: () => void = () => {};

    const note = (text: string): void => {
        if (options.reporterThrows) throw new Error('reporter broke');
        events.push(text);
    };

    const reporter: AgentAudit['reporter'] = {
        agentStarted: () => note('report:agentStarted'),
        agentStopped: (reason, dnsRestored) => note(`report:agentStopped:${reason}:${dnsRestored}`),
        enforcementApplied: (devices) => note(`report:enforcementApplied:${devices.join(',')}`),
        enforcementReset: (detectedAt, reappliedAt) => {
            note('report:enforcementReset');
            resets.push({ detectedAt, reappliedAt });
        },
        enforcementRestored: (devices, trigger, success) => note(`report:enforcementRestored:${devices.join(',')}:${trigger}:${success}`),
    };

    const sender: AgentAudit['sender'] = {
        start: () => {
            events.push('sender.start');
        },
        stop: async (stopOptions) => {
            events.push(`sender.stop:${stopOptions?.finalFlushMs}`);
            if (options.senderStopThrows) throw new Error('sender stop broke');
        },
    };

    const stub: AgentStub = {
        start: async () => {
            events.push('stub.start');
        },
        stop: async () => {
            events.push('stub.stop');
        },
        getState: () => options.state ?? 'ONLINE',
        handleQuery: async () => {
            events.push('probe');
            return Buffer.alloc(12);
        },
    };

    const adapter: AgentAdapter = {
        setDnsLoopback: async (port) => {
            events.push(`set:${port}`);
        },
        restoreDns: async () => {
            events.push('restore');
            if (restoreFailuresLeft > 0) {
                restoreFailuresLeft -= 1;
                throw new Error('nmcli unavailable');
            }
            restored = true;
        },
        reapplyIfDrifted: async () => drift,
    };

    const deps: AgentDeps = {
        stub,
        adapter,
        port: 53,
        restoreAttempts: 3,
        restoreDelayMs: 1,
        startMonitor: (onActivity) => {
            events.push('monitor.start');
            activity = onActivity;
            return {
                stop: () => {
                    events.push('monitor.stop');
                },
            };
        },
        audit: {
            reporter,
            sender,
            enforcedDevices: () => {
                if (options.enforcedDevicesThrows) throw new Error('backup unreadable');
                return restored ? [] : ['wlan0'];
            },
        },
        log: (_level, message) => {
            logs.push(message);
        },
    };

    return {
        deps,
        events,
        logs,
        resets,
        setDrift: (value: DriftResult) => {
            drift = value;
        },
        trigger: () => activity(),
    };
}

describe('runAgent audit wiring', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('records start events after enforcement, then starts the sender and the watcher', async () => {
        const { deps, events } = setup();
        const agent = await runAgent(deps);
        expect(events).toEqual([
            'stub.start',
            'probe',
            'set:53',
            'report:agentStarted',
            'report:enforcementApplied:wlan0',
            'sender.start',
            'monitor.start',
        ]);
        await agent.stop();
    });

    it('reads the device list before restoring, delivers after the restore, and stops the stub last', async () => {
        const { deps, events } = setup();
        const agent = await runAgent(deps);
        const startup = events.length;
        await agent.stop();
        expect(events.slice(startup)).toEqual([
            'monitor.stop',
            'restore',
            'report:enforcementRestored:wlan0:shutdown:true',
            'report:agentStopped:signal:true',
            'sender.stop:5000',
            'stub.stop',
        ]);
    });

    it('still records and delivers when the restore fails, keeps the stub running, and surfaces the error', async () => {
        const { deps, events } = setup({ restoreFailures: 99 });
        const agent = await runAgent(deps);
        await expect(agent.stop()).rejects.toThrow(/could not restore DNS/);
        expect(events).toContain('report:enforcementRestored:wlan0:shutdown:false');
        expect(events).toContain('report:agentStopped:signal:false');
        expect(events).toContain('sender.stop:5000');
        expect(events).not.toContain('stub.stop');
    });

    it('records an enforcement_reset only when the watcher actually re-applied enforcement', async () => {
        vi.useFakeTimers();
        const { deps, resets, setDrift, trigger } = setup();
        const agent = await runAgent(deps);
        setDrift('reapplied');
        trigger();
        await vi.advanceTimersByTimeAsync(300);
        expect(resets).toHaveLength(1);
        expect(resets[0]!.detectedAt).toBeInstanceOf(Date);
        expect(resets[0]!.reappliedAt.getTime()).toBeGreaterThanOrEqual(resets[0]!.detectedAt.getTime());
        setDrift('ok');
        trigger();
        await vi.advanceTimersByTimeAsync(300);
        expect(resets).toHaveLength(1);
        await agent.stop();
    });

    it('records nothing and never starts the sender when startup fails', async () => {
        const { deps, events } = setup({ state: 'FAIL_OPEN_ACTIVE' });
        await expect(runAgent(deps)).rejects.toThrow(/refusing to enforce/);
        expect(events.some((e) => e.startsWith('report:'))).toBe(false);
        expect(events).not.toContain('sender.start');
        expect(events).not.toContain('set:53');
    });

    it('keeps enforcing and shuts down cleanly when the reporter throws', async () => {
        const { deps, events, logs } = setup({ reporterThrows: true });
        const agent = await runAgent(deps);
        await agent.stop();
        expect(events).toContain('sender.start');
        expect(events).toContain('restore');
        expect(events).toContain('stub.stop');
        expect(logs).toContain('audit reporting failed');
    });

    it('still stops the stub when the final delivery throws', async () => {
        const { deps, events, logs } = setup({ senderStopThrows: true });
        const agent = await runAgent(deps);
        await expect(agent.stop()).resolves.toBeUndefined();
        expect(events).toContain('stub.stop');
        expect(logs).toContain('final delivery of audit events failed; they stay in the outbox');
    });

    it('still reports the start when the enforced device list cannot be read, using an empty list', async () => {
        const { deps, events, logs } = setup({ enforcedDevicesThrows: true });
        const agent = await runAgent(deps);
        expect(events).toContain('report:agentStarted');
        expect(events).toContain('report:enforcementApplied:');
        expect(logs).toContain('could not list the enforced network devices');
        await agent.stop();
    });
});
