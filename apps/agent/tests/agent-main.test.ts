import { describe, it, expect } from 'vitest';
import { runAgent, AgentStub, AgentAdapter } from '../src/main.js';
import type { GatewayState } from '../src/dns-stub.js';
import type { DriftResult } from '../src/dns-watcher.js';

interface Options {
    state?: GatewayState;
    rcode?: number;
    setError?: string;
    restoreFailures?: number;
}

function makeDeps(options: Options = {}) {
    const events: string[] = [];
    let restoreFailuresLeft = options.restoreFailures ?? 0;
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
            const response = Buffer.alloc(12);
            response[3] = options.rcode ?? 0;
            return response;
        },
    };
    const adapter: AgentAdapter = {
        setDnsLoopback: async (port) => {
            events.push(`set:${port}`);
            if (options.setError) throw new Error(options.setError);
        },
        restoreDns: async () => {
            events.push('restore');
            if (restoreFailuresLeft > 0) {
                restoreFailuresLeft -= 1;
                throw new Error('nmcli unavailable');
            }
        },
        reapplyIfDrifted: async (): Promise<DriftResult> => 'ok',
    };
    const deps = {
        stub,
        adapter,
        port: 53,
        restoreAttempts: 3,
        restoreDelayMs: 1,
        startMonitor: () => {
            events.push('monitor.start');
            return {
                stop: () => {
                    events.push('monitor.stop');
                },
            };
        },
        log: () => {},
    };
    return { deps, events };
}

describe('runAgent', () => {
    it('starts the stub, checks it, enforces DNS, then starts the watcher; stops in reverse', async () => {
        const { deps, events } = makeDeps();
        const agent = await runAgent(deps);
        expect(events).toEqual(['stub.start', 'probe', 'set:53', 'monitor.start']);
        await agent.stop();
        expect(events.slice(4)).toEqual(['monitor.stop', 'restore', 'stub.stop']);
    });

    it('refuses to enforce while the gateway is unreachable (stub failing open)', async () => {
        const { deps, events } = makeDeps({ state: 'FAIL_OPEN_ACTIVE' });
        await expect(runAgent(deps)).rejects.toThrow(/refusing to enforce/);
        expect(events).not.toContain('set:53');
        expect(events).not.toContain('monitor.start');
        expect(events).toContain('stub.stop');
    });

    it('refuses to enforce when the startup check gets SERVFAIL', async () => {
        const { deps, events } = makeDeps({ rcode: 2 });
        await expect(runAgent(deps)).rejects.toThrow(/refusing to enforce/);
        expect(events).not.toContain('set:53');
    });

    it('cleans up when enforcement fails', async () => {
        const { deps, events } = makeDeps({ setError: 'boom' });
        await expect(runAgent(deps)).rejects.toThrow(/boom/);
        expect(events).toContain('restore');
        expect(events).toContain('stub.stop');
        expect(events).not.toContain('monitor.start');
    });

    it('retries a failing restore on stop and stops the stub only afterwards', async () => {
        const { deps, events } = makeDeps({ restoreFailures: 2 });
        const agent = await runAgent(deps);
        await agent.stop();
        expect(events.filter((e) => e === 'restore')).toHaveLength(3);
        expect(events[events.length - 1]).toBe('stub.stop');
    });

    it('keeps the stub running and reports an error when the restore never succeeds', async () => {
        const { deps, events } = makeDeps({ restoreFailures: 99 });
        const agent = await runAgent(deps);
        await expect(agent.stop()).rejects.toThrow(/could not restore DNS/);
        expect(events).not.toContain('stub.stop');
    });

    it('stop is idempotent', async () => {
        const { deps, events } = makeDeps();
        const agent = await runAgent(deps);
        await agent.stop();
        await agent.stop();
        expect(events.filter((e) => e === 'restore')).toHaveLength(1);
    });
});
