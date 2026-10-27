import { describe, it, expect } from 'vitest';
import { AGENT_VERSION, AgentAuditReporter } from '../src/audit-reporter.js';
import type { GatewayStateChange } from '../src/dns-stub.js';

function setup(options: { throwOnAdd?: boolean; throwOnRecorded?: boolean } = {}) {
    const recorded: Array<{ type: string; payload: Record<string, unknown> }> = [];
    const logs: string[] = [];
    let kicks = 0;
    const reporter = new AgentAuditReporter({
        outbox: {
            add: (type, payload) => {
                if (options.throwOnAdd) throw new Error('disk gone');
                recorded.push({ type, payload });
                return `id-${recorded.length}`;
            },
        },
        failOpenMaxMinutes: 15,
        onRecorded: () => {
            kicks += 1;
            if (options.throwOnRecorded) throw new Error('kick failed');
        },
        log: (_level, message) => {
            logs.push(message);
        },
    });
    return { reporter, recorded, logs, kicks: () => kicks };
}

const change = (from: GatewayStateChange['from'], to: GatewayStateChange['to'], at: string, outageSeconds?: number): GatewayStateChange => ({
    from,
    to,
    at,
    ...(outageSeconds === undefined ? {} : { outageSeconds }),
});

describe('AgentAuditReporter', () => {
    it('reports agent_started with honest placeholders unless real values are given', () => {
        const { reporter, recorded } = setup();
        reporter.agentStarted();
        reporter.agentStarted({ loggedOsUser: 'alice', policyVersion: 3 });
        expect(recorded[0]).toEqual({
            type: 'agent_started',
            payload: { agentVersion: AGENT_VERSION, os: process.platform, loggedOsUser: 'unknown', policyVersion: 0 },
        });
        expect(recorded[1]!.payload).toMatchObject({ loggedOsUser: 'alice', policyVersion: 3 });
    });

    it('reports agent_stopped', () => {
        const { reporter, recorded } = setup();
        reporter.agentStopped('signal', true);
        expect(recorded[0]).toEqual({ type: 'agent_stopped', payload: { reason: 'signal', dnsRestored: true } });
    });

    it('cleans network device names so the gateway will not refuse the event', () => {
        const { reporter, recorded } = setup();
        reporter.enforcementApplied(['wlp58s0', 'bad name!', 'x'.repeat(65)]);
        reporter.enforcementApplied([]);
        reporter.enforcementApplied(Array.from({ length: 20 }, (_, i) => `eth${i}`));
        expect(recorded[0]!.payload).toEqual({ networkDevices: ['wlp58s0'], method: 'nmcli-runtime' });
        expect(recorded[1]!.payload.networkDevices).toEqual(['unknown']);
        expect((recorded[2]!.payload.networkDevices as string[]).length).toBe(16);
    });

    it('reports enforcement_reset with ISO times', () => {
        const { reporter, recorded } = setup();
        reporter.enforcementReset(new Date('2026-10-27T12:00:00.000Z'), new Date('2026-10-27T12:00:01.600Z'));
        expect(recorded[0]).toEqual({
            type: 'enforcement_reset',
            payload: { detectedAt: '2026-10-27T12:00:00.000Z', reappliedAt: '2026-10-27T12:00:01.600Z' },
        });
    });

    it('reports enforcement_restored', () => {
        const { reporter, recorded } = setup();
        reporter.enforcementRestored(['wlp58s0'], 'shutdown', true);
        expect(recorded[0]).toEqual({
            type: 'enforcement_restored',
            payload: { networkDevices: ['wlp58s0'], trigger: 'shutdown', success: true },
        });
    });

    it('maps fail-open entered, then the time limit, with the duration from the timestamps', () => {
        const { reporter, recorded } = setup();
        reporter.gatewayStateChanged(change('ONLINE', 'FAIL_OPEN_ACTIVE', '2026-10-27T12:00:00.000Z'));
        reporter.gatewayStateChanged(change('FAIL_OPEN_ACTIVE', 'FAIL_CLOSED', '2026-10-27T12:15:30.000Z'));
        expect(recorded).toEqual([
            { type: 'fail_open_entered', payload: { reason: 'gateway_unreachable', maxMinutes: 15 } },
            { type: 'fail_open_exited', payload: { durationSeconds: 930, cause: 'time_limit_reached' } },
        ]);
    });

    it('maps recovery from fail-open using the outage length', () => {
        const { reporter, recorded } = setup();
        reporter.gatewayStateChanged(change('ONLINE', 'FAIL_OPEN_ACTIVE', '2026-10-27T12:00:00.000Z'));
        reporter.gatewayStateChanged(change('FAIL_OPEN_ACTIVE', 'ONLINE', '2026-10-27T12:00:42.000Z', 42));
        expect(recorded[1]).toEqual({ type: 'fail_open_exited', payload: { durationSeconds: 42, cause: 'gateway_recovered' } });
    });

    it('records nothing when fail-closed recovers (no event type exists yet) and does not prompt a send', () => {
        const { reporter, recorded, kicks } = setup();
        reporter.gatewayStateChanged(change('FAIL_CLOSED', 'ONLINE', '2026-10-27T13:00:00.000Z', 1800));
        expect(recorded).toEqual([]);
        expect(kicks()).toBe(0);
    });

    it('never throws when the outbox fails, and says so', () => {
        const { reporter, logs, kicks } = setup({ throwOnAdd: true });
        expect(() => reporter.agentStarted()).not.toThrow();
        expect(logs).toContain('could not record an audit event');
        expect(kicks()).toBe(0);
    });

    it('never throws when the delivery prompt fails, and still keeps the event', () => {
        const { reporter, recorded, logs } = setup({ throwOnRecorded: true });
        expect(() => reporter.agentStopped('signal', true)).not.toThrow();
        expect(recorded).toHaveLength(1);
        expect(logs).toContain('audit delivery prompt failed');
    });

    it('prompts a delivery attempt once per recorded event, and rejects an invalid limit', () => {
        const { reporter, kicks } = setup();
        reporter.agentStarted();
        reporter.agentStopped('signal', true);
        expect(kicks()).toBe(2);
        expect(() => new AgentAuditReporter({ outbox: { add: () => 'x' }, failOpenMaxMinutes: 0 })).toThrow(RangeError);
    });
});
