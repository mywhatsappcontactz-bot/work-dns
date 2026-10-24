import { describe, it, expect } from 'vitest';
import type {
    CompanyId,
    DeviceId,
    EventEnvelope,
    EventType,
    AgentStartedPayload,
    AgentStoppedPayload,
    EnforcementAppliedPayload,
    EnforcementResetPayload,
    EnforcementRestoredPayload,
    FailOpenEnteredPayload,
    FailOpenExitedPayload,
    AuthRejectedPayload,
    DeviceRevokedPayload,
    DnsAllowedSummaryPayload,
    RetentionExpiredPayload,
    DnsBlockedPayload,
} from '@work-dns/shared-types';
import { createEventEnvelope, verifyEventChain, GENESIS_HASH } from '../src/hash-chain.js';

const COMPANY = 'comp-test' as CompanyId;
const DEVICE = 'dev-test' as DeviceId;

type Entry = { type: EventType; payload: Record<string, unknown> };

function buildChain(entries: Entry[]): EventEnvelope[] {
    const events: EventEnvelope[] = [];
    let prevHash = GENESIS_HASH;
    entries.forEach((entry, i) => {
        const event = createEventEnvelope({
            id: `evt-${i + 1}`,
            sequenceNumber: i + 1,
            type: entry.type,
            companyId: COMPANY,
            deviceId: DEVICE,
            occurredAt: `2026-10-24T10:00:${String(i).padStart(2, '0')}.000Z`,
            payload: entry.payload,
            prevHash,
        });
        events.push(event);
        prevHash = event.hash;
    });
    return events;
}

const NEW_TYPE_ENTRIES: Entry[] = [
    { type: 'agent_started', payload: { agentVersion: '0.1.0', os: 'linux', loggedOsUser: 'berlin', policyVersion: 1 } satisfies AgentStartedPayload },
    { type: 'enforcement_applied', payload: { networkDevices: ['wlp58s0'], method: 'nmcli-runtime' } satisfies EnforcementAppliedPayload },
    { type: 'enforcement_reset', payload: { detectedAt: '2026-10-24T10:01:00.000Z', reappliedAt: '2026-10-24T10:01:01.600Z', windowSeconds: 1.6 } satisfies EnforcementResetPayload },
    { type: 'fail_open_entered', payload: { reason: 'gateway_unreachable', maxMinutes: 15 } satisfies FailOpenEnteredPayload },
    { type: 'fail_open_exited', payload: { durationSeconds: 42, cause: 'gateway_recovered' } satisfies FailOpenExitedPayload },
    { type: 'auth_rejected', payload: { httpStatus: 401, attempts: 3 } satisfies AuthRejectedPayload },
    { type: 'dns_allowed_summary', payload: { windowStart: '2026-10-24T10:00:00.000Z', windowEnd: '2026-10-24T11:00:00.000Z', allowedCount: 812, blockedCount: 14 } satisfies DnsAllowedSummaryPayload },
    { type: 'device_revoked', payload: { revokedByAdminId: 'admin-1', reason: 'laptop lost' } satisfies DeviceRevokedPayload },
    { type: 'enforcement_restored', payload: { networkDevices: ['wlp58s0'], trigger: 'crash_recovery', success: true } satisfies EnforcementRestoredPayload },
    { type: 'agent_stopped', payload: { reason: 'crash_recovered', dnsRestored: true } satisfies AgentStoppedPayload },
    { type: 'retention_expired', payload: { throughSequenceNumber: 500, retentionDays: 365, checkpointHash: 'a'.repeat(64) } satisfies RetentionExpiredPayload },
];

describe('audit event types', () => {
    it('chains and verifies one event of every new type', () => {
        expect(new Set(NEW_TYPE_ENTRIES.map((e) => e.type)).size).toBe(11);
        const events = buildChain(NEW_TYPE_ENTRIES);
        const result = verifyEventChain(events, { expectedCompanyId: COMPANY, expectedLength: 11 });
        expect(result.valid).toBe(true);
    });

    it('detects a changed payload at the right position', () => {
        const events = buildChain(NEW_TYPE_ENTRIES);
        events[2] = { ...events[2]!, payload: { detectedAt: 'x', windowSeconds: 0 } };
        const result = verifyEventChain(events, { expectedCompanyId: COMPANY });
        expect(result.valid).toBe(false);
        expect(result.brokenIndex).toBe(2);
    });

    it('verifies a blocked-attempt event with the old fields and one with the new fields', () => {
        const oldStyle = { domain: 'facebook.com', loggedOsUser: 'berlin', policyVersion: 1, reasonCode: 'DEFAULT_DENY' } satisfies DnsBlockedPayload;
        const newStyle = {
            ...oldStyle,
            recordType: 'A',
            ruleId: 'r1',
            deviceReportedAt: '2026-10-24T10:00:00.000Z',
            enforcementState: 'enforced',
            count: 3,
        } satisfies DnsBlockedPayload;
        const events = buildChain([
            { type: 'dns_blocked', payload: oldStyle },
            { type: 'dns_blocked', payload: newStyle },
        ]);
        expect(verifyEventChain(events, { expectedCompanyId: COMPANY, expectedLength: 2 }).valid).toBe(true);
    });

    it('catches a deleted tail only when the expected length or head hash is supplied', () => {
        const events = buildChain(NEW_TYPE_ENTRIES);
        const head = events[events.length - 1]!.hash;
        const truncated = events.slice(0, -2);
        expect(verifyEventChain(truncated, { expectedCompanyId: COMPANY }).valid).toBe(true); // the hole
        expect(verifyEventChain(truncated, { expectedCompanyId: COMPANY, expectedLength: 11 }).valid).toBe(false);
        expect(verifyEventChain(truncated, { expectedCompanyId: COMPANY, expectedHeadHash: head }).valid).toBe(false);
    });
});
