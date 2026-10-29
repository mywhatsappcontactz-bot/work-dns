import { describe, it, expect, afterEach, vi } from 'vitest';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import { GatewayEventQueue } from '../src/event-queue.js';
import type { BlockedAttemptRecord } from '../src/event-queue.js';

const attempt = (domain: string) => ({
    companyId: 'comp-a' as CompanyId,
    deviceId: 'dev-1' as DeviceId,
    domain,
    loggedOsUser: 'unknown',
    policyVersion: 1,
    reasonCode: 'DEFAULT_DENY_UNLISTED_DOMAIN',
});

function collector() {
    const got: BlockedAttemptRecord[] = [];
    const queue = new GatewayEventQueue({
        sink: async (records) => {
            got.push(...records);
        },
    });
    return { queue, got };
}

describe('GatewayEventQueue lastSeenAt', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('leaves lastSeenAt unset for a single attempt', async () => {
        const { queue, got } = collector();
        queue.enqueueBlockedAttempt(attempt('a.example.com'));
        await queue.flushNow();
        expect(got).toHaveLength(1);
        expect(got[0]!.count).toBe(1);
        expect(got[0]!.lastSeenAt).toBeUndefined();
    });

    it('records the time of the latest merged attempt and keeps the first attempt time', async () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2026-10-28T10:00:00.000Z'));
        const { queue, got } = collector();
        queue.enqueueBlockedAttempt(attempt('a.example.com'));
        vi.setSystemTime(new Date('2026-10-28T10:00:03.000Z'));
        queue.enqueueBlockedAttempt(attempt('a.example.com'));
        vi.setSystemTime(new Date('2026-10-28T10:00:04.000Z'));
        queue.enqueueBlockedAttempt(attempt('a.example.com'));
        await queue.flushNow();
        expect(got).toHaveLength(1);
        expect(got[0]).toMatchObject({
            count: 3,
            occurredAt: '2026-10-28T10:00:00.000Z',
            lastSeenAt: '2026-10-28T10:00:04.000Z',
        });
    });

    it('tracks each domain separately', async () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2026-10-28T10:00:00.000Z'));
        const { queue, got } = collector();
        queue.enqueueBlockedAttempt(attempt('a.example.com'));
        queue.enqueueBlockedAttempt(attempt('b.example.com'));
        vi.setSystemTime(new Date('2026-10-28T10:00:02.000Z'));
        queue.enqueueBlockedAttempt(attempt('a.example.com'));
        await queue.flushNow();
        const a = got.find((r) => r.domain === 'a.example.com')!;
        const b = got.find((r) => r.domain === 'b.example.com')!;
        expect(a.lastSeenAt).toBe('2026-10-28T10:00:02.000Z');
        expect(b.lastSeenAt).toBeUndefined();
    });
});
