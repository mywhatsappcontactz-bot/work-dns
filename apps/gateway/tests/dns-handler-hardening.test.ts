import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import dnsPacket from 'dns-packet';
import { PolicyEngine } from '@work-dns/policy-engine';
import { PolicyDefinition, DomainAllowRule } from '@work-dns/shared-types';
import { DnsHandler } from '../src/dns-handler.js';
import { buildErrorResponse } from '../src/dns-response.js';
import type { UpstreamResolver } from '../src/upstream.js';
import type { GatewayEventQueue } from '../src/event-queue.js';

const device = {
    deviceId: 'dev-1',
    companyId: 'comp-100',
    deviceGroupId: null,
    status: 'active' as const,
};

function makeQuery(name: string, extra: Partial<dnsPacket.Packet> = {}): Buffer {
    return Buffer.from(
        dnsPacket.encode({
            type: 'query',
            id: 7,
            flags: dnsPacket.RECURSION_DESIRED,
            questions: [{ type: 'A', name }],
            ...extra,
        })
    );
}

describe('buildErrorResponse', () => {
    it.each([
        ['NXDOMAIN', 'NXDOMAIN'],
        ['SERVFAIL', 'SERVFAIL'],
        ['REFUSED', 'REFUSED'],
    ] as const)('round-trips %s with id and question echoed', (rcode, expected) => {
        const query = dnsPacket.decode(makeQuery('example.com'));
        const decoded = dnsPacket.decode(buildErrorResponse(query, rcode));
        expect(decoded.type).toBe('response');
        expect(decoded.rcode).toBe(expected);
        expect(decoded.id).toBe(7);
        expect(decoded.questions?.[0]?.name).toBe('example.com');
        expect(decoded.answers?.length ?? 0).toBe(0);
    });
});

describe('DnsHandler hardening', () => {
    let handler: DnsHandler;
    let upstream: { resolve: ReturnType<typeof vi.fn> };
    let eventQueue: { enqueueBlockedAttempt: ReturnType<typeof vi.fn> };
    let errorSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        errorSpy = vi.spyOn(console, 'error').mockImplementation(() => { });
        upstream = { resolve: vi.fn().mockResolvedValue(Buffer.from('upstream-answer')) };
        eventQueue = { enqueueBlockedAttempt: vi.fn() };
        handler = new DnsHandler({
            policyEngine: new PolicyEngine(),
            upstreamResolver: upstream as unknown as UpstreamResolver,
            eventQueue: eventQueue as unknown as GatewayEventQueue,
        });

        const policy: PolicyDefinition = {
            id: 'pol-1',
            companyId: 'comp-100',
            version: 1,
            mode: 'strict',
            defaultActionDuringEnforcedHours: 'BLOCK',
            defaultActionOutsideEnforcedHours: 'BLOCK',
            timezone: 'Africa/Lagos',
            rules: [
                {
                    id: 'rule-google',
                    type: 'domain_allow',
                    pattern: '*.google.com',
                    effect: 'ALLOW',
                    priority: 1,
                } as DomainAllowRule,
            ],
            updatedAt: new Date().toISOString(),
        };
        handler.updateCompiledPolicy(policy);
    });

    afterEach(() => {
        errorSpy.mockRestore();
    });

    it('rejects multi-question packets and never calls upstream', async () => {
        const query = makeQuery('mail.google.com', {
            questions: [
                { type: 'A', name: 'mail.google.com' },
                { type: 'A', name: 'facebook.com' },
            ],
        });
        const result = await handler.handleDnsMessage(query, device);
        expect(result.statusCode).toBe(400);
        expect(result.action).toBe('REJECT');
        expect(upstream.resolve).not.toHaveBeenCalled();
    });

    it('rejects response packets (QR bit set)', async () => {
        const response = Buffer.from(
            dnsPacket.encode({ type: 'response', id: 9, questions: [{ type: 'A', name: 'mail.google.com' }] })
        );
        const result = await handler.handleDnsMessage(response, device);
        expect(result.statusCode).toBe(400);
        expect(upstream.resolve).not.toHaveBeenCalled();
    });

    it('rejects non-QUERY opcodes', async () => {
        const query = makeQuery('mail.google.com');
        query[2] = (query[2]! & 0x87) | (5 << 3); // opcode 5 = UPDATE
        const result = await handler.handleDnsMessage(query, device);
        expect(result.statusCode).toBe(400);
        expect(result.errorMessage).toMatch(/opcode/i);
        expect(upstream.resolve).not.toHaveBeenCalled();
    });

    it('rejects unsupported query types such as AXFR', async () => {
        const query = makeQuery('mail.google.com', { questions: [{ type: 'AXFR', name: 'mail.google.com' }] });
        const result = await handler.handleDnsMessage(query, device);
        expect(result.statusCode).toBe(400);
        expect(upstream.resolve).not.toHaveBeenCalled();
    });

    it('normalizes case and trailing dots before policy evaluation', async () => {
        const result = await handler.handleDnsMessage(makeQuery('MAIL.Google.Com.'), device);
        expect(result.action).toBe('ALLOW');
        expect(result.domain).toBe('mail.google.com');
    });

    it('blocks names that merely resemble allowed suffixes', async () => {
        for (const name of ['notgoogle.com', 'google.com.evil.com', 'evilgoogle.com']) {
            const result = await handler.handleDnsMessage(makeQuery(name), device);
            expect(result.action, name).toBe('BLOCK');
        }
        expect(upstream.resolve).not.toHaveBeenCalled();
    });

    it('forwards a sanitized single-question query without client extras', async () => {
        const query = makeQuery('mail.google.com', {
            additionals: [{ type: 'TXT', name: 'x.example.com', data: ['hello'] }],
        });
        await handler.handleDnsMessage(query, device);
        const sent = dnsPacket.decode(upstream.resolve.mock.calls[0]![0] as Buffer);
        expect(sent.questions).toHaveLength(1);
        expect(sent.questions?.[0]?.name).toBe('mail.google.com');
        expect(sent.additionals ?? []).toHaveLength(0);
    });

    it('returns a real SERVFAIL and logs the cause when upstream fails', async () => {
        upstream.resolve.mockRejectedValueOnce(new Error('upstream down'));
        const result = await handler.handleDnsMessage(makeQuery('mail.google.com'), device);
        expect(result.upstreamError).toBe('upstream down');
        expect(dnsPacket.decode(result.responseBuffer!).rcode).toBe('SERVFAIL');
        expect(errorSpy).toHaveBeenCalledTimes(1);
    });

    it('records blocked attempts with the normalized domain', async () => {
        await handler.handleDnsMessage(makeQuery('FACEBOOK.com'), device);
        expect(eventQueue.enqueueBlockedAttempt).toHaveBeenCalledWith(
            expect.objectContaining({ domain: 'facebook.com', companyId: 'comp-100', deviceId: 'dev-1' })
        );
    });

    it('still answers NXDOMAIN and logs when the event queue throws', async () => {
        eventQueue.enqueueBlockedAttempt.mockImplementationOnce(() => {
            throw new Error('queue full');
        });
        const result = await handler.handleDnsMessage(makeQuery('facebook.com'), device);
        expect(result.statusCode).toBe(200);
        expect(dnsPacket.decode(result.responseBuffer!).rcode).toBe('NXDOMAIN');
        expect(errorSpy).toHaveBeenCalledTimes(1);
    });
});