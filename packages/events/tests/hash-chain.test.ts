import { describe, it, expect } from 'vitest';
import {
  canonicalJson,
  createEventEnvelope,
  verifyEventHash,
  verifyEventChain,
  GENESIS_HASH,
} from '../src/index.js';
import { EventEnvelope } from '@work-dns/shared-types';

describe('Canonical JSON', () => {
  it('sorts keys deterministically regardless of insertion order', () => {
    const obj1 = { z: 1, a: 2, m: { b: 3, a: 4 } };
    const obj2 = { a: 2, m: { a: 4, b: 3 }, z: 1 };

    expect(canonicalJson(obj1)).toBe(canonicalJson(obj2));
    expect(canonicalJson(obj1)).toBe('{"a":2,"m":{"a":4,"b":3},"z":1}');
  });
});

describe('Audit Log - Tamper-Evident Hash Chain', () => {
  const companyId = 'company-hotel-1';

  it('generates a valid SHA-256 hash envelope for an event', () => {
    const event = createEventEnvelope({
      id: 'evt-1',
      type: 'device_enrolled',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:00:00.000Z',
      payload: { hostname: 'reception-pc-1', os: 'windows' },
      prevHash: GENESIS_HASH,
    });

    expect(event.hash).toHaveLength(64);
    expect(verifyEventHash(event)).toBe(true);
  });

  it('validates an intact sequence of audit events', () => {
    const chain: EventEnvelope[] = [];

    // Event 1 (Genesis)
    const e1 = createEventEnvelope({
      id: 'evt-1',
      type: 'device_enrolled',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:00:00.000Z',
      payload: { hostname: 'reception-pc-1' },
      prevHash: GENESIS_HASH,
    });
    chain.push(e1);

    // Event 2
    const e2 = createEventEnvelope({
      id: 'evt-2',
      type: 'aup_acknowledged',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:01:00.000Z',
      payload: { loggedOsUser: 'receptionist_john' },
      prevHash: e1.hash,
    });
    chain.push(e2);

    // Event 3
    const e3 = createEventEnvelope({
      id: 'evt-3',
      type: 'dns_blocked',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:02:00.000Z',
      payload: { domain: 'gambling-site.com', reasonCode: 'DEFAULT_DENY' },
      prevHash: e2.hash,
    });
    chain.push(e3);

    const verification = verifyEventChain(chain);
    expect(verification.valid).toBe(true);
  });

  it('detects tampering if an adversary edits an event payload in the audit log', () => {
    const e1 = createEventEnvelope({
      id: 'evt-1',
      type: 'dns_blocked',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:00:00.000Z',
      payload: { domain: 'gambling.com' },
      prevHash: GENESIS_HASH,
    });

    const e2 = createEventEnvelope({
      id: 'evt-2',
      type: 'access_requested',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:01:00.000Z',
      payload: { domain: 'gambling.com', reason: 'Hotel audit check' },
      prevHash: e1.hash,
    });

    const chain = [e1, e2];

    // Attacker modifies e1 payload in database to hide gambling domain
    const tamperedE1 = {
      ...e1,
      payload: { domain: 'innocent-site.com' },
    };

    const verification = verifyEventChain([tamperedE1, e2]);
    expect(verification.valid).toBe(false);
    expect(verification.brokenIndex).toBe(0);
    expect(verification.error).toMatch(/tampering detected/i);
  });

  it('detects tampering if an event is deleted from the chain', () => {
    const e1 = createEventEnvelope({
      id: 'evt-1',
      type: 'device_enrolled',
      companyId,
      payload: {},
      prevHash: GENESIS_HASH,
    });
    const e2 = createEventEnvelope({
      id: 'evt-2',
      type: 'dns_blocked',
      companyId,
      payload: { domain: 'blocked.com' },
      prevHash: e1.hash,
    });
    const e3 = createEventEnvelope({
      id: 'evt-3',
      type: 'heartbeat_missed',
      companyId,
      payload: {},
      prevHash: e2.hash,
    });

    // Malicious admin deletes e2 from the audit table
    const brokenChain = [e1, e3];
    const verification = verifyEventChain(brokenChain);

    expect(verification.valid).toBe(false);
    expect(verification.brokenIndex).toBe(1);
    expect(verification.error).toMatch(/broken prevHash linkage/i);
  });
});
