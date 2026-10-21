import { describe, it, expect } from 'vitest';
import {
  canonicalJson,
  computeEventHash,
  createEventEnvelope,
  verifyEventHash,
  verifyEventChain,
  GENESIS_HASH,
} from '../src/index.js';
import { EventEnvelope } from '@work-dns/shared-types';

describe('Canonical JSON & RFC 8785 Compliance', () => {
  it('sorts keys deterministically based on UTF-16 code units', () => {
    const obj1 = { z: 1, a: 2, m: { b: 3, a: 4 } };
    const obj2 = { a: 2, m: { a: 4, b: 3 }, z: 1 };

    expect(canonicalJson(obj1)).toBe(canonicalJson(obj2));
    expect(canonicalJson(obj1)).toBe('{"a":2,"m":{"a":4,"b":3},"z":1}');
  });

  it('guarantees locale-independent sorting over code units (fails on localeCompare)', () => {
    // Under code-unit comparison: 'z' (code 122) < 'ä' (\u00e4, code 228), so 'z' appears before 'ä'.
    // Under German localeCompare ('de'): 'ä' sorts before 'z'.
    // Old implementation using localeCompare produces different key orderings depending on runtime locale.
    const input = { z: 'last-ascii', '\u00e4': 'umlaut' };
    const result = canonicalJson(input);

    expect(result).toBe('{"z":"last-ascii","\u00e4":"umlaut"}');
  });

  it('throws on Date payload objects (fails on old code that silently serialized to ISO string)', () => {
    expect(() => canonicalJson({ timestamp: new Date() })).toThrow(/Date instances are not allowed/);
    expect(() => canonicalJson([new Date()])).toThrow(/Date instances are not allowed/);
  });

  it('throws on undefined values in arrays (fails on JSON.stringify which turns undefined to null)', () => {
    expect(() => canonicalJson(['valid', undefined, 'item'])).toThrow(/undefined in arrays is not allowed/);
  });

  it('throws on NaN and Infinity (fails on JSON.stringify which converts them to null)', () => {
    expect(() => canonicalJson({ val: NaN })).toThrow(/NaN and Infinity are not allowed/);
    expect(() => canonicalJson({ val: Infinity })).toThrow(/NaN and Infinity are not allowed/);
    expect(() => canonicalJson({ val: -Infinity })).toThrow(/NaN and Infinity are not allowed/);
  });

  it('throws on BigInt values', () => {
    expect(() => canonicalJson({ big: BigInt(9007199254740991) })).toThrow(/BigInt is not supported/);
  });

  it('throws on Map instances', () => {
    expect(() => canonicalJson(new Map([['a', 1]]))).toThrow(/Map instances are not allowed/);
    expect(() => canonicalJson({ m: new Map() })).toThrow(/Map instances are not allowed/);
  });

  it('throws on Set instances', () => {
    expect(() => canonicalJson(new Set([1, 2]))).toThrow(/Set instances are not allowed/);
    expect(() => canonicalJson({ s: new Set() })).toThrow(/Set instances are not allowed/);
  });

  it('throws on Buffer instances', () => {
    expect(() => canonicalJson(Buffer.from('hello'))).toThrow(/Buffer instances are not allowed/);
    expect(() => canonicalJson({ b: Buffer.alloc(4) })).toThrow(/Buffer instances are not allowed/);
  });

  it('throws on RegExp instances', () => {
    expect(() => canonicalJson(/abc/)).toThrow(/RegExp instances are not allowed/);
    expect(() => canonicalJson({ r: /abc/g })).toThrow(/RegExp instances are not allowed/);
  });

  it('throws on class instances (non-plain objects)', () => {
    class Foo { x = 1; }
    expect(() => canonicalJson(new Foo())).toThrow(/Class instances and non-plain objects are not allowed/);
    expect(() => canonicalJson({ nested: new Foo() })).toThrow(/Class instances and non-plain objects are not allowed/);
  });

  it('throws when nesting depth exceeds 64', () => {
    // Build a deeply nested object with depth 65
    let deep: unknown = { leaf: true };
    for (let i = 0; i < 65; i++) {
      deep = { nested: deep };
    }
    expect(() => canonicalJson(deep)).toThrow(/Maximum nesting depth of 64 exceeded/);
  });

  it('accepts nesting up to exactly depth 64', () => {
    let deep: unknown = { leaf: true };
    for (let i = 0; i < 63; i++) {
      deep = { n: deep };
    }
    // Should not throw — exactly 64 levels of recursion
    expect(() => canonicalJson(deep)).not.toThrow();
  });
});

describe('Audit Log - Tamper-Evident Hash Chain', () => {
  const companyId = 'company-hotel-1';

  it('generates a valid SHA-256 hash envelope for an event', () => {
    const event = createEventEnvelope({
      id: 'evt-1',
      sequenceNumber: 1,
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

  it('detects tampering when an adversary modifies the event id (fails on old code where id was omitted from hash)', () => {
    const event = createEventEnvelope({
      id: 'evt-original',
      sequenceNumber: 1,
      type: 'dns_blocked',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:00:00.000Z',
      payload: { domain: 'gambling.com' },
      prevHash: GENESIS_HASH,
    });

    // Tamper with the event id while preserving the computed hash
    const tamperedEvent = {
      ...event,
      id: 'evt-forged-id',
    };

    // Old code passes because computeEventHash did not include params.id in hash computation
    expect(verifyEventHash(tamperedEvent)).toBe(false);

    const verification = verifyEventChain([tamperedEvent], {
      expectedCompanyId: companyId,
      expectedAnchorHash: GENESIS_HASH,
    });
    expect(verification.valid).toBe(false);
    expect(verification.error).toMatch(/tampering detected/i);
  });

  it('prevents delimiter injection collisions (fails on old code using "|" string concatenation)', () => {
    // In old code:
    // [prevHash, occurredAt, type, schemaVersion, companyId, deviceId, payload].join('|')
    // Collision:
    // Event A: companyId = "corp|injected", deviceId = "" (null)
    // Event B: companyId = "corp", deviceId = "injected"
    // Both joined to: "...|corp|injected||..." producing identical hashes.
    const commonParams = {
      id: 'evt-col-1',
      sequenceNumber: 1,
      type: 'dns_blocked' as const,
      schemaVersion: 1,
      occurredAt: '2026-10-21T00:00:00.000Z',
      payload: { domain: 'test.com' },
      prevHash: GENESIS_HASH,
    };

    const hashA = computeEventHash({
      ...commonParams,
      companyId: 'corp|injected',
      deviceId: null,
    });

    const hashB = computeEventHash({
      ...commonParams,
      companyId: 'corp',
      deviceId: 'injected',
    });

    // Old code collides (hashA === hashB); structured canonical JSON produces distinct hashes
    expect(hashA).not.toBe(hashB);
  });

  it('detects a deleted first event when verified against expected genesis hash (fails on old code)', () => {
    const e1 = createEventEnvelope({
      id: 'evt-1',
      sequenceNumber: 1,
      type: 'device_enrolled',
      companyId,
      payload: {},
      prevHash: GENESIS_HASH,
    });

    const e2 = createEventEnvelope({
      id: 'evt-2',
      sequenceNumber: 2,
      type: 'dns_blocked',
      companyId,
      payload: { domain: 'gambling.com' },
      prevHash: e1.hash,
    });

    const e3 = createEventEnvelope({
      id: 'evt-3',
      sequenceNumber: 3,
      type: 'heartbeat_missed',
      companyId,
      payload: {},
      prevHash: e2.hash,
    });

    // Adversary drops the initial event e1 so e2 becomes the first event
    const chainMissingGenesis = [e2, e3];

    // Old code only checked linkage for i > 0, so [e2, e3] was accepted as valid!
    const verification = verifyEventChain(chainMissingGenesis, {
      expectedCompanyId: companyId,
      expectedAnchorHash: GENESIS_HASH,
    });
    expect(verification.valid).toBe(false);
    expect(verification.brokenIndex).toBe(0);
    expect(verification.error).toMatch(/does not match expected anchor hash/i);
  });

  it('rejects a mixed-company chain across tenants (fails on old code)', () => {
    const e1 = createEventEnvelope({
      id: 'evt-1',
      sequenceNumber: 1,
      type: 'device_enrolled',
      companyId: 'company-tenant-alpha',
      payload: { note: 'Alpha event' },
      prevHash: GENESIS_HASH,
    });

    // Adversary inserts an event from Beta into Alpha's audit chain
    const e2 = createEventEnvelope({
      id: 'evt-2',
      sequenceNumber: 2,
      type: 'dns_blocked',
      companyId: 'company-tenant-beta',
      payload: { note: 'Beta event' },
      prevHash: e1.hash,
    });

    // Old code never checked companyId continuity, allowing cross-tenant chain pollution
    const verification = verifyEventChain([e1, e2], {
      expectedCompanyId: 'company-tenant-alpha',
      expectedAnchorHash: GENESIS_HASH,
    });
    expect(verification.valid).toBe(false);
    expect(verification.brokenIndex).toBe(1);
    expect(verification.error).toMatch(/mixed-company chain detected/i);
  });

  it('rejects chains with duplicate event IDs', () => {
    const e1 = createEventEnvelope({
      id: 'evt-shared-id',
      sequenceNumber: 1,
      type: 'device_enrolled',
      companyId,
      payload: { seq: 1 },
      prevHash: GENESIS_HASH,
    });

    const e2 = createEventEnvelope({
      id: 'evt-shared-id', // Duplicate id!
      sequenceNumber: 2,
      type: 'aup_acknowledged',
      companyId,
      payload: { seq: 2 },
      prevHash: e1.hash,
    });

    const verification = verifyEventChain([e1, e2], {
      expectedCompanyId: companyId,
      expectedAnchorHash: GENESIS_HASH,
    });
    expect(verification.valid).toBe(false);
    expect(verification.brokenIndex).toBe(1);
    expect(verification.error).toMatch(/duplicate event id detected/i);
  });

  it('validates an intact sequence of audit events', () => {
    const chain: EventEnvelope[] = [];

    const e1 = createEventEnvelope({
      id: 'evt-1',
      sequenceNumber: 1,
      type: 'device_enrolled',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:00:00.000Z',
      payload: { hostname: 'reception-pc-1' },
      prevHash: GENESIS_HASH,
    });
    chain.push(e1);

    const e2 = createEventEnvelope({
      id: 'evt-2',
      sequenceNumber: 2,
      type: 'aup_acknowledged',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:01:00.000Z',
      payload: { loggedOsUser: 'receptionist_john' },
      prevHash: e1.hash,
    });
    chain.push(e2);

    const e3 = createEventEnvelope({
      id: 'evt-3',
      sequenceNumber: 3,
      type: 'dns_blocked',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:02:00.000Z',
      payload: { domain: 'gambling-site.com', reasonCode: 'DEFAULT_DENY' },
      prevHash: e2.hash,
    });
    chain.push(e3);

    const verification = verifyEventChain(chain, {
      expectedCompanyId: companyId,
      expectedAnchorHash: GENESIS_HASH,
    });
    expect(verification.valid).toBe(true);
  });

  it('detects payload tampering within an audit event', () => {
    const e1 = createEventEnvelope({
      id: 'evt-1',
      sequenceNumber: 1,
      type: 'dns_blocked',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:00:00.000Z',
      payload: { domain: 'gambling.com' },
      prevHash: GENESIS_HASH,
    });

    const e2 = createEventEnvelope({
      id: 'evt-2',
      sequenceNumber: 2,
      type: 'access_requested',
      companyId,
      deviceId: 'dev-1',
      occurredAt: '2026-10-21T00:01:00.000Z',
      payload: { domain: 'gambling.com', reason: 'Hotel audit check' },
      prevHash: e1.hash,
    });

    // Attacker modifies e1 payload in database to conceal gambling domain
    const tamperedE1 = {
      ...e1,
      payload: { domain: 'innocent-site.com' },
    };

    const verification = verifyEventChain([tamperedE1, e2], {
      expectedCompanyId: companyId,
      expectedAnchorHash: GENESIS_HASH,
    });
    expect(verification.valid).toBe(false);
    expect(verification.brokenIndex).toBe(0);
    expect(verification.error).toMatch(/tampering detected/i);
  });

  it('fails when expectedCompanyId is not provided', () => {
    const e1 = createEventEnvelope({
      id: 'evt-1',
      sequenceNumber: 1,
      type: 'device_enrolled',
      companyId,
      payload: {},
      prevHash: GENESIS_HASH,
    });

    // Passing empty string as expectedCompanyId should be rejected
    const r1 = verifyEventChain([e1], {
      expectedCompanyId: '' as any,
      expectedAnchorHash: GENESIS_HASH,
    });
    expect(r1.valid).toBe(false);
    expect(r1.error).toMatch(/expectedCompanyId/i);

    // Passing an object without expectedCompanyId should be rejected
    const r2 = verifyEventChain([e1], {} as any);
    expect(r2.valid).toBe(false);
    expect(r2.error).toMatch(/expectedCompanyId/i);
  });
});
