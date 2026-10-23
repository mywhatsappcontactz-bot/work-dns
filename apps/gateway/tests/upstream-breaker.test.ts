import dnsPacket from 'dns-packet';
import { describe, expect, it } from 'vitest';
import { UpstreamResolver } from '../src/upstream.js';

const PRIMARY = 'https://primary.test/dns-query';
const SECONDARY = 'https://secondary.test/dns-query';

function query(name: string): Buffer {
  return Buffer.from(
    dnsPacket.encode({ type: 'query', id: 1, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'A', name }] })
  );
}

function answer(name: string): Response {
  const body = dnsPacket.encode({
    type: 'response',
    id: 0,
    flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
    questions: [{ type: 'A', name }],
    answers: [{ type: 'A', name, ttl: 300, data: '192.0.2.1' }],
  });
  return new Response(body, { status: 200, headers: { 'content-type': 'application/dns-message' } });
}

function setup(failing: Set<string>) {
  const calls: string[] = [];
  let nowMs = 1_000_000;
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    calls.push(u);
    if (failing.has(u)) throw new Error('simulated outage');
    const decoded = dnsPacket.decode(Buffer.from(init!.body as Buffer));
    return answer(decoded.questions![0]!.name);
  }) as typeof fetch;
  const resolver = new UpstreamResolver({
    primaryUrl: PRIMARY,
    secondaryUrl: SECONDARY,
    fetchImpl,
    now: () => nowMs,
    failureCooldownMs: 30_000,
  });
  return { resolver, calls, advance: (ms: number) => (nowMs += ms) };
}

describe('upstream failure cooldown', () => {
  it('skips a failed primary during the cooldown', async () => {
    const { resolver, calls } = setup(new Set([PRIMARY]));
    await resolver.resolve(query('a.example.com'));
    expect(calls).toEqual([PRIMARY, SECONDARY]);
    calls.length = 0;
    await resolver.resolve(query('b.example.com'));
    expect(calls).toEqual([SECONDARY]);
  });

  it('tries the primary again after the cooldown', async () => {
    const { resolver, calls, advance } = setup(new Set([PRIMARY]));
    await resolver.resolve(query('a.example.com'));
    calls.length = 0;
    advance(31_000);
    await resolver.resolve(query('c.example.com'));
    expect(calls[0]).toBe(PRIMARY);
  });

  it('still tries both when both are down', async () => {
    const { resolver, calls } = setup(new Set([PRIMARY, SECONDARY]));
    await expect(resolver.resolve(query('a.example.com'))).rejects.toThrow('simulated outage');
    calls.length = 0;
    await expect(resolver.resolve(query('b.example.com'))).rejects.toThrow('simulated outage');
    expect(calls).toHaveLength(2);
  });
});
