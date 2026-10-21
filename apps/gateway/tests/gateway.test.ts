import { describe, it, expect, beforeEach } from 'vitest';
import dnsPacket from 'dns-packet';
import { PolicyEngine } from '@work-dns/policy-engine';
import { PolicyDefinition, DomainAllowRule } from '@work-dns/shared-types';
import {
  DeviceAuthenticator,
  DnsHandler,
  GatewayEventQueue,
  UpstreamResolver,
  MAX_DNS_PACKET_SIZE,
} from '../src/index.js';

describe('Gateway - Authentication & Rate Limiting', () => {
  let auth: DeviceAuthenticator;
  const rawToken = 'device-secret-bearer-token-abc';
  const tokenHash = DeviceAuthenticator.hashToken(rawToken);

  beforeEach(() => {
    auth = new DeviceAuthenticator();
    auth.registerTokenHash(tokenHash, {
      deviceId: 'dev-1',
      companyId: 'comp-100',
      deviceGroupId: null,
      status: 'active',
    });
  });

  it('authenticates valid Bearer token and returns context', () => {
    const res = auth.authenticateHeader(`Bearer ${rawToken}`);
    expect(res.authenticated).toBe(true);
    expect(res.context?.deviceId).toBe('dev-1');
  });

  it('rejects missing or malformed Authorization header with 401', () => {
    expect(auth.authenticateHeader(undefined).errorStatus).toBe(401);
    expect(auth.authenticateHeader('Basic 12345').errorStatus).toBe(401);
    expect(auth.authenticateHeader('Bearer ').errorStatus).toBe(401);
  });

  it('rejects unknown device tokens with 401', () => {
    const res = auth.authenticateHeader('Bearer wrong-token-not-registered');
    expect(res.authenticated).toBe(false);
    expect(res.errorStatus).toBe(401);
  });

  it('immediately rejects revoked tokens with 403', () => {
    auth.revokeTokenHash(tokenHash);
    const res = auth.authenticateHeader(`Bearer ${rawToken}`);
    expect(res.authenticated).toBe(false);
    expect(res.errorStatus).toBe(403);
    expect(res.errorMessage).toMatch(/revoked/i);
  });

  it('enforces token-bucket rate limiting per device', () => {
    // Consume all 100 burst tokens
    for (let i = 0; i < 100; i++) {
      expect(auth.authenticateHeader(`Bearer ${rawToken}`).authenticated).toBe(true);
    }
    // 101st query in same second is rate limited (429)
    const rateLimited = auth.authenticateHeader(`Bearer ${rawToken}`);
    expect(rateLimited.authenticated).toBe(false);
    expect(rateLimited.errorStatus).toBe(429);
  });
});

describe('Gateway - Strict DNS Message Parser & Fuzz Resilience', () => {
  let handler: DnsHandler;

  beforeEach(() => {
    const policyEngine = new PolicyEngine();
    const eventQueue = new GatewayEventQueue();
    const upstream = new UpstreamResolver();
    handler = new DnsHandler({ policyEngine, upstreamResolver: upstream, eventQueue });

    const samplePolicy: PolicyDefinition = {
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

    handler.updateCompiledPolicy(samplePolicy);
  });

  const validDevice = {
    deviceId: 'dev-1',
    companyId: 'comp-100',
    deviceGroupId: null,
    status: 'active' as const,
  };

  it('rejects payloads exceeding MAX_DNS_PACKET_SIZE (4096 bytes) with 413', async () => {
    const oversizedBuffer = Buffer.alloc(MAX_DNS_PACKET_SIZE + 1, 0xaa);
    const res = await handler.handleDnsMessage(oversizedBuffer, validDevice);
    expect(res.statusCode).toBe(413);
    expect(res.errorMessage).toMatch(/payload too large/i);
  });

  it('rejects buffers shorter than 12-byte DNS header with 400', async () => {
    const tinyBuffer = Buffer.from([0x01, 0x02, 0x03]);
    const res = await handler.handleDnsMessage(tinyBuffer, validDevice);
    expect(res.statusCode).toBe(400);
    expect(res.errorMessage).toMatch(/shorter than standard 12-byte header/i);
  });

  it('safely handles fuzzed / malformed bytes without crashing or throwing unhandled errors', async () => {
    const fuzzedBuffers = [
      Buffer.from([0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
      Buffer.alloc(100, 0x00),
      Buffer.alloc(512, 0xff),
    ];

    for (const fuzzed of fuzzedBuffers) {
      const res = await handler.handleDnsMessage(fuzzed, validDevice);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      expect(res.action).toBe('REJECT');
    }
  });

  it('synthesizes RFC 1035 authoritative NXDOMAIN for blocked domains', async () => {
    const queryBuffer = Buffer.from(
      dnsPacket.encode({
        type: 'query',
        id: 42,
        flags: dnsPacket.RECURSION_DESIRED,
        questions: [{ type: 'A', name: 'facebook.com' }],
      })
    );

    const result = await handler.handleDnsMessage(queryBuffer, validDevice);
    expect(result.statusCode).toBe(200);
    expect(result.action).toBe('BLOCK');
    expect(result.domain).toBe('facebook.com');

    // Decode returned buffer and verify NXDOMAIN
    const decoded = dnsPacket.decode(result.responseBuffer!);
    expect(decoded.id).toBe(42);
    expect(decoded.type).toBe('response');
    expect(decoded.rcode).toBe('NXDOMAIN');
    expect(decoded.answers?.length).toBe(0);
    expect(result.latencyMicroseconds).toBeGreaterThan(0);
  });
});
