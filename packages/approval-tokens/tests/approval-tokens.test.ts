import { describe, it, expect } from 'vitest';
import {
  generateApprovalToken,
  verifyApprovalToken,
  hashApprovalToken,
  constantTimeCompare,
  peekTokenHeader,
} from '../src/index.js';
import { createHmac } from 'node:crypto';

describe('Approval Tokens - Cryptographic Binding, Validation & Expiry', () => {
  const secret = 'super-secret-key-that-is-at-least-32-chars-long-12345';
  const requestId = 'req-abc-123';
  const approverId = 'admin-efe-001';
  const companyId = 'company-hotel-royal';

  it('generates a signed approval token with version and kid, returning hash for database storage', () => {
    const generated = generateApprovalToken({
      requestId,
      approverId,
      companyId,
      secret,
      kid: 'k1',
      version: 1,
      durationMinutes: 10,
    });

    expect(generated.token).toBeDefined();
    expect(generated.token.split('.')).toHaveLength(2);
    expect(generated.tokenHash).toHaveLength(64); // SHA-256 hex
    expect(hashApprovalToken(generated.token)).toBe(generated.tokenHash);
    expect(generated.payload.version).toBe(1);
    expect(generated.payload.kid).toBe('k1');

    const nowSeconds = Math.floor(Date.now() / 1000);
    expect(generated.payload.expiresAt).toBeGreaterThan(nowSeconds + 500);
    expect(generated.payload.expiresAt).toBeLessThanOrEqual(nowSeconds + 600);
  });

  it('verifies a valid token when all required IDs (request, approver, company) match', () => {
    const { token } = generateApprovalToken({
      requestId,
      approverId,
      companyId,
      secret,
    });

    const result = verifyApprovalToken({
      token,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
    });

    expect(result.valid).toBe(true);
    expect(result.payload?.requestId).toBe(requestId);
    expect(result.payload?.approverId).toBe(approverId);
    expect(result.payload?.companyId).toBe(companyId);
    expect(result.payload?.version).toBe(1);
    expect(result.payload?.kid).toBe('k1');
  });

  it('fails when any required expected ID is missing (fails on old code where IDs were optional)', () => {
    const { token } = generateApprovalToken({
      requestId,
      approverId,
      companyId,
      secret,
    });

    // 1. Missing expectedRequestId
    const r1 = verifyApprovalToken({
      token,
      secret,
      expectedRequestId: '' as any,
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
    });
    expect(r1.valid).toBe(false);
    expect(r1.error).toMatch(/missing required expectedrequestid/i);

    // 2. Missing expectedApproverId
    const r2 = verifyApprovalToken({
      token,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: '' as any,
      expectedCompanyId: companyId,
    });
    expect(r2.valid).toBe(false);
    expect(r2.error).toMatch(/missing required expectedapproverid/i);

    // 3. Missing expectedCompanyId (didn't even exist on old code!)
    const r3 = verifyApprovalToken({
      token,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: '' as any,
    });
    expect(r3.valid).toBe(false);
    expect(r3.error).toMatch(/missing required expectedcompanyid/i);
  });

  it('fails when companyId does not match (wrong company fails - fails on old code)', () => {
    const { token } = generateApprovalToken({
      requestId,
      approverId,
      companyId: 'company-hotel-royal',
      secret,
    });

    // An attacker attempts cross-tenant reuse for a different company
    const result = verifyApprovalToken({
      token,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: 'company-hotel-competitor',
    });

    // Old code did not check expectedCompanyId at all!
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/company tenant/i);
  });

  it('fails when token payload is malformed or types are invalid (fails on old unvalidated cast)', () => {
    function craftToken(payload: unknown, signingSecret: string): string {
      const payloadEnc = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const sig = createHmac('sha256', signingSecret).update(payloadEnc, 'utf8').digest('base64url');
      return `${payloadEnc}.${sig}`;
    }

    // 1. Array instead of object
    const tArray = craftToken([1, 2, 3], secret);
    expect(verifyApprovalToken({
      token: tArray,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
    }).valid).toBe(false);

    // 2. Non-numeric expiresAt
    const tBadExpires = craftToken({
      version: 1,
      kid: 'k1',
      requestId,
      approverId,
      companyId,
      expiresAt: 'not-a-number',
      nonce: '1234567890abcdef',
    }, secret);
    expect(verifyApprovalToken({
      token: tBadExpires,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
    }).valid).toBe(false);

    // 3. Non-string requestId
    const tBadReqId = craftToken({
      version: 1,
      kid: 'k1',
      requestId: 12345,
      approverId,
      companyId,
      expiresAt: Math.floor(Date.now() / 1000) + 600,
      nonce: '1234567890abcdef',
    }, secret);
    expect(verifyApprovalToken({
      token: tBadReqId,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
    }).valid).toBe(false);

    // 4. Missing kid / version
    const tMissingMeta = craftToken({
      requestId,
      approverId,
      companyId,
      expiresAt: Math.floor(Date.now() / 1000) + 600,
      nonce: '1234567890abcdef',
    }, secret);
    expect(verifyApprovalToken({
      token: tMissingMeta,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
    }).valid).toBe(false);

    // 5. Corrupt Base64 string
    const tCorrupt = `!not-base64!.${craftToken({}, secret).split('.')[1]}`;
    expect(verifyApprovalToken({
      token: tCorrupt,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
    }).valid).toBe(false);
  });

  it('supports clock injection for testable time control without exposing currentTimeSeconds in production signature', () => {
    const fixedNow = 1770000000; // Fixed epoch seconds
    const mockClock = () => fixedNow;

    const { token, payload } = generateApprovalToken({
      requestId,
      approverId,
      companyId,
      secret,
      durationMinutes: 10,
      clock: mockClock,
    });

    expect(payload.expiresAt).toBe(fixedNow + 600);

    // 1. Verify within valid time window using injected clock
    const validResult = verifyApprovalToken({
      token,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
      clock: () => fixedNow + 300, // 5 minutes later
    });
    expect(validResult.valid).toBe(true);

    // 2. Reject after expiration using injected clock
    const expiredResult = verifyApprovalToken({
      token,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
      clock: () => fixedNow + 601, // 10 minutes and 1 second later
    });
    expect(expiredResult.valid).toBe(false);
    expect(expiredResult.error).toMatch(/expired/i);
  });

  it('supports key rotation via kid and dynamic secret resolver', () => {
    const secretOld = 'super-secret-key-that-is-at-least-32-chars-long-old123';
    const secretNew = 'super-secret-key-that-is-at-least-32-chars-long-new456';

    const keyRing: Record<string, string> = {
      'key-2026-q3': secretOld,
      'key-2026-q4': secretNew,
    };

    // Generate token with key-2026-q4
    const { token } = generateApprovalToken({
      requestId,
      approverId,
      companyId,
      secret: secretNew,
      kid: 'key-2026-q4',
    });

    // Peek unverified header before KMS fetch
    const header = peekTokenHeader(token);
    expect(header?.kid).toBe('key-2026-q4');
    expect(header?.version).toBe(1);

    // Verify using dynamic secret resolver function
    const result = verifyApprovalToken({
      token,
      secret: (kid) => keyRing[kid],
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
    });

    expect(result.valid).toBe(true);
    expect(result.payload?.kid).toBe('key-2026-q4');
  });

  it('rejects a token if the signature or payload has been tampered with', () => {
    const { token } = generateApprovalToken({
      requestId,
      approverId,
      companyId,
      secret,
    });

    const [payloadPart, sigPart] = token.split('.');
    const tamperedSig = sigPart?.slice(0, -2) + 'aa';
    const tamperedToken = `${payloadPart}.${tamperedSig}`;

    const result = verifyApprovalToken({
      token: tamperedToken,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/invalid token signature/i);
  });

  it('rejects a token if presented for a different request ID', () => {
    const { token } = generateApprovalToken({
      requestId: 'req-original',
      approverId,
      companyId,
      secret,
    });

    const result = verifyApprovalToken({
      token,
      secret,
      expectedRequestId: 'req-different-unauthorized',
      expectedApproverId: approverId,
      expectedCompanyId: companyId,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/not bound to the requested access request/i);
  });

  it('rejects a token if presented by a different approver ID', () => {
    const { token } = generateApprovalToken({
      requestId,
      approverId: 'admin-original',
      companyId,
      secret,
    });

    const result = verifyApprovalToken({
      token,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: 'admin-impostor',
      expectedCompanyId: companyId,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/not bound to the designated approver/i);
  });

  it('provides constant-time comparison that resists timing side-channels', () => {
    expect(constantTimeCompare('secret-token-1234', 'secret-token-1234')).toBe(true);
    expect(constantTimeCompare('secret-token-1234', 'secret-token-1235')).toBe(false);
    expect(constantTimeCompare('short', 'longer-string')).toBe(false);
  });
});
