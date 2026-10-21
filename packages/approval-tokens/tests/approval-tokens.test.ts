import { describe, it, expect } from 'vitest';
import {
  generateApprovalToken,
  verifyApprovalToken,
  hashApprovalToken,
  constantTimeCompare,
} from '../src/index.js';

describe('Approval Tokens - Cryptographic Binding & Expiry', () => {
  const secret = 'super-secret-key-that-is-at-least-32-chars-long-12345';
  const requestId = 'req-abc-123';
  const approverId = 'admin-efe-001';
  const companyId = 'company-hotel-royal';

  it('generates a signed approval token and returns hash for database storage', () => {
    const generated = generateApprovalToken({
      requestId,
      approverId,
      companyId,
      secret,
      durationMinutes: 10,
    });

    expect(generated.token).toBeDefined();
    expect(generated.token.split('.')).toHaveLength(2);
    expect(generated.tokenHash).toHaveLength(64); // SHA-256 hex
    expect(hashApprovalToken(generated.token)).toBe(generated.tokenHash);

    const nowSeconds = Math.floor(Date.now() / 1000);
    // Expires ~10 minutes in the future
    expect(generated.payload.expiresAt).toBeGreaterThan(nowSeconds + 500);
    expect(generated.payload.expiresAt).toBeLessThanOrEqual(nowSeconds + 600);
  });

  it('verifies a valid token when request ID and approver ID match', () => {
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
    });

    expect(result.valid).toBe(true);
    expect(result.payload?.requestId).toBe(requestId);
    expect(result.payload?.approverId).toBe(approverId);
    expect(result.payload?.companyId).toBe(companyId);
  });

  it('rejects an expired approval token (exceeding 10-minute limit)', () => {
    const { token, payload } = generateApprovalToken({
      requestId,
      approverId,
      companyId,
      secret,
      durationMinutes: 10,
    });

    // Simulate verification 11 minutes later
    const futureTime = payload.expiresAt + 60;
    const result = verifyApprovalToken({
      token,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
      currentTimeSeconds: futureTime,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/expired/i);
  });

  it('rejects a token if the signature or payload has been tampered with', () => {
    const { token } = generateApprovalToken({
      requestId,
      approverId,
      companyId,
      secret,
    });

    const [payloadPart, sigPart] = token.split('.');
    // Tamper with the signature
    const tamperedSig = sigPart?.slice(0, -2) + 'aa';
    const tamperedToken = `${payloadPart}.${tamperedSig}`;

    const result = verifyApprovalToken({
      token: tamperedToken,
      secret,
      expectedRequestId: requestId,
      expectedApproverId: approverId,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/invalid token signature/i);
  });

  it('rejects a token if presented for a different request ID (cryptographic binding check)', () => {
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
