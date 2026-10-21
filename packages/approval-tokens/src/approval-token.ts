/**
 * Cryptographically Bound Approval Tokens
 * 
 * SECURITY ARCHITECTURE & SINGLE-USE ENFORCEMENT NOTICE:
 * =======================================================
 * Approval tokens are stateless cryptographic bearer tokens signed with HMAC-SHA256,
 * bound to requestId, approverId, companyId, version, and key ID (kid).
 * 
 * Token verification (`verifyApprovalToken`) validates cryptographic integrity,
 * correct binding, valid payload structure, and non-expiration.
 * 
 * CRITICAL DATABASE LAYER REQUIREMENT:
 * Token verification ALONE CANNOT enforce single-use. Single-use MUST be enforced
 * atomically within the database layer at consumption time inside an ACID transaction.
 * 
 * Recommended SQL Pattern:
 * ```sql
 * UPDATE approval_tokens
 * SET status = 'USED', used_at = NOW()
 * WHERE token_hash = $1
 *   AND status = 'PENDING'
 *   AND expires_at > NOW()
 * RETURNING id, request_id, approver_id, company_id;
 * ```
 * If zero rows are returned by the update, the transaction must rollback and reject
 * the request as already used, expired, or invalid.
 * 
 * Raw tokens must NEVER be stored in the database. Only `hashApprovalToken(token)`
 * (SHA-256) is persisted.
 */

import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export type Clock = () => Date | number;

export interface ApprovalTokenPayload {
  version: number;   // Token format version (current: 1)
  kid: string;       // Key ID for HMAC secret lookup & rotation
  requestId: string;
  approverId: string;
  companyId: string;
  expiresAt: number; // Unix epoch seconds
  nonce: string;     // 16-byte hex nonce
}

export interface GeneratedApprovalToken {
  token: string;
  tokenHash: string;
  expiresAt: Date;
  payload: ApprovalTokenPayload;
}

export interface GenerateTokenOptions {
  requestId: string;
  approverId: string;
  companyId: string;
  secret: string;
  kid?: string;              // Key ID (defaults to 'k1')
  version?: number;          // Format version (defaults to 1)
  durationMinutes?: number;  // Defaults to 10 minutes per spec
  clock?: Clock;             // Injected clock function (defaults to Date.now)
}

export interface VerifyTokenOptions {
  token: string;
  secret: string | ((kid: string) => string | undefined);
  expectedRequestId: string;   // Required: Prevents token swapping across requests
  expectedApproverId: string;  // Required: Prevents unauthorized approver impersonation
  expectedCompanyId: string;   // Required: Enforces multi-tenant isolation
  expectedKid?: string;        // Optional key id check
  clock?: Clock;               // Injected clock function (defaults to Date.now)
}

export interface TokenVerificationResult {
  valid: boolean;
  error?: string;
  payload?: ApprovalTokenPayload;
}

/**
 * Computes a SHA-256 hash of the token for secure persistence at rest.
 * The server never stores raw token strings in the database.
 */
export function hashApprovalToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Encodes a buffer or string to URL-safe base64 without padding.
 */
function toBase64Url(input: Buffer | string): string {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buf.toString('base64url');
}

/**
 * Decodes a URL-safe base64 string.
 */
function fromBase64Url(str: string): string {
  return Buffer.from(str, 'base64url').toString('utf8');
}

/**
 * Extracts current time in unix epoch seconds from an optional clock injector or system clock.
 */
function getSecondsFromClock(clock?: Clock): number {
  if (!clock) {
    return Math.floor(Date.now() / 1000);
  }
  const val = clock();
  if (typeof val === 'number') {
    // If milliseconds returned (> 1e11), convert to seconds; otherwise treat as seconds
    return val > 1e11 ? Math.floor(val / 1000) : Math.floor(val);
  }
  if (val instanceof Date) {
    return Math.floor(val.getTime() / 1000);
  }
  return Math.floor(Date.now() / 1000);
}

/**
 * Constant-time string equality comparator to protect against timing side-channels.
 */
export function constantTimeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) {
    return false;
  }

  return timingSafeEqual(bufA, bufB);
}

/**
 * Extracts unverified token header/metadata for key rotation lookup prior to signature validation.
 */
export function peekTokenHeader(token: string): { version?: number; kid?: string } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2 || !parts[0]) return null;
    const raw = JSON.parse(fromBase64Url(parts[0])) as Record<string, unknown>;
    return {
      version: typeof raw?.version === 'number' ? raw.version : undefined,
      kid: typeof raw?.kid === 'string' ? raw.kid : undefined,
    };
  } catch {
    return null;
  }
}

/**
 * Generates a signed, single-use approval token cryptographically bound to request ID, approver ID,
 * company tenant, and key ID. Valid for 10 minutes by default.
 * 
 * Single-use must be enforced atomically in the database layer when consumed.
 */
export function generateApprovalToken(options: GenerateTokenOptions): GeneratedApprovalToken {
  if (!options.secret || options.secret.length < 32) {
    throw new Error('Approval token secret must be at least 32 characters long');
  }
  if (!options.requestId || typeof options.requestId !== 'string' || options.requestId.trim().length === 0) {
    throw new Error('Approval token requires a non-empty string requestId');
  }
  if (!options.approverId || typeof options.approverId !== 'string' || options.approverId.trim().length === 0) {
    throw new Error('Approval token requires a non-empty string approverId');
  }
  if (!options.companyId || typeof options.companyId !== 'string' || options.companyId.trim().length === 0) {
    throw new Error('Approval token requires a non-empty string companyId');
  }

  const durationMinutes = options.durationMinutes ?? 10;
  const nowSeconds = getSecondsFromClock(options.clock);
  const expiresAtSeconds = nowSeconds + durationMinutes * 60;

  const payload: ApprovalTokenPayload = {
    version: options.version ?? 1,
    kid: options.kid ?? 'k1',
    requestId: options.requestId,
    approverId: options.approverId,
    companyId: options.companyId,
    expiresAt: expiresAtSeconds,
    nonce: randomBytes(16).toString('hex'),
  };

  const payloadEncoded = toBase64Url(JSON.stringify(payload));
  const signature = createHmac('sha256', options.secret)
    .update(payloadEncoded, 'utf8')
    .digest();
  const signatureEncoded = toBase64Url(signature);

  const token = `${payloadEncoded}.${signatureEncoded}`;
  const tokenHash = hashApprovalToken(token);

  return {
    token,
    tokenHash,
    expiresAt: new Date(expiresAtSeconds * 1000),
    payload,
  };
}

/**
 * Verifies the integrity, bindings, schema, and expiration of an approval token.
 * 
 * Invariants enforced:
 * 1. Required bindings: expectedRequestId, expectedApproverId, and expectedCompanyId must be provided and match.
 * 2. Strict payload schema: Validates JSON shape and strict primitive types (no type pollution).
 * 3. Key rotation: Resolves signing secret by kid if dynamic secret resolver is provided.
 * 4. Timing attack resistance: All signature and binding checks use constant-time comparison.
 * 5. Clock injection: Uses injected clock function or system time to verify 10-minute expiry window.
 * 
 * Note: Single-use must be enforced atomically in the database layer when status is updated from PENDING to USED.
 */
export function verifyApprovalToken(options: VerifyTokenOptions): TokenVerificationResult {
  const { token, secret: secretOrResolver, expectedRequestId, expectedApproverId, expectedCompanyId } = options;

  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'Missing or invalid token string' };
  }
  if (!secretOrResolver) {
    return { valid: false, error: 'Missing token signing secret or secret resolver' };
  }
  if (!expectedRequestId || typeof expectedRequestId !== 'string' || expectedRequestId.trim().length === 0) {
    return { valid: false, error: 'Missing required expectedRequestId for cryptographic binding verification' };
  }
  if (!expectedApproverId || typeof expectedApproverId !== 'string' || expectedApproverId.trim().length === 0) {
    return { valid: false, error: 'Missing required expectedApproverId for cryptographic binding verification' };
  }
  if (!expectedCompanyId || typeof expectedCompanyId !== 'string' || expectedCompanyId.trim().length === 0) {
    return { valid: false, error: 'Missing required expectedCompanyId for multi-tenant isolation verification' };
  }

  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { valid: false, error: 'Malformed token structure: expected payload.signature' };
  }

  const [payloadEncoded, signatureEncoded] = parts;

  // 1. Decode and strictly validate JSON payload structure and types
  let rawPayload: unknown;
  try {
    rawPayload = JSON.parse(fromBase64Url(payloadEncoded));
  } catch {
    return { valid: false, error: 'Corrupt token payload: invalid JSON encoding' };
  }

  if (!rawPayload || typeof rawPayload !== 'object' || Array.isArray(rawPayload)) {
    return { valid: false, error: 'Malformed token payload: expected JSON object' };
  }

  const p = rawPayload as Record<string, unknown>;

  if (typeof p.version !== 'number' || !Number.isInteger(p.version) || p.version < 1) {
    return { valid: false, error: 'Malformed token payload: invalid or missing version number' };
  }
  if (typeof p.kid !== 'string' || p.kid.trim().length === 0) {
    return { valid: false, error: 'Malformed token payload: invalid or missing kid string' };
  }
  if (typeof p.requestId !== 'string' || p.requestId.trim().length === 0) {
    return { valid: false, error: 'Malformed token payload: invalid or missing requestId string' };
  }
  if (typeof p.approverId !== 'string' || p.approverId.trim().length === 0) {
    return { valid: false, error: 'Malformed token payload: invalid or missing approverId string' };
  }
  if (typeof p.companyId !== 'string' || p.companyId.trim().length === 0) {
    return { valid: false, error: 'Malformed token payload: invalid or missing companyId string' };
  }
  if (typeof p.expiresAt !== 'number' || !Number.isFinite(p.expiresAt) || p.expiresAt <= 0) {
    return { valid: false, error: 'Malformed token payload: invalid or missing expiresAt timestamp' };
  }
  if (typeof p.nonce !== 'string' || p.nonce.trim().length === 0) {
    return { valid: false, error: 'Malformed token payload: invalid or missing nonce string' };
  }

  const payload: ApprovalTokenPayload = {
    version: p.version,
    kid: p.kid,
    requestId: p.requestId,
    approverId: p.approverId,
    companyId: p.companyId,
    expiresAt: p.expiresAt,
    nonce: p.nonce,
  };

  // 2. Resolve signing secret for the token's key id (kid)
  let signingSecret: string | undefined;
  if (typeof secretOrResolver === 'function') {
    signingSecret = secretOrResolver(payload.kid);
    if (!signingSecret) {
      return { valid: false, error: `Unknown or retired key id: ${payload.kid}` };
    }
  } else {
    signingSecret = secretOrResolver;
  }

  // 3. Optional expected kid check
  if (options.expectedKid && !constantTimeCompare(payload.kid, options.expectedKid)) {
    return { valid: false, error: `Token key id (${payload.kid}) does not match expected (${options.expectedKid})` };
  }

  // 4. Verify HMAC-SHA256 signature in constant-time
  const expectedSignature = createHmac('sha256', signingSecret)
    .update(payloadEncoded, 'utf8')
    .digest();
  const expectedSignatureEncoded = toBase64Url(expectedSignature);

  if (!constantTimeCompare(signatureEncoded, expectedSignatureEncoded)) {
    return { valid: false, error: 'Invalid token signature (tampering detected)' };
  }

  // 5. Verify expiration using injected clock or current system time
  const currentTime = getSecondsFromClock(options.clock);
  if (currentTime > payload.expiresAt) {
    return { valid: false, error: 'Approval token has expired (10-minute limit exceeded)' };
  }

  // 6. Verify cryptographic binding to requestId
  if (!constantTimeCompare(payload.requestId, expectedRequestId)) {
    return { valid: false, error: 'Token is not bound to the requested access request' };
  }

  // 7. Verify cryptographic binding to approverId
  if (!constantTimeCompare(payload.approverId, expectedApproverId)) {
    return { valid: false, error: 'Token is not bound to the designated approver' };
  }

  // 8. Verify multi-tenant isolation binding to companyId
  if (!constantTimeCompare(payload.companyId, expectedCompanyId)) {
    return { valid: false, error: 'Token is not bound to the designated company tenant' };
  }

  return {
    valid: true,
    payload,
  };
}
