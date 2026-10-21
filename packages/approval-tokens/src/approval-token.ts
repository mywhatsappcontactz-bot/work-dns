import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export interface ApprovalTokenPayload {
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
  durationMinutes?: number; // Defaults to 10 minutes (per spec)
}

export interface VerifyTokenOptions {
  token: string;
  secret: string;
  expectedRequestId?: string;
  expectedApproverId?: string;
  currentTimeSeconds?: number;
}

export interface TokenVerificationResult {
  valid: boolean;
  error?: string;
  payload?: ApprovalTokenPayload;
}

/**
 * Computes a SHA-256 hash of the token for secure persistence at rest.
 * The server never stores the raw token string in the database.
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
 * Generates a signed, single-use approval token cryptographically bound to request ID and approver.
 * Valid for 10 minutes by default.
 */
export function generateApprovalToken(options: GenerateTokenOptions): GeneratedApprovalToken {
  if (!options.secret || options.secret.length < 32) {
    throw new Error('Approval token secret must be at least 32 characters long');
  }

  const durationMinutes = options.durationMinutes ?? 10;
  const nowSeconds = Math.floor(Date.now() / 1000);
  const expiresAtSeconds = nowSeconds + durationMinutes * 60;

  const payload: ApprovalTokenPayload = {
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
 * Verifies the integrity, binding, and expiration of an approval token using constant-time comparison.
 */
export function verifyApprovalToken(options: VerifyTokenOptions): TokenVerificationResult {
  const { token, secret, expectedRequestId, expectedApproverId } = options;

  if (!token || !secret) {
    return { valid: false, error: 'Missing token or signing secret' };
  }

  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { valid: false, error: 'Malformed token structure' };
  }

  const [payloadEncoded, signatureEncoded] = parts;

  // 1. Recompute and verify HMAC signature in constant-time
  const expectedSignature = createHmac('sha256', secret)
    .update(payloadEncoded, 'utf8')
    .digest();
  const expectedSignatureEncoded = toBase64Url(expectedSignature);

  if (!constantTimeCompare(signatureEncoded, expectedSignatureEncoded)) {
    return { valid: false, error: 'Invalid token signature (tampering detected)' };
  }

  // 2. Decode and parse payload
  let payload: ApprovalTokenPayload;
  try {
    payload = JSON.parse(fromBase64Url(payloadEncoded)) as ApprovalTokenPayload;
  } catch {
    return { valid: false, error: 'Corrupt token payload JSON' };
  }

  // 3. Verify expiration
  const currentTime = options.currentTimeSeconds ?? Math.floor(Date.now() / 1000);
  if (currentTime > payload.expiresAt) {
    return { valid: false, error: 'Approval token has expired (10-minute limit exceeded)' };
  }

  // 4. Verify cryptographic binding to requestId
  if (expectedRequestId && !constantTimeCompare(payload.requestId, expectedRequestId)) {
    return { valid: false, error: 'Token is not bound to the requested access request' };
  }

  // 5. Verify cryptographic binding to approverId
  if (expectedApproverId && !constantTimeCompare(payload.approverId, expectedApproverId)) {
    return { valid: false, error: 'Token is not bound to the designated approver' };
  }

  return {
    valid: true,
    payload,
  };
}
