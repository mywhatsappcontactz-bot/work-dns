# ADR 0006: Cryptographic Approval Tokens with Cryptographic Binding & Constant-Time Verification

## Status
Accepted

## Context
Admins receive single-use approval links (e.g. via email) allowing one-click authorization of blocked domains for 10 minutes. If approval links are predictable, reusable, or vulnerable to timing attacks, an attacker could forge approvals or replay expired tokens.

## Decision
1. **Token Cryptographic Binding**:
   - The token contains: `payload = { requestId, approverId, companyId, expiresAt, nonce }`.
   - The token signature is generated using HMAC-SHA256 with a KMS-derived secret: `signature = HMAC_SHA256(secret, canonicalString(payload))`.
   - The full token string sent in the URL is: `base64url(payload) + "." + base64url(signature)`.
2. **Server-Side Persistence**:
   - The raw token is **never stored** in the database.
   - Only a cryptographic hash (`token_hash = SHA256(token)`) is stored in the database alongside `requestId`, `status` (`PENDING | USED | EXPIRED`), and `expires_at`.
3. **Verification Guarantees**:
   - **Constant-Time Comparison**: Token signature and hash comparisons strictly use `crypto.timingSafeEqual` to eliminate timing side-channel attacks.
   - **10-Minute Expiry**: Tokens older than 10 minutes (`now > expiresAt`) are rejected immediately.
   - **Single-Use Enforcement**: Verified within an atomic database transaction. Once used, the status is immediately updated to `USED`.
   - **Step-Up for Permanent Scope**: One-click email approval grants temporary access (today only). Permanent allowlist exceptions require step-up login to the admin dashboard.

## Consequences
- **Pros**: Leakage of the database does not reveal valid approval tokens; immune to replay and timing attacks; strictly bounded exposure.
- **Cons**: 10-minute expiry requires rapid admin action (dashboard remains fallback for pending requests).
