# ADR 0006: Cryptographic Approval Tokens with Cryptographic Binding & Constant-Time Verification

## Status
Accepted (Updated with Key Rotation & Atomic DB Single-Use Specification)

## Context
Admins receive single-use approval links (e.g. via email) allowing one-click authorization of blocked domains for 10 minutes. If approval links are predictable, reusable, or vulnerable to timing attacks, an attacker could forge approvals or replay expired tokens.

## Decision
1. **Token Cryptographic Binding & Key Rotation**:
   - The token contains: `payload = { version: 1, kid: string, requestId: string, approverId: string, companyId: string, expiresAt: number, nonce: string }`.
   - `version` ensures forward compatibility as token formats evolve.
   - `kid` (Key ID) allows seamless rotation of HMAC-SHA256 secrets without invalidating in-flight tokens.
   - The token signature is generated using HMAC-SHA256 with a KMS-derived secret: `signature = HMAC_SHA256(secretForKid, base64url(canonicalString(payload)))`.
   - The full token string sent in the URL is: `base64url(payload) + "." + base64url(signature)`.
2. **Server-Side Persistence**:
   - The raw token is **never stored** in the database.
   - Only a cryptographic hash (`token_hash = SHA256(token)`) is stored in the database alongside `requestId`, `approverId`, `companyId`, `status` (`PENDING | USED | EXPIRED`), and `expires_at`.
3. **Verification Guarantees**:
   - **Mandatory Bindings**: `expectedRequestId`, `expectedApproverId`, and `expectedCompanyId` are strictly required and verified in constant-time.
   - **Payload Type & Schema Validation**: Strict runtime schema validation is executed post-decoding; any malformed, extra-type, or corrupted payloads are rejected.
   - **Constant-Time Comparison**: Token signature and binding comparisons strictly use `crypto.timingSafeEqual` (`constantTimeCompare`) to eliminate timing side-channel attacks.
   - **10-Minute Expiry & Clock Injection**: Tokens older than 10 minutes (`now > expiresAt`) are rejected immediately. Verification accepts an injected `clock` function for deterministic time control in tests and operational environments without leaking mutable timestamps into the production signature.
   - **Atomic Single-Use Enforcement in Database Layer**:
     Token verification is stateless and verifies cryptographic integrity and binding. Single-use **must** be enforced atomically in the PostgreSQL database layer using conditional row-level updates:
     ```sql
     UPDATE approval_tokens
     SET status = 'USED', used_at = NOW()
     WHERE token_hash = $1
       AND status = 'PENDING'
       AND expires_at > NOW()
     RETURNING id, request_id, approver_id, company_id;
     ```
     If zero rows are returned, the transaction rolls back and the operation is rejected.
   - **Step-Up for Permanent Scope**: One-click email approval grants temporary access (today only). Permanent allowlist exceptions require step-up login to the admin dashboard.

## Consequences
- **Pros**: Leakage of the database does not reveal valid approval tokens; immune to replay, token swapping, and timing attacks; strictly bounded 10-minute exposure; rotation supported via `kid`.
- **Cons**: 10-minute expiry requires rapid admin action (dashboard remains fallback for pending requests); database layer must handle conditional atomic consumption.
