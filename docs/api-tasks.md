# API Implementation Task List (Phase 1)
*Status: Active Engineering Task List*

---

## 1. Authentication, Tokens & Approval Workflows

- [ ] **[CRITICAL] Atomic Single-Use Approval Token Enforcement in DB Layer**
  - **Requirement**: Token verification (`verifyApprovalToken`) validates cryptographic signature, structure, non-expiration, and bindings (`requestId`, `approverId`, `companyId`). Single-use **must** be enforced atomically in PostgreSQL at consumption time.
  - **Implementation**:
    Execute an atomic conditional update inside the consumption transaction:
    ```sql
    UPDATE approval_tokens
    SET status = 'USED', used_at = NOW()
    WHERE token_hash = $1
      AND status = 'PENDING'
      AND expires_at > NOW()
    RETURNING id, request_id, approver_id, company_id;
    ```
    If zero rows are updated, the request must immediately fail with HTTP 409 Conflict / HTTP 410 Gone.
  - **Storage**: Never persist the plaintext token string; persist only `token_hash = SHA256(token)`.
  - **Key Rotation**: Use `kid` to look up the active or retired KMS secret during verification.

- [ ] **Access Request Approval Endpoint (`POST /api/v1/access-requests/:id/approve`)**
  - Verify token using `verifyApprovalToken({ token, secret, expectedRequestId, expectedApproverId, expectedCompanyId })`.
  - Atomically update token status to `USED` in PostgreSQL.
  - Create or extend domain rule with 10-minute / today duration scope.
  - Emit `access_approved` event envelope into the company's append-only audit hash chain.

- [ ] **Access Request Denial Endpoint (`POST /api/v1/access-requests/:id/deny`)**
  - Verify token and approver session.
  - Mark token status as `USED` or `REJECTED`.
  - Emit `access_denied` event envelope to the audit hash chain.

- [ ] **Admin Authentication & Session Management**
  - Mandatory MFA (TOTP / WebAuthn passkeys).
  - Short-lived JWT access tokens with rotating refresh tokens stored as Argon2id hashes.
  - Rate limiting on authentication endpoints (5 attempts per minute per IP).

---

## 2. Multi-Tenant Isolation & Data Layer

- [ ] **PostgreSQL Row-Level Security (RLS) Session Middleware**
  - Enforce `SET LOCAL app.current_company_id = '<company_id>'` on every connection checkout in the pool.
  - Verify that no query can bypass tenant boundaries.

- [ ] **Append-Only Audit Event Store**
  - Ensure the database application role has only `SELECT, INSERT` on the `events` table (`REVOKE UPDATE, DELETE`).
  - Maintain the per-company SHA-256 hash chain using `computeEventHash` with canonical JSON structured objects and genesis anchor verification.

---

## 3. Device Enrollment & Policy Delivery

- [ ] **Device Registration Endpoint (`POST /api/v1/devices/enroll`)**
  - Validate one-time enrollment code and company device quota.
  - Issue device bearer token; store only salted hash server-side.
  - Emit `device_enrolled` event into the audit hash chain.

- [ ] **Policy Distribution (`GET /api/v1/policies/current`)**
  - Authenticate device token via `Authorization: Bearer <token_hash>`.
  - Return compiled policy and active rules for the device group with immutable `policy_version`.

---

## 4. Operational Telemetry & Health

- [ ] **Heartbeat Ingestion (`POST /api/v1/devices/heartbeat`)**
  - Ingest 60s heartbeats.
  - Raise tamper/offline alerts if 2 consecutive heartbeats are missed (120s).
