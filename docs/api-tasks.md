# API Implementation Task List (Phase 1)
*Status: Active Engineering Task List*

---

## 1. Authentication, Tokens & Approval Workflows

- [ ] **[CRITICAL] Two-Step Approval Flow: GET Confirmation Page + POST Execution**
  - **Email Scanner Mitigation**: Enterprise email security scanners (e.g. Microsoft Defender Safe Links, Proofpoint, Google Workspace) automatically issue HTTP `GET` requests to prefetch and inspect every URL in incoming emails.
  - **Flow Requirement**:
    - Email links must point to `GET /approve/:token`, which renders a read-only confirmation page displaying the request metadata (domain, requesting device/user, reason, 10-minute validity window).
    - The actual approval action must strictly be triggered by an explicit user gesture issuing a `POST /api/v1/access-requests/:id/approve` carrying the approval token in the request body or authorization header.
    - `GET` endpoints must NEVER mutate token state or grant network access.

- [ ] **[CRITICAL] Atomic Single-Use Token Consumption in PostgreSQL**
  - **Requirement**: Token verification (`verifyApprovalToken`) validates cryptographic signature, structure, non-expiration, and bindings (`requestId`, `approverId`, `companyId`). Single-use **must** be enforced atomically in PostgreSQL at consumption time inside an ACID transaction.
  - **SQL Query**:
    ```sql
    UPDATE approval_tokens
    SET status = 'USED', used_at = NOW()
    WHERE token_hash = $1
      AND request_id = $2
      AND approver_id = $3
      AND company_id = $4
      AND status = 'PENDING'
      AND expires_at > NOW()
    RETURNING id, request_id, approver_id, company_id;
    ```
    If zero rows are updated, the transaction must roll back and reject the request.
  - **Storage**: Plaintext tokens are NEVER persisted; only `token_hash = SHA256(token)` is stored.
  - **Key Rotation**: Use token `kid` to look up the active or retired KMS secret during verification.
  - **Generic Client Errors**: Client-facing responses must return uniform generic errors (e.g. HTTP 400 with message `"Invalid or expired approval request"`). Detailed diagnostic reasons (mismatched approver, already used, expired) must be logged internally only to prevent token enumeration, timing leakage, or data probing.

- [ ] **Access Request Denial Endpoint (`POST /api/v1/access-requests/:id/deny`)**
  - Verify token and approver session.
  - Mark token status as `USED` or `REJECTED`.
  - Emit `access_denied` event envelope to the audit hash chain.

- [ ] **Admin Authentication & Session Management**
  - Mandatory MFA (TOTP / WebAuthn passkeys).
  - Short-lived JWT access tokens with rotating refresh tokens stored as Argon2id hashes.
  - Rate limiting on authentication endpoints (5 attempts per minute per IP).

---

## 2. Multi-Tenant Isolation & Tamper-Evident Event Store

- [ ] **[CRITICAL] Per-Company Monotonic Event Sequence Numbers & Locking**
  - **Schema Requirement**: The `events` table must enforce a unique composite index:
    ```sql
    CREATE UNIQUE INDEX uq_events_company_seq ON events (company_id, sequence_number);
    ```
  - **Concurrency & Locking Requirement**:
    - Appending an event to a company's audit chain requires an explicit row-level lock on the tenant row to serialize sequence generation and hash chaining without race conditions or sequence gaps:
      ```sql
      SELECT id FROM companies WHERE id = $1 FOR UPDATE;
      ```
    - The next sequence number is strictly `COALESCE(MAX(sequence_number), 0) + 1` for that `company_id`.
    - Every event binds `sequenceNumber` into its canonical SHA-256 hash envelope. Gaps, duplicates, or regressions break `verifyEventChain`.

- [ ] **PostgreSQL Row-Level Security (RLS) Session Middleware**
  - Enforce `SET LOCAL app.current_company_id = '<company_id>'` on every connection checkout in the pool.
  - Verify that no query can bypass tenant boundaries.

- [ ] **Append-Only Audit Event Store**
  - Ensure the database application role has only `SELECT, INSERT` on the `events` table (`REVOKE UPDATE, DELETE`).
  - Maintain the per-company SHA-256 hash chain using `computeEventHash` with canonical JSON structured objects, monotonic sequence numbers, and genesis anchor verification.

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

## Audit event delivery (open)
- The gateway produces plain blocked-attempt records only (apps/gateway/src/event-queue.ts). It has NO sink wired yet, so blocked attempts are held in memory and dropped when the queue is full. The audit log does not work end to end until a sink posts batches to the backend API.
- Sequence numbers and hash-chain fields must be assigned by the backend inside one database transaction per company (never in a gateway process: they reset on restart and fork across instances).
- The backend must accept batches idempotently (records carry unique ids) and apply authentication and rate limits to the ingestion endpoint.
