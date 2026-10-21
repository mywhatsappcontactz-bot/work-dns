# Threat Model: Work-Only DNS Enforcement & Audit Platform
*Version 0.1 · Status: Active Architectural Document*

---

## 1. Overview & Methodology

This threat model identifies high-value assets, untrusted threat actors, attack vectors, and architectural mitigations for the Work-Only DNS Enforcement and Defensible Audit Platform. Security is treated as an operational requirement enforced from day one across single-tenant, multi-tenant, agent, and gateway boundaries.

---

## 2. Key Assets & Sensitivity

| Asset | Sensitivity | Impact of Compromise | Primary Protection |
| :--- | :--- | :--- | :--- |
| **Device Tokens** | High (Bearer Secret) | Attacker can spoof device queries, manipulate audit entries, or bypass device-level quotas. | Stored as salted hashes server-side (Argon2id/SHA-256). Instant revocation. Future: per-device asymmetric key pairs (TPM/DPAPI). |
| **Enrollment Codes** | High (Bootstrap Secret) | Unauthorized device registration under tenant company quota. | Rate-limited, max-device limits, time-bounded expiration, revocable, scoped to specific tenant. |
| **Policies & Rules** | High (Integrity) | Unauthorized allowlisting of arbitrary domains (exfiltration / unrestricted browsing). | Immutable `policy_version` numbering. Step-up authorization for permanent changes. Cryptographic audit trail. |
| **Audit Logs** | Critical (Tamper-Evidence) | Inability to defend HR/legal disputes, loss of compliance integrity. | PostgreSQL Row-Level Security (RLS), append-only permissions (`REVOKE UPDATE, DELETE ON events`), per-company SHA-256 hash chain, external write-once anchoring (S3 Object Lock). |
| **Admin Accounts** | Critical (Tenant Control) | Hostile policy rewrite, bulk data exfiltration, employee tracking. | Mandatory MFA (WebAuthn/Passkeys, TOTP), Argon2id passwords, short-lived JWT sessions with refresh rotation, account lockout on brute force. |
| **Operator Accounts** | Critical (System-Wide) | Cross-tenant data breach, global policy alteration. | Multi-party authorization, mandatory MFA, zero standing customer data access. Just-In-Time (JIT) scoped sessions with audit logs visible in customer dashboard. |
| **Signing & Approval Keys** | Critical (Integrity) | Forgery of 10-minute access approval tokens or malicious config distribution. | HMAC-SHA256 secrets held in KMS/Parameter Store with envelope encryption. Tokens bound to `requestId` and `approverId`, constant-time comparison, token hash-only persistence. |

---

## 3. Threat Actors & Attacker Profiles

### 3.1 Curious or Evasive Staff (Local Device User)
* **Profile**: Employee attempting to access restricted entertainment/social domains, or disable agent enforcement.
* **Capabilities**: Local administrative rights (some hotel PCs), browser configuration access, network adapter settings.
* **Threat Vectors**:
  * Modifying DNS settings on network adapter back to `8.8.8.8` or DHCP.
  * Disabling the agent system service or terminating the process.
  * Enabling DoH in Chrome/Firefox/Edge to bypass loopback port 53.
  * Attempting to replay or steal local device tokens.
* **Mitigations**:
  * Agent binds exclusively to `127.0.0.1:53` (loopback only).
  * 5-minute periodic re-assertion of DNS adapter settings + hooks on network change/wake.
  * Browser enterprise policies (GPO / registry / managed preferences) deployed to disable browser DoH.
  * Missing heartbeat tamper alerts raised within 2 missed intervals (120s).
  * Device token protected by machine-scoped permissions (DPAPI on Windows, root-only `0600` on Linux).
  * Fail-open is strictly time-limited and locally audited in an encrypted write-ahead log.

### 3.2 Malicious or Compromised Admin
* **Profile**: Rogue internal company admin or an attacker who acquired company admin credentials.
* **Capabilities**: Can modify tenant policies, approve access requests, view audit logs.
* **Threat Vectors**:
  * Secretly allowlisting exfiltration domains.
  * Retroactively deleting or altering audit records to conceal wrongful termination or misconduct.
  * Rubber-stamping unauthorized domain exceptions.
* **Mitigations**:
  * Every policy change creates an immutable `policy_version` linked to the admin's identity.
  * All access approvals require step-up confirmation for permanent scope.
  * Database role denies `UPDATE` and `DELETE` on the `events` table.
  * Weekly exception summary reports emailed to designated company directors to expose rubber-stamping.

### 3.3 External Attacker (Internet / Network)
* **Profile**: Remote unauthenticated attacker probing public endpoints.
* **Capabilities**: Sending arbitrary payloads to public HTTPS endpoints (`/dns-query`, `/api/v1/*`, `/approve/:token`).
* **Threat Vectors**:
  * DNS amplification using an open resolver.
  * DoS / resource exhaustion on DoH endpoint.
  * Malformed DNS packet attacks (buffer overflow / parser panic).
  * Brute-forcing approval tokens or enrollment codes.
* **Mitigations**:
  * **No public port 53**: Only HTTPS (443) is exposed.
  * RFC 8484 DoH endpoint mandates valid `Authorization: Bearer <device_token>`; unauthenticated requests are discarded.
  * Strict packet parsing bounds and strict size limits (`MAX_DNS_PACKET_SIZE = 4096`).
  * Per-device rate limiting (token bucket on gateway).
  * Approval tokens: 256-bit cryptographically secure entropy, signed HMAC, 10-minute expiry, constant-time compare (`crypto.timingSafeEqual`), rate-limited endpoint.

### 3.4 Compromised Operator (Platform Insider)
* **Profile**: Rogue platform employee or compromised master operator credentials.
* **Threat Vectors**:
  * Snooping on tenant browsing trends.
  * Modifying tenant rules out-of-band.
* **Mitigations**:
  * Zero standing access: Operator access to tenant data requires explicit JIT justification.
  * Every operator action generates an immutable `operator_access` audit event visible in the customer admin's dashboard.
  * KMS envelope encryption of tenant-specific secrets.

### 3.5 Cross-Tenant Contamination (Tenant-to-Tenant)
* **Profile**: Company A admin or employee attempting to view or alter Company B records.
* **Threat Vectors**:
  * IDOR (Insecure Direct Object Reference) on API endpoints.
  * Missing `company_id` filter in ORM / SQL query.
  * Cross-tenant cache poisoning in DoH gateway memory.
* **Mitigations**:
  * **PostgreSQL Row-Level Security (RLS)**: Enforced directly at the database engine level using session variables (`SET LOCAL app.current_company_id = '...'`).
  * Application-layer tenant scoping middleware on every Prisma transaction.
  * Automated adversarial tests in CI explicitly asserting that Company A tokens cannot read or write Company B resources.
  * Gateway in-memory policy cache strictly keyed by `company_id`.

---

## 4. Threat Matrix & Architecture Verification

| ID | Threat Vector | Target Component | Mitigations Implemented | Test Verification |
| :--- | :--- | :--- | :--- | :--- |
| **T-01** | Open Resolver Exploitation | Gateway | Reject all queries without valid Bearer token; no public UDP/TCP 53. | Gateway auth test rejects unsigned packets. |
| **T-02** | Cross-Tenant Data Leak | Backend API & DB | PostgreSQL RLS + tenant-scoped Prisma client. | Automated cross-tenant penetration unit tests. |
| **T-03** | Approval Link Forgery | Access Approval | HMAC-SHA256, bound to `requestId` + `approverId`, 10-minute expiry, hash-only persistence. | Approval token test suite with signature tampering & expiry tests. |
| **T-04** | Audit Log Repudiation | Events / Audit Store | Cryptographic hash chain (`prev_hash`), DB role denies `UPDATE`/`DELETE`. | Hash chain integrity test verifies tamper detection. |
| **T-05** | Local DNS Bypass | Device Agent | Re-assert loopback 127.0.0.1 every 5m; enterprise policies to disable browser DoH. | Platform adapter adapter-reassertion tests. |
| **T-06** | Parser Crash / Fuzzing | Gateway DNS Parser | Strict RFC 1035 / RFC 8484 bounds checking, safe error handlers, no unhandled exceptions. | Parser boundary fuzz & oversized payload tests. |

---

## 5. Security Maintenance & Cadence

1. This threat model is reviewed whenever a new module or protocol is introduced.
2. Changes to authentication, token formats, or gateway packet processing require an updated ADR and security review.
3. Automated security tests run on every commit in CI prior to merge.
