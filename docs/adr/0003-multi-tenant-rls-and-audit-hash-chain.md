# ADR 0003: Multi-Tenant PostgreSQL Row-Level Security & Tamper-Evident Hash Chain

## Status
Accepted

## Context
In a multi-tenant platform serving sensitive corporate client DNS queries and audit logs, data isolation cannot rely solely on application developers remembering `WHERE company_id = ?` in every ORM or SQL query. Furthermore, audit logs must be defensible in legal and HR dispute scenarios, meaning they must be provably tamper-evident.

## Decision
1. **Engine-Level PostgreSQL Row-Level Security (RLS)**:
   - Every tenant table has RLS enabled (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY`).
   - Tenant isolation policies enforce: `USING (company_id = NULLIF(current_setting('app.current_company_id', true), '')::uuid)`.
   - The application database connection pool sets the session context on every transaction before executing queries: `SET LOCAL app.current_company_id = '<tenant_uuid>'`.
2. **Append-Only Permissions**:
   - The application database role is explicitly granted only `SELECT, INSERT` on the `events` table. `UPDATE` and `DELETE` permissions are revoked.
3. **Per-Tenant SHA-256 Hash Chain**:
   - Every audit event row includes: `id`, `company_id`, `occurred_at`, `payload`, `prev_hash`, `hash`.
   - `hash = SHA256(canonical_json({ id, prevHash, occurredAt, type, schemaVersion, companyId, deviceId, payload }))`.
   - Structured canonical JSON eliminates delimiter injection vulnerabilities and binds event `id` directly into the hash.
   - A corrupt or modified record breaks the chain, rendering tampering immediately detectable.
   - Periodic head hashes are exported and anchored to write-once storage (e.g. S3 Object Lock).

## Consequences
- **Pros**: Zero possibility of accidental cross-tenant data leaks due to missed application filters; mathematically verifiable audit trail.
- **Cons**: Every database transaction must establish the tenant context; hash chain generation requires sequential ordering per company during event commitment.
