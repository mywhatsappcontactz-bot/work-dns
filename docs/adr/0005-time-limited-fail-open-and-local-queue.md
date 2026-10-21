# ADR 0005: Time-Limited Fail-Open with Local Write-Ahead Event Queue

## Status
Accepted

## Context
If the DoH gateway is temporarily unreachable (e.g. transient cellular/ISP routing failure in Nigeria), an unconditional fail-closed policy immediately breaks all internet access for front-desk staff, causing extreme operational disruption. However, an indefinite fail-open allows employees to bypass filtering by simply interfering with the gateway connection.

## Decision
1. **Time-Limited Fail-Open**:
   - When the gateway is detected as unreachable, the agent enters a `FAIL_OPEN_ACTIVE` state, temporarily falling back to standard upstream resolvers (or cached records).
   - Fail-open is strictly bounded by a configurable per-company timeout (default: 15 minutes max per day/session).
   - If the timeout expires without gateway restoration, the agent transitions to fail-closed, preserving corporate policy.
2. **Local Write-Ahead Event Queue**:
   - While in fail-open or offline status, the agent continues intercepting queries.
   - All query attempts and a `gateway_unreachable` tamper event are persisted into a local durable write-ahead queue (file-backed or SQLite).
   - When connection to the DoH gateway is re-established, the agent immediately flushes the queued audit events to the backend API.
3. **Gateway Certificate Pinning**:
   - The agent embeds or securely pins the gateway public certificate / CA fingerprint to protect against upstream TLS interception or spoofed gateways.

## Consequences
- **Pros**: Prevents business downtime during minor blips while eliminating blind spots in audit logging.
- **Cons**: Requires local disk storage management and replay deduplication on the server.
