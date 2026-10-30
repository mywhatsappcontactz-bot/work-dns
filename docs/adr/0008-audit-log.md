# ADR 0008: Audit log design and evidence model

Status: Accepted for the local spike. The production design differs where noted.
Date: 2026-10-30

## Context

The product must answer two audit questions: what did a device try to reach and was it allowed, and was the device actually protected at that moment. A log is only useful if a reader can tell what was witnessed from what was merely claimed, and can detect tampering.

## Decisions

### 1. Two kinds of entries

- Witnessed: written by the gateway (dns_blocked). occurredAt is the gateway's write time.
- Device-reported: sent by the agent. Every payload carries `source: "device_reported"` and `deviceReportedAt`; occurredAt is still the server's time. A compromised device can lie or stay silent, so these are claims.

### 2. Append-only, hash-chained store

- One chain per company. Each entry's SHA-256 covers its canonical JSON (id, sequence number, type, schema version, company, device, occurredAt, payload, previous hash).
- The store assigns the sequence number and hash inside one transaction (BEGIN IMMEDIATE). Callers never supply them.
- SQLite triggers refuse updates, deletes, sequence gaps and a wrong previous hash. The file is mode 0600.
- Limit: anyone who can write the file can drop the triggers. The guarantee comes from verification and checkpoints, not from the triggers.
- Production: a backend assigns sequence numbers in PostgreSQL (docs/api-tasks.md). The gateway writing locally is a single-gateway stand-in.
- Chain order is write order, not event order. Readers must sort by firstSeenAt or deviceReportedAt.

### 3. Signed checkpoints

- Ed25519. A checkpoint holds company, sequence number, head hash, time, previous checkpoint hash, key id and signature.
- createCheckpoint refuses to sign a chain that fails verification or contradicts the previous checkpoint.
- verifyCheckpoints detects: deleted newest events, an edited event, a fully rewritten chain, a modified or forged checkpoint, an unknown key, and a removed middle checkpoint.
- Limit: removing the newest checkpoints is invisible without a copy kept outside the log writer's reach.
- Key custody is unsolved. Nothing signs checkpoints in the running system. A key kept beside the log defeats the purpose, and on a laptop the administrator can reach any local key.
- Production: a KMS-held key and checkpoint copies in S3 with Object Lock in compliance mode.

### 4. Device event endpoint

POST /api/v1/agent-events on the gateway.
- Identity (company and device) comes from the authenticated token, never from the body.
- Stored id is deviceId:clientId, so devices cannot collide with or pre-claim each other's ids. A retried batch is counted as duplicates.
- Allow-list of eight types: agent_started, agent_stopped, enforcement_applied, enforcement_reset, enforcement_restored, fail_open_entered, fail_open_exited, offline_query. Every other type is refused (dns_blocked, policy and admin events included).
- Unknown fields are refused, and a whole batch is validated before anything is written.
- Limits: 64 KiB body, 50 events per request, deviceReportedAt at most 5 minutes ahead and 30 days old. Answers 503 when the audit log is disabled.

### 5. Agent delivery

- AgentOutbox: a durable, owner-only, bounded file (5000 events). An event is written before any send attempt and removed only after the gateway confirms it.
- AgentEventSender: an event counts as delivered only when the gateway returns JSON whose accepted plus duplicates equals the batch size. A captive portal's 200 or 400 HTML page is not a receipt.
- An event the gateway names as invalid moves to a quarantine file with the reason. It is never dropped silently and never retried forever.
- Backoff from 1 s doubling to 60 s with jitter. The token goes only to the configured gateway origin (https, or http on loopback), and redirects are refused.
- One last delivery attempt of at most 5 seconds at shutdown, after DNS has been restored.
- Reporting failures are logged and never break enforcement or shutdown.

### 6. Volume: roll-up of repeats

- The first attempt at a domain is written at once. Repeats inside the window (default 300 s, GATEWAY_ROLLUP_WINDOW_SECONDS) become one entry with `rollup: true`, a count, the first and last repeat times and the window bounds.
- A window is keyed by company, device, domain, reason, policy version and user. Its entry id is `rollup:` plus the first entry's id, so a retry cannot duplicate it.
- A retried batch is not counted twice. A failed roll-up write keeps its counts and retries on the next sweep. Shutdown writes open windows. Beyond 10000 open windows, new attempts are written in full.
- Limit: repeat counts held in memory are lost if the gateway crashes. The first sighting is already stored.
- Allowed queries are not logged. The type dns_allowed_summary exists but nothing emits it.

### 7. Reports

- Integrity has three states. VERIFIED: the chain and signed checkpoints are valid and nothing is newer than the last checkpoint. PARTIAL: nothing contradicts the log but something is unprotected, and the caveats say what. FAILED: tampering was detected.
- Reports always list caveats, such as entries with no verified user. CSV export guards against spreadsheet formula injection. The CLI exits 0, 1 or 2 for the three states.

## Verified live (Phase 0 laptop)

- Blocked attempts written by the running gateway into the store; the chain verified.
- Five requests to the device endpoint (valid batch, retry, forbidden type, a body claiming another company, no token) behaved as designed.
- Three devices (two in one company, one in another) sent the same event id; the entries stayed separate under each token's identity.
- A real agent against the real gateway produced agent_started, enforcement_applied, enforcement_reset (forced wifi reconnect), enforcement_restored and agent_stopped. The outbox was empty afterwards and no quarantine file existed.
- Roll-up: 21 requests over 40 seconds with a 20 second window produced 5 entries whose counts summed to exactly the 21 sent.
- An edited copy and a truncated copy of a log were reported FAILED (exit code 2).

## Not verified, and known gaps

- loggedOsUser is "unknown" on every entry, and agent events carry policyVersion 0 (not reported). Entries identify a device, not a person.
- Nothing emits heartbeat_missed, auth_rejected, device_revoked, dns_allowed_summary or retention_expired, and there is no event for crash recovery or for recovery from fail-closed.
- The missed-heartbeat watcher, the only server-side way to notice a silent or tampered agent, is not built.
- No process signs checkpoints, and key custody is undecided.
- Reset events under-report the gap: detectedAt is when the watcher noticed it.
- Stopping the gateway with a roll-up window still open is covered by a unit test only, not by a live run.
- When agent and gateway share a laptop, the gateway's lookup of its own upstream hostname is blocked by the enforcement. Use an IP-based upstream.
- A device with a wrong clock has its events quarantined by the time bounds.
- Production needs TLS, a PostgreSQL backend, a retention period with a data-protection review, and a Windows agent. None of these exists.
- The systemd service in /opt/work-dns runs an older build.
- Privacy: blocked-domain entries record browsing. Only domains are stored, never URLs, and retention must be bounded.
