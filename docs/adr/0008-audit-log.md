# ADR 0008: Audit log design and evidence model

Status: Accepted for the local spike. The production design differs where noted.
Date: 2026-10-30
Updated: heartbeat watcher (2026-11-01); console user attribution; systemd service verified (2026-11-09)

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

- The first attempt at a domain is written within the queue's 5 second flush (measured live: about 5 seconds). Repeats inside the window (default 300 s, GATEWAY_ROLLUP_WINDOW_SECONDS) become one entry with `rollup: true`, a count, the first and last repeat times and the window bounds.
- A window is keyed by company, device, domain, reason, policy version and user. Its entry id is `rollup:` plus the first entry's id, so a retry cannot duplicate it.
- A retried batch is not counted twice. A failed roll-up write keeps its counts and retries on the next sweep. Shutdown writes open windows. Beyond 10000 open windows, new attempts are written in full.
- Limit: repeat counts held in memory are lost if the gateway crashes. The first sighting is already stored.
- Allowed queries are not logged. The type dns_allowed_summary exists but nothing emits it.

### 7. Reports

- Integrity has three states. VERIFIED: the chain and signed checkpoints are valid and nothing is newer than the last checkpoint. PARTIAL: nothing contradicts the log but something is unprotected, and the caveats say what. FAILED: tampering was detected.
- Reports always list caveats, such as entries with no verified user. CSV export guards against spreadsheet formula injection. The CLI exits 0, 1 or 2 for the three states.

### 8. Heartbeat watcher

- The gateway records the time of every authenticated request (DNS queries and device events), per company and device. An active device that is silent for longer than the threshold (default 300 s, GATEWAY_HEARTBEAT_THRESHOLD_SECONDS) gets one heartbeat_missed entry per outage. When it is heard from again, one heartbeat_resumed entry records the gap.
- Both entries are witnessed: the gateway observed the silence. Entry ids include company, device and outage start, so a retried write cannot duplicate them.
- The hook runs only after a valid token check, so a request without a token cannot make a silent device look alive. A failing hook is logged and never affects the request.
- At gateway start every active device counts as seen now, so a device that never returns is still reported one threshold later. Both payloads carry lastSeenSource ("request" or "gateway_start"), so a reader can tell a real last sighting from the gateway's own start time.
- stop() writes nothing, so gateway downtime is never blamed on devices. Only active devices are tracked, capped at 10000. A failed write is logged and retried on the next sweep.
- Limits are listed under "Not verified".

### 9. Console user attribution

- The agent asks systemd-logind for the active local session on seat0 (every 5 seconds, cached, no shell). Only a session of class user that is local, active and in state active counts. A login screen, an SSH session, a failed lookup or an odd-looking name gives "unknown".
- The name travels in the X-Work-Dns-User header to the configured gateway only, never to the fallback resolver. The agent and the gateway each validate it (a plain username of up to 64 characters), and a repeated header is ignored.
- The gateway stores it in loggedOsUser with loggedOsUserSource "device_reported". The name is part of the queue's merge key and of the roll-up window key, so attempts under different names are never merged.
- It names the person at the console, not the program that made the request. Background programs and system checks are recorded under the same name, and the gateway cannot verify it: a holder of a device token can claim any name. Reports count these entries separately (claimedUserBlocks), print a caveat, and the CSV export has a loggedOsUserSource column.
- Privacy: a name next to blocked domains is personal data. The header is plain text over loopback in the spike, so production needs TLS and a bounded retention period.

## Verified live (Phase 0 laptop)

- Blocked attempts written by the running gateway into the store; the chain verified.
- Five requests to the device endpoint (valid batch, retry, forbidden type, a body claiming another company, no token) behaved as designed.
- Three devices (two in one company, one in another) sent the same event id; the entries stayed separate under each token's identity.
- A real agent against the real gateway produced agent_started, enforcement_applied, enforcement_reset (forced wifi reconnect), enforcement_restored and agent_stopped. The outbox was empty afterwards and no quarantine file existed.
- Roll-up: 21 requests over 40 seconds with a 20 second window produced 5 entries whose counts summed to exactly the 21 sent.
- An edited copy and a truncated copy of a log were reported FAILED (exit code 2).
- Heartbeat watcher, scripted run with a 10 second threshold: three queries, 25 seconds of silence, one more query. Exactly one heartbeat_missed (written 11 seconds after the last request) and one heartbeat_resumed (gap 27 seconds). No false entry at startup and none for a device when the gateway stopped.
- Stopping the gateway with a roll-up window still open wrote the pending roll-up before the store closed (same scripted run).
- Console user attribution, unattended run with the real agent and gateway on the laptop: blocked entries carried user "berlin" with source "device_reported" (69 attempts, of which the test caused 12; the rest were background lookups), one entry was recorded as "unknown" without a marker, the outbox was empty with no quarantine file, the chain verified, and resolv.conf was back on the router afterwards.
- The real systemd service (build 8c979b0, account work-dns) against a local gateway with an IP-based upstream: it enforced DNS, blocked entries named the console user (so loginctl works inside the unit), agent_started and enforcement_applied reached the log, and the outbox was empty. After kill -9 on the service, ExecStopPost restored DNS by itself (state failed, result signal) and lookups worked again.

## Not verified, and known gaps

- User names are claims, not proof: the console user is recorded for every program that runs while that person is logged in. The real loginctl call was verified from a shell and inside the current systemd unit (which has only light hardening: no filesystem sandboxing), so any hardening added later must be re-tested. Switching between two console users was not run live (a unit test keeps them apart). One entry in the live run was recorded as "unknown", probably the agent's startup probe, which was not confirmed. Agent events still carry policyVersion 0, and agent_started says "unknown".
- Nothing emits auth_rejected, device_revoked, dns_allowed_summary or retention_expired, and there is no event for crash recovery or for recovery from fail-closed.
- The heartbeat watcher uses any authenticated request as its sign of life; the agent sends no dedicated heartbeat. An idle but healthy laptop can raise a false alarm, and silence cannot tell a killed agent from a closed lid. Read heartbeat entries together with agent_stopped and fail-open entries.
- No process signs checkpoints, and key custody is undecided.
- Reset events under-report the gap: detectedAt is when the watcher noticed it.
- Heartbeat state lives in memory: after a gateway restart a long outage can be reported twice (lastSeenSource says when lastSeenAt is the gateway's start). Behavior with many devices and real sleep patterns is untested.
- When agent and gateway share a laptop, the gateway's lookup of its own upstream hostname is blocked by the enforcement. Use an IP-based upstream.
- A device with a wrong clock has its events quarantined by the time bounds.
- Production needs TLS, a PostgreSQL backend, a retention period with a data-protection review, and a Windows agent. None of these exists.
- The systemd service runs a snapshot copy in /opt/work-dns, refreshed by hand with scripts/deploy-local.sh (last deployed: commit 8c979b0). There is no automatic deploy and no signed release.
- A crash writes no event: ExecStopPost restores DNS but records nothing, so the log shows enforcement_applied with no matching end. Only a missed heartbeat could hint at it, and only while the gateway is up.
- The gateway itself still runs from a terminal as the administrator, not as a service under its own account, so the audit database is owned by the person being audited.
- Privacy: blocked-domain entries record browsing. Only domains are stored, never URLs, and retention must be bounded.
