# ADR 0007: DNS enforcement and revert (Linux)

Status: Proposed
Date: 2026-10-23

## Context

The agent must force all DNS lookups on a device through the local stub (127.0.0.1) and must always be able to undo that.

Observed on the Phase 0 laptop (Arch, wifi connection "Airtel_X25A_4650", device wlp58s0):

- systemd-resolved is not running. NetworkManager is active and generates /etc/resolv.conf, so hand edits would be overwritten.
- Before enforcement, resolv.conf listed the router (192.168.1.1) and 114.114.114.114, a public resolver sent in plain text.
- The saved profile uses defaults: ipv4.dns and ipv6.dns empty, ipv4.ignore-auto-dns no, ipv6.ignore-auto-dns no.
- `nmcli device modify` changes the live device without a password prompt, and resolv.conf follows immediately.
- `nmcli device reapply` does NOT undo a modify. It re-applies the modified settings.
- Reverting worked with: `nmcli device modify wlp58s0 ipv4.dns "" ipv4.ignore-auto-dns no ipv6.ignore-auto-dns no`.
- NetworkManager takes DNS servers as IP addresses only, with no port. The stub must therefore listen on port 53.
- Nothing listens on port 53. net.ipv4.ip_unprivileged_port_start is 1024, so an unprivileged process cannot bind it.

## Decision

1. Method: runtime-only `nmcli device modify` on the active device. Nothing is written to the saved profile, so a reboot also clears it.
2. Enforce: set ipv4.dns 127.0.0.1, clear ipv6.dns, and set ipv4/ipv6.ignore-auto-dns yes. IPv6 DNS is cleared, not pointed at ::1, because the stub's IPv6 listening is unverified. This still blocks the router's IPv6 resolver.
3. Backup: before enforcing, record the device's current ipv4.dns, ipv6.dns and both ignore-auto-dns values to a file. Restore writes those values back and deletes the file only after every device restored. An existing backup is never overwritten, because a second capture would save the enforced values as the originals. Spike: ~/.config/work-dns/dns-backup.json, mode 0600. Production must use a root-owned path.
4. Device: detect the active devices with nmcli at run time. Never hard-code wlp58s0.
5. Crash safety: restore must not depend on the agent staying alive. The systemd unit runs the restore in ExecStopPost, which systemd runs after a crash or kill.
6. Port 53: the unit grants AmbientCapabilities=CAP_NET_BIND_SERVICE. The agent does not run as root.
7. Fail-open: if restore itself fails, log it loudly and keep retrying. Never leave a device pointing at a dead stub silently.

## Consequences

- A stuck state is recoverable by reboot, and by running the restore command above.
- The agent must re-apply enforcement if NetworkManager resets the device settings.

## Open questions (untested)

- Does a roam or sleep/wake also drop the runtime settings? A manual reconnect did (see Findings). Other kinds are untested.
- Can a firewall rule (block outbound port 53 except from the stub) close the leak window during reconnects? Not tried.
- Can the stub listen on ::1, so IPv6 DNS can point at it instead of being cleared? Not checked.
- Does `nmcli connection up` also undo a modify? Not tested.
- Behavior with several active devices (ethernet plus wifi), VPN clients, and captive portals.
- Whether ExecStopPost runs reliably on SIGKILL and on out-of-memory kills. Test it.
- Applications that do their own DoH (browsers) bypass system DNS. Out of scope here.

## Implementation status

- Implemented in LinuxPlatformAdapter (setDnsLoopback, restoreDns) with mock-based tests. Parsing was checked against real nmcli output on the Phase 0 laptop.
- Done since: apps/agent/src/main.ts restores DNS on exit, `npm run restore -w @work-dns/agent` restores it on its own, and deploy/systemd/work-dns-agent.service runs that restore in ExecStopPost.
- Done since: enforcement ran live on the Phase 0 laptop from scripts, from the agent process and from the systemd service.

## Findings

- 2026-10-23, scripts/reconnect-test.mjs: `nmcli connection up` on the enforced device cleared the runtime DNS settings. resolv.conf had no nameservers at +0.3 s and the router's resolvers at +1.3 s, and facebook.com then resolved through the router. Enforcement is silently lost on reconnect.
- Decision: the agent must detect the reset and re-apply enforcement, using `nmcli monitor` events plus a periodic check. setDnsLoopback already reuses an existing backup, so re-applying is safe.
- 2026-10-23, scripts/reconnect-watch-test.mjs: with DnsDriftWatcher running (2 s timer plus nmcli monitor activity, 300 ms debounce), the same reconnect was re-enforced about 0.7 s after resolv.conf showed the router again. Total window 1.6 s: 0.9 s with no nameservers, then 0.7 s on the router's resolvers. One sample. facebook.com was blocked afterwards.
- Known gap: the watcher cannot close this window. Closing it needs a firewall rule or a different mechanism, and neither is tried.
- Untested: sleep/wake, roaming between access points, a second device appearing during a run, and the watcher inside a real agent process.

## Deployment findings (2026-10-24)

- Under systemd-run, polkit refused `nmcli device modify` for the normal user ("not authorized") and allowed root. A system user `work-dns` plus /etc/polkit-1/rules.d/50-work-dns.rules (granting org.freedesktop.NetworkManager.network-control to that user) also worked. The agent therefore runs as `work-dns`, not root.
- The rule's scope is broad: network-control covers any NetworkManager setting, not only DNS. Narrowing it (for example to the service's cgroup) is untested.
- The unit limits the agent to CAP_NET_BIND_SERVICE and sets NoNewPrivileges. It runs a root-owned copy of the build in /opt/work-dns, copied by hand. A deploy script is not written.
- Started as a service, the agent enforced DNS (resolv.conf showed only 127.0.0.1, facebook.com blocked). After `kill -9` on the main process, ExecStopPost ran the restore, resolv.conf returned to the router's resolvers and lookups worked again, with no manual step.
- Restart=no is deliberate: an automatic restart would re-enforce DNS and hide whether the restore ran. Enable it once that no longer matters for testing.
- The journal showed notify-send failing under the service (no desktop session). Staff see no block notices until a helper runs inside the user session.
- The journal also showed cloudflare-dns.com blocked by company policy. Suspected cause: the gateway's own upstream lookups go through the enforced resolver when the gateway runs on the same machine. Not confirmed. An IP-based upstream (https://1.0.0.1/dns-query) would avoid it.
- Audit log: the gateway can persist blocked attempts to a local SQLite store (GATEWAY_AUDIT_DB), and a live run produced a verifying chain. This is a single-gateway stand-in: the production design is a backend that assigns sequence numbers and hashes (docs/api-tasks.md). Signed checkpoints exist in code but nothing signs them yet, the signing key has no custody plan, loggedOsUser is still "unknown", and agent system events are not yet emitted.
