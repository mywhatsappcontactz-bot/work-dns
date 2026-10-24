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
- Not done: no caller invokes restoreDns on exit or crash, and the systemd unit with ExecStopPost does not exist.
- Not done: no live run of enforcement against the real network.

## Findings

- 2026-10-23, scripts/reconnect-test.mjs: `nmcli connection up` on the enforced device cleared the runtime DNS settings. resolv.conf had no nameservers at +0.3 s and the router's resolvers at +1.3 s, and facebook.com then resolved through the router. Enforcement is silently lost on reconnect.
- Decision: the agent must detect the reset and re-apply enforcement, using `nmcli monitor` events plus a periodic check. setDnsLoopback already reuses an existing backup, so re-applying is safe.
- 2026-10-23, scripts/reconnect-watch-test.mjs: with DnsDriftWatcher running (2 s timer plus nmcli monitor activity, 300 ms debounce), the same reconnect was re-enforced about 0.7 s after resolv.conf showed the router again. Total window 1.6 s: 0.9 s with no nameservers, then 0.7 s on the router's resolvers. One sample. facebook.com was blocked afterwards.
- Known gap: the watcher cannot close this window. Closing it needs a firewall rule or a different mechanism, and neither is tried.
- Untested: sleep/wake, roaming between access points, a second device appearing during a run, and the watcher inside a real agent process.
