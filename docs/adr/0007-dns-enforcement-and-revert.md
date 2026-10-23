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
2. Enforce: set ipv4.dns 127.0.0.1, ipv6.dns ::1, and ipv4/ipv6.ignore-auto-dns yes.
3. Backup: before enforcing, record the device's current ipv4.dns, ipv6.dns and both ignore-auto-dns values to a root-owned file. Restore writes those values back.
4. Device: detect the active devices with nmcli at run time. Never hard-code wlp58s0.
5. Crash safety: restore must not depend on the agent staying alive. The systemd unit runs the restore in ExecStopPost, which systemd runs after a crash or kill.
6. Port 53: the unit grants AmbientCapabilities=CAP_NET_BIND_SERVICE. The agent does not run as root.
7. Fail-open: if restore itself fails, log it loudly and keep retrying. Never leave a device pointing at a dead stub silently.

## Consequences

- A stuck state is recoverable by reboot, and by running the restore command above.
- The agent must re-apply enforcement if NetworkManager resets the device settings.

## Open questions (untested)

- Does a wifi reconnect or roam drop the runtime settings? Assumed yes, not verified.
- Does the stub accept queries on ::1, or only on IPv4 127.0.0.1? Not checked.
- Does `nmcli connection up` also undo a modify? Not tested.
- Behavior with several active devices (ethernet plus wifi), VPN clients, and captive portals.
- Whether ExecStopPost runs reliably on SIGKILL and on out-of-memory kills. Test it.
- Applications that do their own DoH (browsers) bypass system DNS. Out of scope here.
