# ADR 0001: NXDOMAIN Block Response & Local Agent Notification

## Status
Accepted

## Context
When the policy engine determines that a queried domain is not on the tenant's allowlist, the DoH gateway must return a DNS response to the client. Two primary options exist:
1. **HTTP/HTTPS Sinkhole (Block Page)**: Returning an IP address pointing to an internal web server displaying a "Blocked by Company Policy" landing page.
2. **NXDOMAIN (Non-Existent Domain)**: Synthesizing an RFC 1035 NXDOMAIN (RCODE 3) response.

With the modern web, virtually all traffic is HTTPS (TLS). If a sinkhole IP is returned, the client's web browser initiates a TLS handshake with the sinkhole server. Because the sinkhole server does not hold a valid TLS certificate for the requested domain (e.g., `facebook.com`), the browser displays a severe, alarming security warning ("Your connection is not private / NET::ERR_CERT_COMMON_NAME_INVALID"). This confuses staff, increases IT support tickets, and conditions employees to click past security warnings.

## Decision
1. **The DoH gateway will return `NXDOMAIN` (RCODE 3)** for all blocked domain queries.
2. The endpoint staff experience will be managed via the **local agent tray / notification daemon**:
   - The agent observes DNS queries sent to loopback 127.0.0.1:53 that receive `NXDOMAIN` from the authenticated DoH gateway.
   - When a blocked domain is detected, the agent displays a non-intrusive desktop toast/notification: *"Access to [domain] is restricted by your company's policy. [Request Access]"*.
   - Clicking "Request Access" opens the local or portal access request dialog with pre-filled domain and device context.

## Consequences
- **Pros**: Clean browser behavior; zero TLS/SSL certificate mismatch warnings; lightweight gateway execution; no sinkhole IP infrastructure.
- **Cons**: Requires the client agent to be installed to provide a rich "Request Access" CTA (which matches our target model of managed company laptops).
