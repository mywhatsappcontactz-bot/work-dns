# ADR 0004: Platform-Neutral Agent Stub with OS Adapter Isolation

## Status
Accepted

## Context
While the primary production target is Windows laptops in Nigerian hotels and corporate environments, developer development, integration testing, and Phase 0 spikes occur on Linux (specifically Arch Linux). Binding the agent architecture tightly to Windows APIs (PowerShell adapter commands, DPAPI, Windows Service control manager) would prevent rapid local development and automated CI testing.

## Decision
1. **Core Platform-Neutral Engine (`apps/agent`)**:
   - The DNS UDP stub (`127.0.0.1:53`), RFC 8484 DoH client, token memory manager, local queue, and heartbeat loop are written in portable TypeScript/Node.js.
2. **OS Adapter Interface (`PlatformAdapter`)**:
   - Platform-specific operations are abstracted behind a strict interface:
     - `setLoopbackDns()` / `restoreDns()`
     - `secureStoreSecret(key, secret)` / `secureRetrieveSecret(key)`
     - `applyBrowserEnterprisePolicies()`
     - `showDesktopNotification(title, message, actionUrl)`
3. **Target Implementations**:
   - `LinuxPlatformAdapter`: Uses `systemd-resolved` / `/etc/resolv.conf`, `notify-send` / libnotify, and secure root file storage (`0600`).
   - `WindowsPlatformAdapter`: Uses `netsh` / PowerShell adapter cmdlets, Windows DPAPI (`CryptProtectData`), native Windows toast notifications, and registry enterprise policy keys.
   - `MockPlatformAdapter`: For unit testing without root/admin privileges.

## Consequences
- **Pros**: Immediate testability on Arch Linux; identical business logic between Linux and Windows; clear boundary for OS-specific edge cases.
- **Cons**: Minor runtime overhead of abstraction layer.
