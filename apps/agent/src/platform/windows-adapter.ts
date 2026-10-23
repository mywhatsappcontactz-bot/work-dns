import { PlatformAdapter, NotificationOptions } from './adapter.js';

const NOT_IMPLEMENTED =
  'WindowsPlatformAdapter is not implemented yet: no Windows DNS enforcement, notifications or secret protection exist (see docs/adr/0007)';

/**
 * Placeholder for Windows-specific APIs (netsh or PowerShell for DNS, DPAPI for secrets).
 * Every method fails loudly so the agent can never believe it is enforcing or protecting
 * anything on Windows. Nothing here has been run on a real Windows machine.
 */
export class WindowsPlatformAdapter implements PlatformAdapter {
  public readonly platformName = 'windows';

  public async setDnsLoopback(_port: number): Promise<void> {
    throw new Error(NOT_IMPLEMENTED);
  }

  public async restoreDns(): Promise<void> {
    throw new Error(NOT_IMPLEMENTED);
  }

  public async showNotification(_options: NotificationOptions): Promise<void> {
    throw new Error(NOT_IMPLEMENTED);
  }

  public async secureStore(_key: string, _secret: string): Promise<void> {
    throw new Error(NOT_IMPLEMENTED);
  }

  public async secureRetrieve(_key: string): Promise<string | null> {
    throw new Error(NOT_IMPLEMENTED);
  }
}
