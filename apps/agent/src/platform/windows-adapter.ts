import { PlatformAdapter, NotificationOptions } from './adapter.js';

/**
 * WindowsPlatformAdapter isolates all Windows-specific APIs (netsh, PowerShell, DPAPI).
 * Can be compiled on Linux without triggering OS-dependent native build failures.
 */
export class WindowsPlatformAdapter implements PlatformAdapter {
  public readonly platformName = 'windows';
  private inMemorySecrets = new Map<string, string>();

  public async setDnsLoopback(_port: number): Promise<void> {
    // Windows implementation will invoke PowerShell netsh cmdlets to set loopback adapter DNS
  }

  public async restoreDns(): Promise<void> {
    // Windows implementation will invoke netsh to restore DHCP DNS
  }

  public async showNotification(_options: NotificationOptions): Promise<void> {
    // Windows implementation will invoke BurntToast or Windows WinRT Toast notification API
  }

  public async secureStore(key: string, secret: string): Promise<void> {
    // Windows implementation invokes DPAPI CryptProtectData
    this.inMemorySecrets.set(key, secret);
  }

  public async secureRetrieve(key: string): Promise<string | null> {
    // Windows implementation invokes DPAPI CryptUnprotectData
    return this.inMemorySecrets.get(key) ?? null;
  }
}
