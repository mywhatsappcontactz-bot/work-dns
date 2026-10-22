export interface NotificationOptions {
  title: string;
  message: string;
  actionLabel?: string;
  actionUrl?: string;
}

export interface PlatformAdapter {
  readonly platformName: 'linux' | 'windows' | 'mock';

  /**
   * Configures local OS network adapters to direct DNS to 127.0.0.1 (and loopback port).
   */
  setDnsLoopback(port: number): Promise<void>;

  /**
   * Restores OS network adapters to standard DHCP or prior DNS resolvers.
   */
  restoreDns(): Promise<void>;

  /**
   * Displays an un-intrusive desktop toast/notification to staff.
   */
  showNotification(options: NotificationOptions): Promise<void>;

  /**
   * Stores a secret (e.g. device token) with machine/user scope protection.
   * On Linux: 0600 file permissions in ~/.config/work-dns.
   * On Windows: DPAPI (CryptProtectData).
   */
  secureStore(key: string, secret: string): Promise<void>;

  /**
   * Retrieves a previously protected secret.
   */
  secureRetrieve(key: string): Promise<string | null>;
}
