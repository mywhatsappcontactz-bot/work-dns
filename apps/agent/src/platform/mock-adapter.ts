import { PlatformAdapter, NotificationOptions } from './adapter.js';

export class MockPlatformAdapter implements PlatformAdapter {
  public readonly platformName = 'mock';
  public secrets = new Map<string, string>();
  public notifications: NotificationOptions[] = [];
  public isLoopbackSet = false;

  public async setDnsLoopback(_port: number): Promise<void> {
    this.isLoopbackSet = true;
  }

  public async restoreDns(): Promise<void> {
    this.isLoopbackSet = false;
  }

  public async showNotification(options: NotificationOptions): Promise<void> {
    this.notifications.push(options);
  }

  public async secureStore(key: string, secret: string): Promise<void> {
    this.secrets.set(key, secret);
  }

  public async secureRetrieve(key: string): Promise<string | null> {
    return this.secrets.get(key) ?? null;
  }
}
