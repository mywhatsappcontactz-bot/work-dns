import { describe, it, expect } from 'vitest';
import { WindowsPlatformAdapter } from '../src/platform/windows-adapter.js';

describe('WindowsPlatformAdapter (placeholder)', () => {
  const adapter = new WindowsPlatformAdapter();

  it('reports the windows platform', () => {
    expect(adapter.platformName).toBe('windows');
  });

  it('fails loudly instead of silently pretending to enforce or protect anything', async () => {
    await expect(adapter.setDnsLoopback(53)).rejects.toThrow(/not implemented/i);
    await expect(adapter.restoreDns()).rejects.toThrow(/not implemented/i);
    await expect(adapter.showNotification({ title: 't', message: 'm' })).rejects.toThrow(/not implemented/i);
    await expect(adapter.secureStore('k', 's')).rejects.toThrow(/not implemented/i);
    await expect(adapter.secureRetrieve('k')).rejects.toThrow(/not implemented/i);
  });
});
