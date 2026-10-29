import { describe, it, expect } from 'vitest';
import { loadConfig } from '../src/config.js';

const required = { GATEWAY_TOKENS_FILE: '/etc/work-dns/tokens.json', GATEWAY_POLICIES_FILE: '/etc/work-dns/policies.json' };

describe('loadConfig', () => {
  it('applies safe defaults', () => {
    expect(loadConfig(required)).toEqual({
      host: '127.0.0.1',
      port: 8053,
      trustProxy: false,
      tokensFile: '/etc/work-dns/tokens.json',
      policiesFile: '/etc/work-dns/policies.json',
      upstreamPrimary: undefined,
      upstreamSecondary: undefined,
      rollupWindowSeconds: 300,
      ipRateBurst: 1000,
      ipRatePerSecond: 500,
    });
  });

  it('reads overrides', () => {
    const config = loadConfig({
      ...required,
      GATEWAY_HOST: '10.0.0.5',
      GATEWAY_PORT: '9000',
      GATEWAY_TRUST_PROXY: 'true',
      GATEWAY_UPSTREAM_PRIMARY: 'https://dns.example.com/dns-query',
      GATEWAY_UPSTREAM_SECONDARY: 'https://dns2.example.com/dns-query',
      GATEWAY_IP_RATE_BURST: '50',
      GATEWAY_IP_RATE_PER_SECOND: '10',
    });
    expect(config).toMatchObject({
      host: '10.0.0.5',
      port: 9000,
      trustProxy: true,
      upstreamPrimary: 'https://dns.example.com/dns-query',
      upstreamSecondary: 'https://dns2.example.com/dns-query',
      ipRateBurst: 50,
      ipRatePerSecond: 10,
    });
  });

  it('treats blank values as unset', () => {
    expect(loadConfig({ ...required, GATEWAY_PORT: '  ', GATEWAY_HOST: '' }).port).toBe(8053);
  });

  it('reports every problem at once', () => {
    let message = '';
    try {
      loadConfig({
        GATEWAY_PORT: '70000',
        GATEWAY_TRUST_PROXY: 'yes',
        GATEWAY_UPSTREAM_PRIMARY: 'http://insecure.example.com',
        GATEWAY_IP_RATE_BURST: '0',
      });
    } catch (err) {
      message = (err as Error).message;
    }
    for (const fragment of [
      'GATEWAY_PORT',
      'GATEWAY_TRUST_PROXY',
      'GATEWAY_TOKENS_FILE is required',
      'GATEWAY_POLICIES_FILE is required',
      'GATEWAY_UPSTREAM_PRIMARY must use https',
      'GATEWAY_IP_RATE_BURST',
    ]) {
      expect(message).toContain(fragment);
    }
  });

  it.each(['abc', '-1', '1.5', '99999'])('rejects invalid port %s', (port) => {
    expect(() => loadConfig({ ...required, GATEWAY_PORT: port })).toThrow(/GATEWAY_PORT/);
  });

  it('accepts port 0 (OS-assigned)', () => {
    expect(loadConfig({ ...required, GATEWAY_PORT: '0' }).port).toBe(0);
  });

  it('rejects invalid upstream URLs', () => {
    expect(() => loadConfig({ ...required, GATEWAY_UPSTREAM_PRIMARY: 'not a url' })).toThrow(/not a valid URL/);
  });
});
