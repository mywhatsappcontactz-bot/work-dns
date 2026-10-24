import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadAgentConfig, readDeviceToken } from '../src/config.js';

const base = { AGENT_GATEWAY_URL: 'https://gw.example.com/dns-query', AGENT_DEVICE_TOKEN_FILE: '/tmp/token' };

describe('loadAgentConfig', () => {
    it('applies defaults', () => {
        expect(loadAgentConfig(base)).toEqual({
            gatewayUrl: 'https://gw.example.com/dns-query',
            deviceTokenFile: '/tmp/token',
            loopbackPort: 53,
            fallbackDohUrl: 'https://cloudflare-dns.com/dns-query',
            queueFile: undefined,
        });
    });

    it('reports every missing required variable at once', () => {
        expect(() => loadAgentConfig({})).toThrow(/AGENT_GATEWAY_URL is required[\s\S]*AGENT_DEVICE_TOKEN_FILE is required/);
    });

    it('rejects an invalid port', () => {
        expect(() => loadAgentConfig({ ...base, AGENT_LOOPBACK_PORT: '70000' })).toThrow(/AGENT_LOOPBACK_PORT/);
        expect(() => loadAgentConfig({ ...base, AGENT_LOOPBACK_PORT: 'abc' })).toThrow(/AGENT_LOOPBACK_PORT/);
    });

    it('rejects http for a non-loopback gateway', () => {
        expect(() => loadAgentConfig({ ...base, AGENT_GATEWAY_URL: 'http://gw.example.com/dns-query' })).toThrow(/must use https/);
    });

    it('allows http for a loopback gateway and port 0', () => {
        const config = loadAgentConfig({ ...base, AGENT_GATEWAY_URL: 'http://127.0.0.1:8053/dns-query', AGENT_LOOPBACK_PORT: '0' });
        expect(config.gatewayUrl).toBe('http://127.0.0.1:8053/dns-query');
        expect(config.loopbackPort).toBe(0);
    });

    it('rejects a non-https fallback resolver', () => {
        expect(() => loadAgentConfig({ ...base, AGENT_FALLBACK_DOH: 'http://x.test/dns-query' })).toThrow(/AGENT_FALLBACK_DOH must use https/);
    });
});

describe('readDeviceToken', () => {
    let dir: string;

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-token-'));
    });

    afterEach(() => {
        fs.rmSync(dir, { recursive: true, force: true });
    });

    it('reads and trims a token from an owner-only file', () => {
        const file = path.join(dir, 'token');
        fs.writeFileSync(file, 'secret-token\n');
        fs.chmodSync(file, 0o600);
        expect(readDeviceToken(file)).toBe('secret-token');
    });

    it('refuses a file that group or others can read', () => {
        const file = path.join(dir, 'token');
        fs.writeFileSync(file, 'secret-token\n');
        fs.chmodSync(file, 0o644);
        expect(() => readDeviceToken(file)).toThrow(/chmod 600/);
    });

    it('refuses an empty file', () => {
        const file = path.join(dir, 'token');
        fs.writeFileSync(file, '  \n');
        fs.chmodSync(file, 0o600);
        expect(() => readDeviceToken(file)).toThrow(/empty/);
    });

    it('reports a missing file', () => {
        expect(() => readDeviceToken(path.join(dir, 'nope'))).toThrow(/Cannot read device token file/);
    });
});
