import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

vi.mock('node:child_process', () => ({ execFile: vi.fn() }));
import { execFile } from 'node:child_process';
import { LinuxPlatformAdapter } from '../src/platform/linux-adapter.js';

type ExecCall = [string, string[], Record<string, unknown>, unknown];

function lastExecCall(): ExecCall {
    const calls = vi.mocked(execFile).mock.calls;
    return calls[calls.length - 1] as unknown as ExecCall;
}

describe('LinuxPlatformAdapter.showNotification', () => {
    const adapter = new LinuxPlatformAdapter({ configDir: path.join(os.tmpdir(), 'unused-work-dns') });

    beforeEach(() => {
        vi.mocked(execFile).mockClear();
    });

    it('runs notify-send without a shell and passes text as separate arguments after --', async () => {
        await adapter.showNotification({ title: 'Blocked', message: 'bet9ja.com' });
        const [file, args, options] = lastExecCall();
        expect(file).toBe('notify-send');
        expect(args).toEqual(['--app-name=Work DNS', '--', 'Blocked', 'bet9ja.com']);
        expect(options.shell).toBeUndefined();
    });

    it('passes shell metacharacters through as inert argument text', async () => {
        await adapter.showNotification({
            title: '"; touch /tmp/pwned; "',
            message: '$(touch /tmp/pwned)',
        });
        const [, args] = lastExecCall();
        expect(args).toHaveLength(4);
        expect(args[2]).toBe('"; touch /tmp/pwned; "');
        expect(args[3]).toBe('$(touch /tmp/pwned)');
        expect(fs.existsSync('/tmp/pwned')).toBe(false);
    });

    it('prevents option injection from text that starts with dashes', async () => {
        await adapter.showNotification({ title: '--hint=string:x:y', message: '-u critical' });
        const [, args] = lastExecCall();
        expect(args.indexOf('--')).toBe(1);
        expect(args[2]).toBe('--hint=string:x:y');
        expect(args[3]).toBe('-u critical');
    });

    it('escapes markup characters', async () => {
        await adapter.showNotification({ title: '<b>x</b> & y', message: 'ok' });
        const [, args] = lastExecCall();
        expect(args[2]).toBe('&lt;b&gt;x&lt;/b&gt; &amp; y');
    });

    it('replaces control characters and truncates long text', async () => {
        await adapter.showNotification({ title: 'a\u0000b\nc', message: 'x'.repeat(500) });
        const [, args] = lastExecCall();
        expect(args[2]).toBe('a b c');
        expect(args[3]).toHaveLength(200);
    });
});

describe('LinuxPlatformAdapter credential storage', () => {
    let base: string;
    let configDir: string;
    let credsFile: string;
    let adapter: LinuxPlatformAdapter;

    beforeEach(() => {
        base = fs.mkdtempSync(path.join(os.tmpdir(), 'work-dns-test-'));
        configDir = path.join(base, 'cfg');
        credsFile = path.join(configDir, 'credentials.json');
        adapter = new LinuxPlatformAdapter({ configDir });
    });

    afterEach(() => {
        fs.rmSync(base, { recursive: true, force: true });
    });

    it('stores and retrieves a secret with strict permissions and no leftover temp files', async () => {
        await adapter.secureStore('device_token', 'secret-1');
        expect(await adapter.secureRetrieve('device_token')).toBe('secret-1');
        expect(fs.statSync(credsFile).mode & 0o777).toBe(0o600);
        expect(fs.statSync(configDir).mode & 0o777).toBe(0o700);
        expect(fs.readdirSync(configDir)).toEqual(['credentials.json']);
    });

    it('preserves existing keys when storing another', async () => {
        await adapter.secureStore('a', '1');
        await adapter.secureStore('b', '2');
        expect(await adapter.secureRetrieve('a')).toBe('1');
        expect(await adapter.secureRetrieve('b')).toBe('2');
    });

    it('returns null when the store does not exist', async () => {
        expect(await adapter.secureRetrieve('missing')).toBeNull();
    });

    it('throws on corrupt JSON and leaves the file untouched', async () => {
        fs.mkdirSync(configDir, { mode: 0o700 });
        fs.writeFileSync(credsFile, '{not json', { mode: 0o600 });
        await expect(adapter.secureStore('b', '2')).rejects.toThrow(/corrupt/i);
        await expect(adapter.secureRetrieve('b')).rejects.toThrow(/corrupt/i);
        expect(fs.readFileSync(credsFile, 'utf8')).toBe('{not json');
    });

    it('rejects non-object JSON and non-string values', async () => {
        fs.mkdirSync(configDir, { mode: 0o700 });
        for (const bad of ['[]', 'null', '{"a":1}']) {
            fs.writeFileSync(credsFile, bad, { mode: 0o600 });
            await expect(adapter.secureStore('b', '2')).rejects.toThrow(/corrupt/i);
        }
    });

    it('does not expose inherited object properties', async () => {
        await adapter.secureStore('a', '1');
        expect(await adapter.secureRetrieve('constructor')).toBeNull();
        expect(await adapter.secureRetrieve('toString')).toBeNull();
    });

    it('rejects invalid keys', async () => {
        await expect(adapter.secureStore('', 'x')).rejects.toThrow(/invalid credential key/i);
        await expect(adapter.secureStore('a b', 'x')).rejects.toThrow(/invalid credential key/i);
    });

    it('tightens permissions on an existing loose directory', async () => {
        fs.mkdirSync(configDir, { mode: 0o755 });
        fs.chmodSync(configDir, 0o755);
        await adapter.secureStore('a', '1');
        expect(fs.statSync(configDir).mode & 0o777).toBe(0o700);
    });

    it('refuses a symlinked config directory', async () => {
        const real = path.join(base, 'real');
        fs.mkdirSync(real, { mode: 0o700 });
        fs.symlinkSync(real, configDir);
        await expect(adapter.secureStore('a', '1')).rejects.toThrow(/symlink/i);
    });

    it('throws explicit not-implemented errors for DNS enforcement', async () => {
        await expect(adapter.setDnsLoopback(53)).rejects.toThrow(/not implemented/i);
        await expect(adapter.restoreDns()).rejects.toThrow(/not implemented/i);
    });
});