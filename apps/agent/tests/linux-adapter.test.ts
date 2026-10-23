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
});

interface FakeDevice {
    device: string;
    type: string;
    state: string;
    connection: string;
}

interface FakeDnsState {
    ipv4Dns: string;
    ipv4Ignore: string;
    ipv6Dns: string;
    ipv6Ignore: string;
}

/** Simulates the nmcli commands the adapter uses. Nothing here touches the real network. */
function makeFakeNmcli(devices: FakeDevice[], failWhen?: (args: string[]) => boolean) {
    const calls: string[][] = [];
    const runtime = new Map<string, FakeDnsState>();
    for (const d of devices) {
        runtime.set(d.device, { ipv4Dns: '', ipv4Ignore: 'no', ipv6Dns: '', ipv6Ignore: 'no' });
    }
    const run = async (file: string, args: string[]): Promise<string> => {
        calls.push([file, ...args]);
        if (file !== 'nmcli') throw new Error(`unexpected program ${file}`);
        if (failWhen?.(args)) throw new Error('simulated nmcli failure');
        if (args.includes('status')) {
            return devices.map((d) => `${d.device}:${d.type}:${d.state}`).join('\n') + '\n';
        }
        if (args.includes('GENERAL.CONNECTION')) {
            const name = args[args.length - 1];
            const dev = devices.find((d) => d.device === name);
            return `${dev?.connection ?? '--'}\n`;
        }
        if (args.includes('connection') && args.includes('show')) {
            return '\nno\n\nno\n'; // profile defaults: no custom DNS, ignore-auto-dns off
        }
        if (args[0] === 'device' && args[1] === 'modify') {
            runtime.set(args[2]!, { ipv4Dns: args[4]!, ipv4Ignore: args[6]!, ipv6Dns: args[8]!, ipv6Ignore: args[10]! });
            return '';
        }
        throw new Error(`unexpected nmcli args: ${args.join(' ')}`);
    };
    return { run, calls, runtime };
}

const WIFI: FakeDevice = { device: 'wlan0', type: 'wifi', state: 'connected', connection: 'HomeNet' };
const ETH: FakeDevice = { device: 'eth0', type: 'ethernet', state: 'connected', connection: 'Wired' };
const LOOPBACK: FakeDevice = { device: 'lo', type: 'loopback', state: 'unmanaged', connection: '--' };

describe('LinuxPlatformAdapter DNS enforcement', () => {
    let dir: string;
    let backupFile: string;

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-dns-'));
        backupFile = path.join(dir, 'dns-backup.json');
    });

    afterEach(() => {
        fs.rmSync(dir, { recursive: true, force: true });
    });

    const modifies = (calls: string[][]) => calls.filter((c) => c[1] === 'device' && c[2] === 'modify');

    it('rejects any port other than 53 and runs no commands', async () => {
        const fake = makeFakeNmcli([WIFI]);
        const adapter = new LinuxPlatformAdapter({ configDir: dir, runCommand: fake.run });
        await expect(adapter.setDnsLoopback(5353)).rejects.toThrow(/53/);
        expect(fake.calls).toHaveLength(0);
    });

    it('enforces with exact nmcli arguments, backs up the originals (mode 0600), and restores them', async () => {
        const fake = makeFakeNmcli([LOOPBACK, WIFI]);
        const adapter = new LinuxPlatformAdapter({ configDir: dir, runCommand: fake.run });

        await adapter.setDnsLoopback(53);
        expect(modifies(fake.calls)).toEqual([
            ['nmcli', 'device', 'modify', 'wlan0', 'ipv4.dns', '127.0.0.1', 'ipv4.ignore-auto-dns', 'yes', 'ipv6.dns', '', 'ipv6.ignore-auto-dns', 'yes'],
        ]);
        expect(fs.statSync(backupFile).mode & 0o777).toBe(0o600);
        const saved = JSON.parse(fs.readFileSync(backupFile, 'utf8')) as Array<Record<string, string>>;
        expect(saved).toEqual([
            { device: 'wlan0', connection: 'HomeNet', ipv4Dns: '', ipv4IgnoreAuto: 'no', ipv6Dns: '', ipv6IgnoreAuto: 'no' },
        ]);

        await adapter.restoreDns();
        expect(fake.runtime.get('wlan0')).toEqual({ ipv4Dns: '', ipv4Ignore: 'no', ipv6Dns: '', ipv6Ignore: 'no' });
        expect(fs.existsSync(backupFile)).toBe(false);
    });

    it('restoreDns is safe to call when nothing is enforced and safe to call twice', async () => {
        const fake = makeFakeNmcli([WIFI]);
        const adapter = new LinuxPlatformAdapter({ configDir: dir, runCommand: fake.run });
        await adapter.restoreDns();
        expect(fake.calls).toHaveLength(0);

        await adapter.setDnsLoopback(53);
        await adapter.restoreDns();
        const callsAfterFirstRestore = fake.calls.length;
        await adapter.restoreDns();
        expect(fake.calls).toHaveLength(callsAfterFirstRestore);
    });

    it('never overwrites an existing backup: the originals are captured once', async () => {
        const fake = makeFakeNmcli([WIFI]);
        const adapter = new LinuxPlatformAdapter({ configDir: dir, runCommand: fake.run });
        await adapter.setDnsLoopback(53);
        await adapter.setDnsLoopback(53);
        const captures = fake.calls.filter((c) => c.includes('connection') && c.includes('show'));
        expect(captures).toHaveLength(1);
        const saved = JSON.parse(fs.readFileSync(backupFile, 'utf8')) as Array<Record<string, string>>;
        expect(saved[0]?.ipv4Dns).toBe('');
    });

    it('rolls back every device when enforcement fails part-way', async () => {
        const fake = makeFakeNmcli([WIFI, ETH], (args) => args[1] === 'modify' && args[2] === 'eth0' && args[4] === '127.0.0.1');
        const adapter = new LinuxPlatformAdapter({ configDir: dir, runCommand: fake.run });
        await expect(adapter.setDnsLoopback(53)).rejects.toThrow(/simulated nmcli failure/);
        expect(fake.runtime.get('wlan0')).toEqual({ ipv4Dns: '', ipv4Ignore: 'no', ipv6Dns: '', ipv6Ignore: 'no' });
        expect(fs.existsSync(backupFile)).toBe(false);
    });

    it('keeps the backup and reports an error when a restore fails', async () => {
        let failing = false;
        const fake = makeFakeNmcli([WIFI], (args) => failing && args[1] === 'modify');
        const adapter = new LinuxPlatformAdapter({ configDir: dir, runCommand: fake.run });
        await adapter.setDnsLoopback(53);
        failing = true;
        await expect(adapter.restoreDns()).rejects.toThrow(/restoreDns failed/);
        expect(fs.existsSync(backupFile)).toBe(true);
    });

    it('skips a device that is no longer connected when restoring', async () => {
        const wifi: FakeDevice = { ...WIFI };
        const fake = makeFakeNmcli([wifi]);
        const adapter = new LinuxPlatformAdapter({ configDir: dir, runCommand: fake.run });
        await adapter.setDnsLoopback(53);
        wifi.state = 'disconnected';
        const before = modifies(fake.calls).length;
        await adapter.restoreDns();
        expect(modifies(fake.calls)).toHaveLength(before);
        expect(fs.existsSync(backupFile)).toBe(false);
    });

    it('refuses to enforce when a backup file is corrupt', async () => {
        fs.writeFileSync(backupFile, 'not json', { mode: 0o600 });
        const fake = makeFakeNmcli([WIFI]);
        const adapter = new LinuxPlatformAdapter({ configDir: dir, runCommand: fake.run });
        await expect(adapter.setDnsLoopback(53)).rejects.toThrow(/corrupt/);
        expect(modifies(fake.calls)).toHaveLength(0);
    });

    it('refuses to enforce when no wifi or ethernet device is connected', async () => {
        const fake = makeFakeNmcli([LOOPBACK]);
        const adapter = new LinuxPlatformAdapter({ configDir: dir, runCommand: fake.run });
        await expect(adapter.setDnsLoopback(53)).rejects.toThrow(/no connected/);
        expect(fs.existsSync(backupFile)).toBe(false);
    });
});
