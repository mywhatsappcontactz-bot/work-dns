import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { PlatformAdapter, NotificationOptions } from './adapter.js';

const MAX_NOTIFICATION_TEXT = 200;
const KEY_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;
const DEVICE_PATTERN = /^[A-Za-z0-9._-]{1,15}$/;
const DNS_LIST_PATTERN = /^[0-9A-Fa-f:.]+(,[0-9A-Fa-f:.]+)*$/;

/** Runs a program without a shell and resolves with its stdout. Injectable for tests. */
export type CommandRunner = (file: string, args: string[]) => Promise<string>;

function runWithExecFile(file: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(file, args, { timeout: 10_000 }, (error, stdout) => {
      if (error) {
        reject(error);
      } else {
        resolve(String(stdout));
      }
    });
  });
}

/** nmcli terse output escapes ':' and '\\'; empty values print as nothing or '--'. */
function unescapeNmcli(value: string): string {
  const trimmed = value.trim();
  return trimmed === '--' ? '' : trimmed.replace(/\\(.)/g, '$1');
}

/** The original runtime DNS settings of one device, saved before enforcement. */
interface DnsBackupEntry {
  device: string;
  connection: string;
  ipv4Dns: string;
  ipv4IgnoreAuto: 'yes' | 'no';
  ipv6Dns: string;
  ipv6IgnoreAuto: 'yes' | 'no';
}

function isYesNo(value: unknown): value is 'yes' | 'no' {
  return value === 'yes' || value === 'no';
}

function isDnsList(value: unknown): value is string {
  return typeof value === 'string' && (value === '' || DNS_LIST_PATTERN.test(value));
}

/**
 * Notification text can contain attacker-controlled data (queried domain names).
 * Strip control characters, truncate, and escape markup.
 */
function sanitizeNotificationText(input: unknown): string {
  return String(input)
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .slice(0, MAX_NOTIFICATION_TEXT)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

export interface LinuxPlatformAdapterOptions {
  /** Override the credential directory (used by tests). */
  configDir?: string;
  /** Override how external programs (nmcli) are run (used by tests). */
  runCommand?: CommandRunner;
}

/**
 * NOTE: secureStore keeps secrets as plain JSON with strict file permissions.
 * That is weak storage, acceptable only for the Phase 0 spike.
 */
export class LinuxPlatformAdapter implements PlatformAdapter {
  public readonly platformName = 'linux';
  private readonly configDir: string;
  private readonly credsFile: string;
  private readonly backupFile: string;
  private readonly runCommand: CommandRunner;

  constructor(options: LinuxPlatformAdapterOptions = {}) {
    this.configDir = options.configDir ?? path.join(os.homedir(), '.config', 'work-dns');
    this.credsFile = path.join(this.configDir, 'credentials.json');
    this.backupFile = path.join(this.configDir, 'dns-backup.json');
    this.runCommand = options.runCommand ?? runWithExecFile;
  }

  /**
   * Points every connected wifi/ethernet device at the local stub using runtime-only nmcli changes
   * (docs/adr/0007). NetworkManager takes IP addresses only, so the stub must listen on port 53.
   * IPv6 DNS is cleared and the router's IPv6 DNS is ignored, so it cannot bypass the stub.
   */
  public async setDnsLoopback(port: number): Promise<void> {
    if (port !== 53) {
      throw new RangeError(`setDnsLoopback: NetworkManager cannot target a port; the stub must listen on 53, got ${port}`);
    }
    const devices = await this.activeDevices();
    if (devices.length === 0) {
      throw new Error('setDnsLoopback: no connected wifi or ethernet device found');
    }

    // Never overwrite an existing backup: it holds the true originals (for example after a crash).
    const entries = this.readBackup() ?? [];
    let added = false;
    for (const device of devices) {
      if (!entries.some((entry) => entry.device === device)) {
        entries.push(await this.captureDevice(device));
        added = true;
      }
    }
    if (added) {
      this.writeBackup(entries);
    }

    try {
      for (const device of devices) {
        await this.applyDns(device, '127.0.0.1', 'yes', '', 'yes');
      }
    } catch (err) {
      try {
        await this.restoreDns();
      } catch (restoreErr) {
        console.error(JSON.stringify({ level: 'error', message: 'DNS rollback failed', error: String(restoreErr) }));
      }
      throw err;
    }
  }

  /**
   * Restores the saved DNS settings. Safe to call when nothing is enforced and safe to call twice.
   * A device that is no longer connected is skipped: its runtime settings went away with the connection.
   */
  public async restoreDns(): Promise<void> {
    const entries = this.readBackup();
    if (entries === null) return;

    const active = new Set(await this.activeDevices());
    const failures: string[] = [];
    for (const entry of entries) {
      if (!active.has(entry.device)) continue;
      try {
        await this.applyDns(entry.device, entry.ipv4Dns, entry.ipv4IgnoreAuto, entry.ipv6Dns, entry.ipv6IgnoreAuto);
      } catch (err) {
        failures.push(`${entry.device}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    if (failures.length > 0) {
      throw new Error(`restoreDns failed (backup kept at ${this.backupFile}): ${failures.join('; ')}`);
    }
    fs.rmSync(this.backupFile, { force: true });
  }

  private async activeDevices(): Promise<string[]> {
    const out = await this.runCommand('nmcli', ['-t', '-f', 'DEVICE,TYPE,STATE', 'device', 'status']);
    const devices: string[] = [];
    for (const line of out.split('\n')) {
      const [device, type, state] = line.split(':');
      if (
        device !== undefined &&
        state === 'connected' &&
        (type === 'wifi' || type === 'ethernet') &&
        DEVICE_PATTERN.test(device)
      ) {
        devices.push(device);
      }
    }
    return devices;
  }

  private async captureDevice(device: string): Promise<DnsBackupEntry> {
    const connection = unescapeNmcli(
      await this.runCommand('nmcli', ['-t', '-g', 'GENERAL.CONNECTION', 'device', 'show', device])
    );
    if (connection === '') {
      throw new Error(`device ${device} has no active connection`);
    }
    const out = await this.runCommand('nmcli', [
      '-g',
      'ipv4.dns,ipv4.ignore-auto-dns,ipv6.dns,ipv6.ignore-auto-dns',
      'connection',
      'show',
      'id',
      connection,
    ]);
    const lines = out.replace(/\n$/, '').split('\n').map(unescapeNmcli);
    if (lines.length !== 4) {
      throw new Error(`unexpected nmcli output for ${device}: expected 4 values, got ${lines.length}`);
    }
    const [ipv4Dns, ipv4IgnoreAuto, ipv6Dns, ipv6IgnoreAuto] = lines;
    if (!isDnsList(ipv4Dns) || !isDnsList(ipv6Dns) || !isYesNo(ipv4IgnoreAuto) || !isYesNo(ipv6IgnoreAuto)) {
      throw new Error(`unexpected nmcli values for ${device}; refusing to enforce without a safe backup`);
    }
    return { device, connection, ipv4Dns, ipv4IgnoreAuto, ipv6Dns, ipv6IgnoreAuto };
  }

  private async applyDns(
    device: string,
    ipv4Dns: string,
    ipv4IgnoreAuto: 'yes' | 'no',
    ipv6Dns: string,
    ipv6IgnoreAuto: 'yes' | 'no'
  ): Promise<void> {
    await this.runCommand('nmcli', [
      'device',
      'modify',
      device,
      'ipv4.dns',
      ipv4Dns,
      'ipv4.ignore-auto-dns',
      ipv4IgnoreAuto,
      'ipv6.dns',
      ipv6Dns,
      'ipv6.ignore-auto-dns',
      ipv6IgnoreAuto,
    ]);
  }

  private readBackup(): DnsBackupEntry[] | null {
    let raw: string;
    try {
      raw = fs.readFileSync(this.backupFile, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw err;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(`DNS backup ${this.backupFile} is corrupt (invalid JSON): ${(err as Error).message}`);
    }
    if (!Array.isArray(parsed)) {
      throw new Error(`DNS backup ${this.backupFile} is corrupt (expected an array)`);
    }
    const entries: DnsBackupEntry[] = [];
    for (const item of parsed as unknown[]) {
      const e = item as Record<string, unknown> | null;
      if (
        e === null ||
        typeof e !== 'object' ||
        typeof e.device !== 'string' ||
        !DEVICE_PATTERN.test(e.device) ||
        typeof e.connection !== 'string' ||
        !isDnsList(e.ipv4Dns) ||
        !isDnsList(e.ipv6Dns) ||
        !isYesNo(e.ipv4IgnoreAuto) ||
        !isYesNo(e.ipv6IgnoreAuto)
      ) {
        throw new Error(`DNS backup ${this.backupFile} is corrupt (invalid entry)`);
      }
      entries.push({
        device: e.device,
        connection: e.connection,
        ipv4Dns: e.ipv4Dns,
        ipv4IgnoreAuto: e.ipv4IgnoreAuto,
        ipv6Dns: e.ipv6Dns,
        ipv6IgnoreAuto: e.ipv6IgnoreAuto,
      });
    }
    return entries;
  }

  private writeBackup(entries: DnsBackupEntry[]): void {
    this.ensureConfigDir();
    const tmpPath = `${this.backupFile}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
    let fd: number | undefined;
    try {
      fd = fs.openSync(tmpPath, 'wx', 0o600);
      fs.writeFileSync(fd, JSON.stringify(entries, null, 2));
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(tmpPath, this.backupFile);
    } catch (err) {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch { /* best-effort cleanup; the original error is rethrown below */ }
      }
      try { fs.rmSync(tmpPath, { force: true }); } catch { /* best-effort cleanup; the original error is rethrown below */ }
      throw err;
    }
  }

  public async showNotification(options: NotificationOptions): Promise<void> {
    const title = sanitizeNotificationText(options.title);
    const message = sanitizeNotificationText(options.message);
    // No shell. '--' ends option parsing so text starting with '-' cannot become an option.
    execFile(
      'notify-send',
      ['--app-name=Work DNS', '--', title, message],
      { timeout: 5000 },
      (error) => {
        if (error) {
          console.debug(`notify-send failed: ${error.message}`);
        }
      }
    );
  }

  public async secureStore(key: string, secret: string): Promise<void> {
    this.assertValidKey(key);
    if (typeof secret !== 'string') {
      throw new TypeError('secureStore: secret must be a string');
    }
    this.ensureConfigDir();
    const creds = this.readCredentials();
    creds.set(key, secret);
    this.writeCredentials(creds);
  }

  public async secureRetrieve(key: string): Promise<string | null> {
    this.assertValidKey(key);
    return this.readCredentials().get(key) ?? null;
  }

  private assertValidKey(key: string): void {
    if (typeof key !== 'string' || !KEY_PATTERN.test(key)) {
      throw new TypeError(`Invalid credential key: must match ${KEY_PATTERN}`);
    }
  }

  private ensureConfigDir(): void {
    fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
    const st = fs.lstatSync(this.configDir);
    if (st.isSymbolicLink() || !st.isDirectory()) {
      throw new Error(`Config path ${this.configDir} must be a real directory, not a symlink`);
    }
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
      throw new Error(`Config directory ${this.configDir} is not owned by the current user`);
    }
    if ((st.mode & 0o077) !== 0) {
      fs.chmodSync(this.configDir, 0o700); // throws on failure; not swallowed
    }
  }

  private readCredentials(): Map<string, string> {
    let raw: string;
    try {
      raw = fs.readFileSync(this.credsFile, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        return new Map();
      }
      throw err;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(
        `Credential store ${this.credsFile} is corrupt (invalid JSON); refusing to continue: ${(err as Error).message}`
      );
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error(`Credential store ${this.credsFile} is corrupt (expected a JSON object)`);
    }

    const creds = new Map<string, string>();
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof v !== 'string') {
        throw new Error(`Credential store ${this.credsFile} is corrupt (non-string value for key "${k}")`);
      }
      creds.set(k, v);
    }
    return creds;
  }

  private writeCredentials(creds: Map<string, string>): void {
    const data = JSON.stringify(Object.fromEntries(creds), null, 2);
    const tmpPath = `${this.credsFile}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
    let fd: number | undefined;
    try {
      fd = fs.openSync(tmpPath, 'wx', 0o600); // exclusive create: no symlink following
      fs.writeFileSync(fd, data);
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fs.renameSync(tmpPath, this.credsFile);
    } catch (err) {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch { /* best-effort cleanup; the original error is rethrown below */ }
      }
      try { fs.rmSync(tmpPath, { force: true }); } catch { /* best-effort cleanup; the original error is rethrown below */ }
      throw err;
    }
  }
}
