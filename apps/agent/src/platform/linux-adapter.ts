import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { PlatformAdapter, NotificationOptions } from './adapter.js';

const MAX_NOTIFICATION_TEXT = 200;
const KEY_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;

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
}

/**
 * NOTE: secureStore keeps secrets as plain JSON with strict file permissions.
 * That is weak storage, acceptable only for the Phase 0 spike.
 */
export class LinuxPlatformAdapter implements PlatformAdapter {
  public readonly platformName = 'linux';
  private readonly configDir: string;
  private readonly credsFile: string;

  constructor(options: LinuxPlatformAdapterOptions = {}) {
    this.configDir = options.configDir ?? path.join(os.homedir(), '.config', 'work-dns');
    this.credsFile = path.join(this.configDir, 'credentials.json');
  }

  public async setDnsLoopback(_port: number): Promise<void> {
    throw new Error('LinuxPlatformAdapter.setDnsLoopback is not implemented (see docs/adr/0007)');
  }

  public async restoreDns(): Promise<void> {
    throw new Error('LinuxPlatformAdapter.restoreDns is not implemented (see docs/adr/0007)');
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
