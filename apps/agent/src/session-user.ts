import { execFile } from 'node:child_process';

export const UNKNOWN_USER = 'unknown';

const USER_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$/;
const SESSION_ID = /^[A-Za-z0-9]{1,16}$/;
const SEAT_NAME = /^[A-Za-z0-9_.-]{1,32}$/;

/** Runs a program without a shell and resolves with its stdout. Injectable for tests. */
export type LoginctlRunner = (file: string, args: string[]) => Promise<string>;

type ResolverLog = (level: 'info' | 'error', message: string, fields?: Record<string, unknown>) => void;

export interface SessionUserResolverOptions {
  run?: LoginctlRunner;
  /** The seat whose active session is read (default seat0). */
  seat?: string;
  /** How often the answer is refreshed (default 5000). */
  refreshIntervalMs?: number;
  log?: ResolverLog;
}

function defaultLog(level: 'info' | 'error', message: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ level, message, ...fields });
  if (level === 'error') {
    console.error(line);
  } else {
    console.log(line);
  }
}

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function runWithExecFile(file: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(file, args, { timeout: 3_000, maxBuffer: 16_384, windowsHide: true }, (error, stdout) => {
      if (error) {
        reject(error);
      } else {
        resolve(String(stdout));
      }
    });
  });
}

/** Parses "Key=value" lines in any order. */
function parseProperties(text: string): Map<string, string> {
  const props = new Map<string, string>();
  for (const line of text.split('\n')) {
    const at = line.indexOf('=');
    if (at <= 0) continue;
    props.set(line.slice(0, at).trim(), line.slice(at + 1).trim());
  }
  return props;
}

/** Returns the name if it looks like a plain username, otherwise "unknown". Untrusted text must pass through this. */
export function sanitizeUserName(value: unknown): string {
  return typeof value === 'string' && USER_NAME.test(value) ? value : UNKNOWN_USER;
}

/**
 * Names the person at the machine's console: the owner of the seat's active local session. This is who sat
 * at the keyboard, NOT which program made a request (a system process such as a connectivity check is
 * recorded under the console user too). Any doubt gives "unknown". A claim, not proof.
 */
export class SessionUserResolver {
  private readonly run: LoginctlRunner;
  private readonly seat: string;
  private readonly refreshIntervalMs: number;
  private readonly log: ResolverLog;
  private cached = UNKNOWN_USER;
  private timer: NodeJS.Timeout | null = null;
  private inFlight: Promise<string> | null = null;
  private lastFailureKey: string | null = null;

  constructor(options: SessionUserResolverOptions = {}) {
    const seat = options.seat ?? 'seat0';
    if (!SEAT_NAME.test(seat)) {
      throw new RangeError('SessionUserResolver: the seat name is not valid');
    }
    const interval = options.refreshIntervalMs ?? 5_000;
    if (!Number.isFinite(interval) || interval <= 0) {
      throw new RangeError('SessionUserResolver: refreshIntervalMs must be greater than zero');
    }
    this.run = options.run ?? runWithExecFile;
    this.seat = seat;
    this.refreshIntervalMs = interval;
    this.log = options.log ?? defaultLog;
  }

  /** The last answer. Cheap and synchronous, so it is safe on the DNS hot path. */
  public current(): string {
    return this.cached;
  }

  /** Looks the user up now. Never rejects. Concurrent calls share one lookup. */
  public refresh(): Promise<string> {
    if (this.inFlight) return this.inFlight;
    const pending = this.lookup().finally(() => {
      this.inFlight = null;
    });
    this.inFlight = pending;
    return pending;
  }

  public start(): void {
    if (this.timer) return;
    void this.refresh();
    this.timer = setInterval(() => {
      void this.refresh();
    }, this.refreshIntervalMs);
    this.timer.unref?.();
  }

  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private settle(value: string): string {
    this.cached = value;
    this.lastFailureKey = null;
    return value;
  }

  /** Records "unknown" and logs once per streak of the same failure. */
  private fail(key: string, message: string, fields: Record<string, unknown>): string {
    this.cached = UNKNOWN_USER;
    if (this.lastFailureKey !== key) {
      this.lastFailureKey = key;
      this.log('error', message, fields);
    }
    return UNKNOWN_USER;
  }

  private async lookup(): Promise<string> {
    try {
      const seatOut = (await this.run('loginctl', ['show-seat', this.seat, '-p', 'ActiveSession', '--value'])).trim();
      if (seatOut === '') return this.settle(UNKNOWN_USER); // nobody is logged in at the console: normal
      if (!SESSION_ID.test(seatOut)) {
        return this.fail('bad-session-id', 'logind returned an unexpected session id; recording the user as unknown', {});
      }
      const out = await this.run('loginctl', [
        'show-session',
        seatOut,
        '-p',
        'Name',
        '-p',
        'Class',
        '-p',
        'State',
        '-p',
        'Remote',
        '-p',
        'Active',
      ]);
      const props = parseProperties(out);
      // A login screen, a remote login or an inactive session is normal: not a console user.
      if (
        props.get('Class') !== 'user' ||
        props.get('Remote') !== 'no' ||
        props.get('Active') !== 'yes' ||
        props.get('State') !== 'active'
      ) {
        return this.settle(UNKNOWN_USER);
      }
      const name = props.get('Name');
      if (name === undefined || !USER_NAME.test(name)) {
        return this.fail('bad-name', 'the active login session has an unexpected user name; recording the user as unknown', {});
      }
      return this.settle(name);
    } catch (err) {
      return this.fail('command', 'could not read the active login session; recording the user as unknown', {
        error: errorMessageOf(err),
      });
    }
  }
}
