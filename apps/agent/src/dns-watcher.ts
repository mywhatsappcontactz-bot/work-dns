import { spawn } from 'node:child_process';

export type DriftResult = 'inactive' | 'no-device' | 'ok' | 'reapplied';

export interface MonitorHandle {
  stop(): void;
}

type LogFn = (level: 'info' | 'error', message: string, fields?: Record<string, unknown>) => void;

export interface DnsWatcherOptions {
  /** One drift check, normally LinuxPlatformAdapter.reapplyIfDrifted. */
  check: () => Promise<DriftResult>;
  /** Starts a source of "something changed" signals. Any call to onActivity triggers a check. */
  startMonitor: (onActivity: () => void, onExit: () => void) => MonitorHandle;
  intervalMs?: number; // default 5000
  debounceMs?: number; // default 300
  restartMonitorMs?: number; // default 5000
  log?: LogFn;
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

function positive(name: string, value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new RangeError(`DnsDriftWatcher: ${name} must be greater than zero`);
  }
  return value;
}

/**
 * Keeps DNS enforcement in place: checks on a timer and whenever the monitor reports activity.
 * Only one check runs at a time. A signal that arrives during a check causes one more check after it.
 * Run it only while enforcement is intended: an 'inactive' result is reported as an error.
 */
export class DnsDriftWatcher {
  private readonly check: () => Promise<DriftResult>;
  private readonly startMonitor: DnsWatcherOptions['startMonitor'];
  private readonly intervalMs: number;
  private readonly debounceMs: number;
  private readonly restartMonitorMs: number;
  private readonly log: LogFn;

  private started = false;
  private stopped = false;
  private intervalTimer: NodeJS.Timeout | null = null;
  private debounceTimer: NodeJS.Timeout | null = null;
  private restartTimer: NodeJS.Timeout | null = null;
  private monitor: MonitorHandle | null = null;
  private running: Promise<void> | null = null;
  private rerun = false;
  private lastKey = 'ok';

  constructor(options: DnsWatcherOptions) {
    this.check = options.check;
    this.startMonitor = options.startMonitor;
    this.intervalMs = positive('intervalMs', options.intervalMs ?? 5000);
    this.debounceMs = positive('debounceMs', options.debounceMs ?? 300);
    this.restartMonitorMs = positive('restartMonitorMs', options.restartMonitorMs ?? 5000);
    this.log = options.log ?? defaultLog;
  }

  public start(): void {
    if (this.started) throw new Error('DnsDriftWatcher is already started');
    this.started = true;
    this.intervalTimer = setInterval(() => this.runCheck(), this.intervalMs);
    this.launchMonitor();
  }

  /** Stops all timers and the monitor, then waits for a check that is already running. */
  public async stop(): Promise<void> {
    this.stopped = true;
    if (this.intervalTimer) clearInterval(this.intervalTimer);
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    if (this.restartTimer) clearTimeout(this.restartTimer);
    this.intervalTimer = null;
    this.debounceTimer = null;
    this.restartTimer = null;
    this.monitor?.stop();
    this.monitor = null;
    if (this.running) await this.running;
  }

  private launchMonitor(): void {
    if (this.stopped) return;
    try {
      this.monitor = this.startMonitor(
        () => this.trigger(),
        () => this.onMonitorExit()
      );
    } catch (err) {
      this.log('error', 'could not start the network monitor; relying on the timer', { error: errorMessageOf(err) });
      this.scheduleMonitorRestart();
    }
  }

  private onMonitorExit(): void {
    this.monitor = null;
    if (this.stopped) return;
    this.log('error', 'network monitor exited; restarting', {});
    this.scheduleMonitorRestart();
  }

  private scheduleMonitorRestart(): void {
    if (this.stopped || this.restartTimer) return;
    this.restartTimer = setTimeout(() => {
      this.restartTimer = null;
      this.launchMonitor();
    }, this.restartMonitorMs);
  }

  private trigger(): void {
    if (this.stopped) return;
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      this.runCheck();
    }, this.debounceMs);
  }

  private runCheck(): void {
    if (this.stopped) return;
    if (this.running) {
      this.rerun = true;
      return;
    }
    this.running = this.loop().finally(() => {
      this.running = null;
    });
  }

  private async loop(): Promise<void> {
    do {
      this.rerun = false;
      await this.checkOnce();
    } while (this.rerun && !this.stopped);
  }

  private async checkOnce(): Promise<void> {
    try {
      this.report(await this.check());
    } catch (err) {
      const message = errorMessageOf(err);
      this.reportOnce(`error:${message}`, 'error', 'DNS drift check failed; will retry', { error: message });
    }
  }

  private report(result: DriftResult): void {
    switch (result) {
      case 'ok':
        this.lastKey = 'ok';
        return;
      case 'no-device':
        return; // no connection right now: expected during a reconnect
      case 'reapplied':
        this.lastKey = 'ok';
        this.log('info', 'DNS enforcement had been reset and was re-applied', {});
        return;
      case 'inactive':
        this.reportOnce(
          'inactive',
          'error',
          'DNS enforcement is not active: no backup exists (a failed re-apply rolls back). Devices may be unenforced',
          {}
        );
        return;
    }
  }

  /** Logs a problem once per streak, so a persistent failure does not flood the log every few seconds. */
  private reportOnce(key: string, level: 'info' | 'error', message: string, fields: Record<string, unknown>): void {
    if (this.lastKey === key) return;
    this.lastKey = key;
    this.log(level, message, fields);
  }
}

/** Runs `nmcli monitor` and reports every line of output as activity. The text is never parsed. */
export function spawnNmcliMonitor(onActivity: () => void, onExit: () => void): MonitorHandle {
  const child = spawn('nmcli', ['monitor'], { stdio: ['ignore', 'pipe', 'ignore'] });
  let finished = false;
  const done = (): void => {
    if (!finished) {
      finished = true;
      onExit();
    }
  };
  child.stdout.on('data', () => onActivity());
  child.on('error', done);
  child.on('exit', done);
  return {
    stop: () => {
      finished = true; // an intentional stop must not look like a crash
      child.kill();
    },
  };
}
