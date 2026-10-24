export type RestoreLog = (level: 'info' | 'error', message: string, fields?: Record<string, unknown>) => void;

export interface RestoreOptions {
  attempts?: number;
  delayMs?: number;
  log?: RestoreLog;
}

function defaultLog(level: 'info' | 'error', message: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ level, message, ...fields });
  if (level === 'error') {
    console.error(line);
  } else {
    console.log(line);
  }
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Restores DNS on its own, without the agent running. Safe when nothing is enforced.
 * Returns the process exit code: 0 on success, 1 when every attempt failed.
 */
export async function runRestore(adapter: { restoreDns(): Promise<void> }, options: RestoreOptions = {}): Promise<number> {
  const attempts = options.attempts ?? 3;
  const delayMs = options.delayMs ?? 500;
  const log = options.log ?? defaultLog;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      await adapter.restoreDns();
      log('info', 'DNS restored (or nothing was enforced)', {});
      return 0;
    } catch (err) {
      log('error', 'restoring DNS failed', { attempt, error: err instanceof Error ? err.message : String(err) });
      if (attempt < attempts) await sleep(delayMs);
    }
  }
  log('error', 'could not restore DNS; restore it by hand (see docs/adr/0007)', {});
  return 1;
}
