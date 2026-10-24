import { startAgent } from './main.js';

const FORCE_EXIT_AFTER_MS = 20_000;

function logError(message: string, err: unknown): void {
  console.error(
    JSON.stringify({ level: 'error', message, error: err instanceof Error ? err.message : String(err) })
  );
}

const started = startAgent(process.env);
started
  .then(() => console.log(JSON.stringify({ level: 'info', message: 'agent running; press Ctrl+C or send SIGTERM to stop' })))
  .catch((err: unknown) => {
    logError('agent failed to start', err);
    process.exit(1);
  });

let shuttingDown = false;
function shutdown(reason: string, code: number): void {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(JSON.stringify({ level: 'info', message: 'shutdown requested', reason }));
  const force = setTimeout(() => {
    logError('forced exit: DNS may not be restored', new Error('shutdown timed out'));
    process.exit(1);
  }, FORCE_EXIT_AFTER_MS);
  force.unref();
  started
    .then((agent) => agent.stop(), () => undefined)
    .then(() => process.exit(code))
    .catch((err: unknown) => {
      logError('error during shutdown; DNS may not be restored', err);
      process.exit(1);
    });
}

process.on('uncaughtException', (err) => {
  logError('uncaught exception', err);
  shutdown('uncaughtException', 1);
});
process.on('unhandledRejection', (reason) => {
  logError('unhandled promise rejection', reason);
  shutdown('unhandledRejection', 1);
});
process.on('SIGTERM', () => shutdown('SIGTERM', 0));
process.on('SIGINT', () => shutdown('SIGINT', 0));
