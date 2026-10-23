import { startGateway } from './main.js';

const FORCE_EXIT_AFTER_MS = 15_000;

function logError(message: string, err: unknown): void {
  console.error(
    JSON.stringify({ level: 'error', message, error: err instanceof Error ? err.message : String(err) })
  );
}

process.on('uncaughtException', (err) => {
  logError('uncaught exception: exiting', err);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  logError('unhandled promise rejection: exiting', reason);
  process.exit(1);
});

startGateway(process.env)
  .then((gateway) => {
    let shuttingDown = false;
    const shutdown = (signal: string): void => {
      if (shuttingDown) return;
      shuttingDown = true;
      console.log(JSON.stringify({ level: 'info', message: 'shutdown requested', signal }));
      const force = setTimeout(() => process.exit(1), FORCE_EXIT_AFTER_MS);
      force.unref();
      gateway
        .stop()
        .then(() => process.exit(0))
        .catch((err: unknown) => {
          logError('error during shutdown', err);
          process.exit(1);
        });
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  })
  .catch((err: unknown) => {
    logError('gateway failed to start', err);
    process.exit(1);
  });
