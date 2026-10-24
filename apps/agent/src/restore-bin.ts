import { LinuxPlatformAdapter } from './platform/linux-adapter.js';
import { runRestore } from './restore.js';

if (process.platform !== 'linux') {
  console.error(JSON.stringify({ level: 'error', message: 'restore supports Linux only' }));
  process.exit(1);
}

runRestore(new LinuxPlatformAdapter())
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    console.error(
      JSON.stringify({ level: 'error', message: 'restore crashed', error: err instanceof Error ? err.message : String(err) })
    );
    process.exit(1);
  });
