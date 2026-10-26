import fs from 'node:fs';
import {
  SqliteEventStore,
  buildReport,
  filterEvents,
  eventsToCsv,
  formatReportText,
  readCheckpointFile,
  publicKeyIdOf,
} from '../packages/events/dist/index.js';

const USAGE = `Usage: node scripts/audit-cli.mjs --db FILE --company ID [options]
  --checkpoints FILE   signed checkpoint file (JSON lines)
  --pubkey FILE        public key (PEM) for the checkpoints; repeatable
  --device ID          only events for this device
  --domain NAME        only this domain and its subdomains
  --type A,B           only these event types
  --from ISO --to ISO  occurredAt range (from inclusive, to exclusive)
  --format NAME        summary (default), csv or json
Exit codes: 0 verified, 1 partial, 2 failed, 64 usage error, 70 other error.
Audit a COPY of the database: stop the gateway, then copy the .db, -wal and -shm files.
This tool opens the store with write access.`;

function die(message) {
  console.error(message);
  console.error(USAGE);
  process.exit(64);
}

const VALUE_FLAGS = new Set(['--db', '--company', '--checkpoints', '--pubkey', '--device', '--domain', '--type', '--from', '--to', '--format']);
const args = process.argv.slice(2);
const opts = { pubkeys: [] };
for (let i = 0; i < args.length; i += 1) {
  const flag = args[i];
  if (flag === '--help' || flag === '-h') {
    console.log(USAGE);
    process.exit(0);
  }
  if (!VALUE_FLAGS.has(flag)) die(`unknown option: ${flag}`);
  const value = args[i + 1];
  if (value === undefined || value.startsWith('--')) die(`${flag} needs a value`);
  i += 1;
  if (flag === '--pubkey') opts.pubkeys.push(value);
  else opts[flag.slice(2)] = value;
}

if (!opts.db) die('--db is required');
if (!opts.company) die('--company is required');
if (!fs.existsSync(opts.db)) die(`database file not found: ${opts.db}`);
const format = opts.format ?? 'summary';
if (!['summary', 'csv', 'json'].includes(format)) die(`unknown format: ${format}`);
if (opts.checkpoints && !fs.existsSync(opts.checkpoints)) die(`checkpoint file not found: ${opts.checkpoints}`);
for (const file of opts.pubkeys) {
  if (!fs.existsSync(file)) die(`public key file not found: ${file}`);
}

const filter = {};
if (opts.device) filter.deviceId = opts.device;
if (opts.domain) filter.domain = opts.domain;
if (opts.type) filter.types = opts.type.split(',').map((t) => t.trim()).filter(Boolean);
if (opts.from) filter.from = opts.from;
if (opts.to) filter.to = opts.to;

let store;
try {
  store = new SqliteEventStore(opts.db);
  const publicKeys = {};
  for (const file of opts.pubkeys) {
    const pem = fs.readFileSync(file, 'utf8');
    publicKeys[publicKeyIdOf(pem)] = pem;
  }
  const checkpoints = opts.checkpoints ? readCheckpointFile(opts.checkpoints) : null;
  const report = buildReport(store, opts.company, { filter, checkpoints, publicKeys });
  const events = filterEvents(store.readAll(opts.company), filter);

  if (format === 'csv') {
    process.stdout.write(eventsToCsv(events));
    console.error(`integrity: ${report.integrity}`);
    for (const caveat of report.caveats) console.error(`caveat: ${caveat}`);
  } else if (format === 'json') {
    console.log(JSON.stringify({ report, events }, null, 2));
  } else {
    process.stdout.write(formatReportText(report));
  }
  process.exitCode = { verified: 0, partial: 1, failed: 2 }[report.integrity];
} catch (err) {
  console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = err instanceof RangeError ? 64 : 70;
} finally {
  try {
    store?.close();
  } catch {
    /* nothing useful to do if closing fails */
  }
}
