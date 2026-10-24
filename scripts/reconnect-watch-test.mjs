import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import dnsPacket from 'dns-packet';
import {
  LinuxPlatformAdapter,
  LocalEventQueue,
  DnsStubServer,
  DnsDriftWatcher,
  spawnNmcliMonitor,
} from '../apps/agent/dist/index.js';

const DEVICE = 'wlp58s0';
const CONN = 'Airtel_X25A_4650';
const RECOVERY = 'nmcli device modify ' + DEVICE + ' ipv4.dns "" ipv4.ignore-auto-dns no ipv6.dns "" ipv6.ignore-auto-dns no';
const RESOLV = '/etc/resolv.conf';
const token = fs.readFileSync(path.join(os.homedir(), 'gw-demo', 'demo-token'), 'utf8').trim();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-watch-'));
const T0 = Date.now();
const stamp = () => '+' + ((Date.now() - T0) / 1000).toFixed(1) + 's';

const adapter = new LinuxPlatformAdapter();
const queue = new LocalEventQueue({ filePath: path.join(tmp, 'queue.json') });
const stub = new DnsStubServer(
  {
    loopbackPort: 53,
    gatewayUrl: 'http://127.0.0.1:8053/dns-query',
    deviceToken: token,
    fallbackUpstreamDoh: 'https://cloudflare-dns.com/dns-query',
    gatewayTimeoutMs: 2000,
  },
  adapter,
  queue
);
const watcher = new DnsDriftWatcher({
  check: () => adapter.reapplyIfDrifted(53),
  startMonitor: spawnNmcliMonitor,
  intervalMs: 2000,
  debounceMs: 300,
  log: (level, message, fields) => console.log(stamp() + ' [watcher ' + level + '] ' + message + (fields && fields.error ? ': ' + fields.error : '')),
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let cleaning = null;
function cleanup() {
  if (!cleaning) {
    cleaning = (async () => {
      await watcher.stop(); // first, so it cannot re-enforce while we restore
      try {
        await adapter.restoreDns();
        console.log('restoreDns: done');
      } catch (err) {
        console.error('RESTORE FAILED: ' + err.message);
        console.error('Run this by hand: ' + RECOVERY);
      }
      await stub.stop();
      fs.rmSync(tmp, { recursive: true, force: true });
    })();
  }
  return cleaning;
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => void cleanup().then(() => process.exit(130)));
}
process.on('uncaughtException', (err) => {
  console.error('uncaught: ' + err.message);
  void cleanup().then(() => process.exit(1));
});
const watchdog = setTimeout(() => {
  console.error('WATCHDOG: 90 s elapsed, restoring');
  void cleanup().then(() => process.exit(2));
}, 90_000);

function run(file, args, timeout) {
  return new Promise((resolve) => {
    execFile(file, args, { timeout: timeout ?? 8000 }, (err, stdout, stderr) => {
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, out: String(stdout) + String(stderr) });
    });
  });
}

function directQuery(name) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    const timer = setTimeout(() => { sock.close(); reject(new Error('no reply in 3 s')); }, 3000);
    sock.on('message', (msg) => {
      clearTimeout(timer);
      sock.close();
      resolve({ rcode: msg[3] & 0x0f, answers: dnsPacket.decode(msg).answers.length });
    });
    const q = dnsPacket.encode({ type: 'query', id: 7, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'A', name }] });
    sock.send(q, 53, '127.0.0.1');
  });
}

function nameservers() {
  try {
    return fs.readFileSync(RESOLV, 'utf8').split('\n').filter((l) => l.startsWith('nameserver ')).map((l) => l.slice(11).trim());
  } catch {
    return [];
  }
}
async function waitFor(predicate, timeoutMs) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (predicate()) return true;
    await sleep(200);
  }
  return predicate();
}
const onlyLoopback = (ns) => ns.length > 0 && ns.every((n) => n === '127.0.0.1');

let harnessFailed = false;
let verdict = 'NOT REACHED';

try {
  const gwQuery = dnsPacket.encode({ type: 'query', id: 9, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'A', name: 'mail.google.com' }] });
  let gwStatus = 'unreachable';
  try {
    const res = await fetch('http://127.0.0.1:8053/dns-query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/dns-message', Authorization: 'Bearer ' + token },
      body: gwQuery,
      signal: AbortSignal.timeout(3000),
    });
    gwStatus = 'HTTP ' + res.status;
  } catch (err) {
    gwStatus = 'unreachable: ' + err.message;
  }
  if (gwStatus !== 'HTTP 200') throw new Error('gateway check failed (' + gwStatus + '): start the gateway in terminal 1 first');
  console.log('PASS gateway answers (' + gwStatus + ')');
  await stub.start();
  console.log(stamp() + ' stub listening on 127.0.0.1:53');
  const direct = await directQuery('mail.google.com');
  if (!(direct.rcode === 0 && direct.answers > 0)) throw new Error('stub is not answering; refusing to enforce');
  console.log('PASS stub answers directly');

  await adapter.setDnsLoopback(53);
  if (!(await waitFor(() => onlyLoopback(nameservers()), 10000))) throw new Error('enforcement never appeared in resolv.conf');
  console.log('PASS enforced: resolv.conf = ' + nameservers().join(','));

  watcher.start();
  console.log(stamp() + ' watcher started (timer 2 s + nmcli monitor)');
  await sleep(1500);

  console.log(stamp() + ' --- reconnecting wifi: nmcli connection up "' + CONN + '" (internet will blip) ---');
  const t0 = Date.now();
  let upDone = false;
  let upResult = null;
  void run('nmcli', ['connection', 'up', CONN], 30000).then((r) => { upDone = true; upResult = r; });

  let last = nameservers().join(',');
  let leakStart = null;
  let leakTotalMs = 0;
  let sawLeak = false;
  let reenforcedAfterMs = null;
  let stableSince = null;
  while (Date.now() - t0 < 40000) {
    await sleep(100);
    const ns = nameservers();
    const now = ns.join(',');
    if (now !== last) {
      console.log('  ' + stamp() + ' resolv.conf: ' + (now || '(no nameservers)'));
      last = now;
    }
    const loop = onlyLoopback(ns);
    if (!loop && leakStart === null) {
      leakStart = Date.now();
      sawLeak = true;
    }
    if (loop && leakStart !== null) {
      leakTotalMs += Date.now() - leakStart;
      leakStart = null;
      reenforcedAfterMs = Date.now() - t0;
    }
    if (sawLeak && loop && upDone) {
      if (stableSince === null) stableSince = Date.now();
      if (Date.now() - stableSince > 3000) break;
    } else {
      stableSince = null;
    }
  }
  if (leakStart !== null) leakTotalMs += Date.now() - leakStart;
  console.log('nmcli connection up exit ' + (upResult ? upResult.code : 'unfinished'));
  console.log('time resolv.conf was NOT loopback-only: ' + (leakTotalMs / 1000).toFixed(1) + ' s');

  const finalNs = nameservers();
  console.log('final resolv.conf nameservers: ' + (finalNs.join(',') || '(none)'));
  const probe = await run('getent', ['ahosts', 'facebook.com']);
  console.log('facebook.com lookup exit ' + probe.code + ' (2 = blocked, 0 = leaked)');

  if (!sawLeak) {
    verdict = 'INCONCLUSIVE: the reconnect never changed resolv.conf';
  } else if (onlyLoopback(finalNs) && probe.code === 2) {
    verdict = 'RE-ENFORCED: watcher restored enforcement; unenforced window ' + (leakTotalMs / 1000).toFixed(1) + ' s';
  } else {
    verdict = 'NOT RE-ENFORCED: resolv.conf = ' + (finalNs.join(',') || '(none)') + ', facebook.com exit ' + probe.code + '; paste this output';
  }
} catch (err) {
  console.error('ERROR: ' + err.message);
  harnessFailed = true;
  verdict = 'HARNESS ERROR (no conclusion)';
} finally {
  clearTimeout(watchdog);
  await cleanup();
  const restored = await waitFor(() => !nameservers().includes('127.0.0.1'), 10000);
  console.log('after restore, resolv.conf nameservers: ' + (nameservers().join(',') || '(none)'));
  if (!restored) console.error('STILL ON 127.0.0.1. Run this by hand: ' + RECOVERY);
  console.log('RESULT: ' + verdict);
  process.exit(harnessFailed || !restored ? 1 : 0);
}
