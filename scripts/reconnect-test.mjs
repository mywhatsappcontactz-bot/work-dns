import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import dnsPacket from 'dns-packet';
import { LinuxPlatformAdapter, LocalEventQueue, DnsStubServer } from '../apps/agent/dist/index.js';

const DEVICE = 'wlp58s0';
const CONN = 'Airtel_X25A_4650';
const RECOVERY = 'nmcli device modify ' + DEVICE + ' ipv4.dns "" ipv4.ignore-auto-dns no ipv6.dns "" ipv6.ignore-auto-dns no';
const RESOLV = '/etc/resolv.conf';
const token = fs.readFileSync(path.join(os.homedir(), 'gw-demo', 'demo-token'), 'utf8').trim();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-reconnect-'));

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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let cleaning = null;
function cleanup() {
  if (!cleaning) {
    cleaning = (async () => {
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
  return fs.readFileSync(RESOLV, 'utf8').split('\n').filter((l) => l.startsWith('nameserver ')).map((l) => l.slice(11).trim());
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
  await stub.start();
  console.log('stub listening on 127.0.0.1:53');
  const direct = await directQuery('mail.google.com');
  if (!(direct.rcode === 0 && direct.answers > 0)) throw new Error('stub is not answering; refusing to enforce');
  console.log('PASS stub answers directly');

  await adapter.setDnsLoopback(53);
  const enforced = await waitFor(() => onlyLoopback(nameservers()), 10000);
  if (!enforced) throw new Error('enforcement never appeared in resolv.conf');
  console.log('PASS enforced: resolv.conf = ' + nameservers().join(','));

  console.log('--- reconnecting wifi now: nmcli connection up "' + CONN + '" (internet may blip) ---');
  const t0 = Date.now();
  let upDone = false;
  let upResult = null;
  void run('nmcli', ['connection', 'up', CONN], 30000).then((r) => { upDone = true; upResult = r; });

  let last = nameservers().join(',');
  let upDoneAt = null;
  while (Date.now() - t0 < 40000) {
    await sleep(300);
    const now = nameservers().join(',');
    if (now !== last) {
      console.log('  +' + ((Date.now() - t0) / 1000).toFixed(1) + 's resolv.conf changed: ' + (now || '(no nameservers)'));
      last = now;
    }
    if (upDone && upDoneAt === null) upDoneAt = Date.now();
    if (upDoneAt !== null && Date.now() - upDoneAt > 6000) break;
  }
  console.log('nmcli connection up exit ' + (upResult ? upResult.code : 'unfinished') + ': ' + (upResult ? upResult.out.trim().slice(0, 200) : ''));

  const finalNs = nameservers();
  console.log('final resolv.conf nameservers: ' + (finalNs.join(',') || '(none)'));
  const probe = await run('getent', ['ahosts', 'facebook.com']);
  console.log('facebook.com lookup exit ' + probe.code + ' (2 = blocked, 0 = leaked through the router)');

  if (onlyLoopback(finalNs) && probe.code === 2) {
    verdict = 'SURVIVED: enforcement persisted across the wifi reconnect';
  } else if (!finalNs.includes('127.0.0.1')) {
    verdict = 'DROPPED: the reconnect reverted DNS to ' + (finalNs.join(',') || '(none)') + '; the agent needs a re-apply loop';
  } else {
    verdict = 'MIXED: resolv.conf = ' + finalNs.join(',') + ', facebook.com exit ' + probe.code + '; paste this output';
  }
} catch (err) {
  console.error('ERROR: ' + err.message);
  harnessFailed = true;
  verdict = 'HARNESS ERROR (no conclusion about reconnects)';
} finally {
  clearTimeout(watchdog);
  await cleanup();
  const restored = await waitFor(() => !nameservers().includes('127.0.0.1'), 10000);
  console.log('after restore, resolv.conf nameservers: ' + (nameservers().join(',') || '(none)'));
  if (!restored) console.error('STILL ON 127.0.0.1. Run this by hand: ' + RECOVERY);
  console.log('RESULT: ' + verdict);
  process.exit(harnessFailed || !restored ? 1 : 0);
}
