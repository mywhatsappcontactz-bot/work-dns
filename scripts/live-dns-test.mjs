import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import dnsPacket from 'dns-packet';
import { LinuxPlatformAdapter, LocalEventQueue, DnsStubServer } from '../apps/agent/dist/index.js';

const RECOVERY = 'nmcli device modify wlp58s0 ipv4.dns "" ipv4.ignore-auto-dns no ipv6.dns "" ipv6.ignore-auto-dns no';
const token = fs.readFileSync(path.join(os.homedir(), 'gw-demo', 'demo-token'), 'utf8').trim();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-live-'));

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
  console.error('WATCHDOG: 60 s elapsed, restoring');
  void cleanup().then(() => process.exit(2));
}, 60_000);

function run(file, args) {
  return new Promise((resolve) => {
    execFile(file, args, { timeout: 8000 }, (err, stdout, stderr) => {
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

let failed = false;
function check(label, ok, detail) {
  console.log((ok ? 'PASS ' : 'FAIL ') + label + (detail ? ' (' + detail + ')' : ''));
  if (!ok) failed = true;
}

const RESOLV = '/etc/resolv.conf';
function nameservers(text) {
  return text.split('\n').filter((l) => l.startsWith('nameserver ')).map((l) => l.slice(11).trim());
}
async function waitForResolv(predicate, timeoutMs) {
  const end = Date.now() + timeoutMs;
  let text = '';
  while (Date.now() < end) {
    text = fs.readFileSync(RESOLV, 'utf8');
    if (predicate(text)) return { ok: true, text };
    await new Promise((r) => setTimeout(r, 200));
  }
  return { ok: false, text };
}

try {
  await stub.start();
  console.log('stub listening on 127.0.0.1:53');
  const direct = await directQuery('mail.google.com');
  check('stub answers directly, before enforcement', direct.rcode === 0 && direct.answers > 0, JSON.stringify(direct));
  if (failed) throw new Error('stub is not answering; refusing to enforce');

  await adapter.setDnsLoopback(53);
  const enforced = await waitForResolv((t) => nameservers(t).length > 0 && nameservers(t).every((n) => n === '127.0.0.1'), 10000);
  console.log('--- /etc/resolv.conf while enforced: ---');
  console.log(enforced.text);
  check('resolv.conf points only at 127.0.0.1', enforced.ok);
  if (!enforced.ok) throw new Error('enforcement never appeared in resolv.conf');

  const allowed = await run('getent', ['ahosts', 'mail.google.com']);
  check('mail.google.com resolves through the stub (allowed)', allowed.code === 0);
  const blocked = await run('getent', ['ahosts', 'facebook.com']);
  check('facebook.com is blocked (not found)', blocked.code === 2, 'getent exit ' + blocked.code);
} catch (err) {
  console.error('ERROR: ' + err.message);
  failed = true;
} finally {
  clearTimeout(watchdog);
  await cleanup();
  const restored = await waitForResolv((t) => !nameservers(t).includes('127.0.0.1'), 10000);
  console.log('--- /etc/resolv.conf after restore: ---');
  console.log(restored.text);
  check('resolv.conf no longer points at 127.0.0.1', restored.ok);
  if (!restored.ok) console.error('Run this by hand: ' + RECOVERY);
  console.log(failed ? 'RESULT: FAIL' : 'RESULT: PASS');
  process.exit(failed ? 1 : 0);
}
