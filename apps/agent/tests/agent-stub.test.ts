import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import dgram from 'node:dgram';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import dnsPacket from 'dns-packet';
import { DnsStubServer, DnsStubConfig } from '../src/dns-stub.js';
import { LocalEventQueue } from '../src/local-queue.js';
import { MockPlatformAdapter } from '../src/platform/mock-adapter.js';

const GATEWAY = 'https://gateway.example.com/dns-query';
const FALLBACK = 'https://1.1.1.1/dns-query';
const FLAGS = dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE;
const MIN_FAIL_OPEN_MS = 16 * 60_000;

function query(name: string, id = 101): Buffer {
  return Buffer.from(
    dnsPacket.encode({ type: 'query', id, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'A', name }] })
  );
}

function answer(name: string, id = 101): Buffer {
  return Buffer.from(
    dnsPacket.encode({
      type: 'response',
      id,
      flags: FLAGS,
      questions: [{ type: 'A', name }],
      answers: [{ type: 'A', name, ttl: 300, data: '102.134.1.20' }],
    })
  );
}

function nxdomain(name: string, id = 101): Buffer {
  return Buffer.from(
    dnsPacket.encode({ type: 'response', id, flags: FLAGS | 3, questions: [{ type: 'A', name }], answers: [] })
  );
}

function reply(
  body: Buffer,
  init: { status?: number; contentType?: string | null; policy?: string } = {}
) {
  const headers = new Headers();
  if (init.contentType !== null) {
    headers.set('content-type', init.contentType ?? 'application/dns-message');
  }
  if (init.policy) {
    headers.set('x-policy-action', init.policy);
  }
  return {
    status: init.status ?? 200,
    headers,
    arrayBuffer: async () => new Uint8Array(body).buffer,
  };
}

const rcodeOf = (buf: Buffer): number => (buf[3] ?? 0) & 0x0f;

describe('DnsStubServer', () => {
  let base: string;
  let now: number;
  let platform: MockPlatformAdapter;
  let queue: LocalEventQueue;
  let fetchMock: ReturnType<typeof vi.fn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let stubs: DnsStubServer[];

  function make(overrides: Partial<DnsStubConfig> = {}): DnsStubServer {
    const stub = new DnsStubServer(
      {
        loopbackPort: 0,
        gatewayUrl: GATEWAY,
        deviceToken: 'valid-test-device-token',
        gatewayTimeoutMs: 100,
        failOpenMaxMinutes: 15,
        fetchImpl: fetchMock as unknown as typeof fetch,
        now: () => now,
        ...overrides,
      },
      platform,
      queue
    );
    stubs.push(stub);
    return stub;
  }

  const callsTo = (url: string): number => fetchMock.mock.calls.filter((call) => call[0] === url).length;

  beforeEach(() => {
    base = fs.mkdtempSync(path.join(os.tmpdir(), 'work-dns-stub-'));
    now = 1_000_000;
    platform = new MockPlatformAdapter();
    queue = new LocalEventQueue({ filePath: path.join(base, 'q.jsonl'), now: () => now });
    fetchMock = vi.fn();
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    stubs = [];
  });

  afterEach(async () => {
    for (const stub of stubs) {
      await stub.stop();
    }
    errorSpy.mockRestore();
    fs.rmSync(base, { recursive: true, force: true });
  });

  it('forwards the query with the bearer token and returns the gateway answer', async () => {
    fetchMock.mockResolvedValue(reply(answer('mail.google.com', 7), { policy: 'ALLOW' }));
    const out = await make().handleQuery(query('mail.google.com', 7));

    expect(dnsPacket.decode(out).answers).toHaveLength(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(GATEWAY);
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer valid-test-device-token');
    expect(init.headers['Content-Type']).toBe('application/dns-message');
    expect(platform.notifications).toHaveLength(0);
  });

  it('passes a real NXDOMAIN through and notifies once per cooldown', async () => {
    fetchMock.mockImplementation(async () => reply(nxdomain('blocked-site.com'), { policy: 'BLOCK' }));
    const stub = make();

    const first = await stub.handleQuery(query('blocked-site.com'));
    expect(dnsPacket.decode(first).rcode).toBe('NXDOMAIN');
    expect(dnsPacket.decode(first).id).toBe(101);
    expect(platform.notifications).toHaveLength(1);
    expect(platform.notifications[0]!.title).toMatch(/access blocked/i);
    expect(platform.notifications[0]!.message).toContain('blocked-site.com');
    expect(platform.notifications[0]!.actionUrl).toBeUndefined();

    await stub.handleQuery(query('blocked-site.com'));
    expect(platform.notifications).toHaveLength(1);

    now += 31_000;
    await stub.handleQuery(query('blocked-site.com'));
    expect(platform.notifications).toHaveLength(2);
  });

  it('offers a request-access link only when configured, with the domain encoded', async () => {
    fetchMock.mockResolvedValue(reply(nxdomain('blocked-site.com'), { policy: 'BLOCK' }));
    await make({ requestAccessUrl: 'https://portal.example.com/request' }).handleQuery(query('blocked-site.com'));
    expect(platform.notifications[0]!.actionUrl).toBe('https://portal.example.com/request?domain=blocked-site.com');
  });

  it('does not trust the BLOCK header unless the answer really is NXDOMAIN', async () => {
    fetchMock.mockResolvedValue(reply(answer('mail.google.com'), { policy: 'BLOCK' }));
    await make().handleQuery(query('mail.google.com'));
    expect(platform.notifications).toHaveLength(0);
  });

  it.each([
    ['network error', () => Promise.reject(new Error('connection refused'))],
    ['HTTP 503', () => Promise.resolve(reply(Buffer.from('{}'), { status: 503, contentType: 'application/json' }))],
  ])('fails open on %s, queues the attempt and uses the fallback resolver', async (_label, gatewayBehaviour) => {
    fetchMock.mockImplementation(async (url: string) =>
      url === GATEWAY ? gatewayBehaviour() : reply(answer('vendor-portal.ng', 102))
    );
    const stub = make();
    const out = await stub.handleQuery(query('vendor-portal.ng', 102));

    expect(dnsPacket.decode(out).answers).toHaveLength(1);
    expect(stub.getState()).toBe('FAIL_OPEN_ACTIVE');
    expect(queue.getItems()).toHaveLength(1);
    expect(queue.getItems()[0]).toMatchObject({ domain: 'vendor-portal.ng', actionTaken: 'FAIL_OPEN_ALLOWED' });
    expect(platform.notifications.filter((n) => /offline/i.test(n.title))).toHaveLength(1);
    expect(callsTo(FALLBACK)).toBe(1);
  });

  it.each([401, 403])('returns a real SERVFAIL for HTTP %i and never falls back', async (status) => {
    fetchMock.mockResolvedValue(reply(Buffer.from('{}'), { status, contentType: 'application/json' }));
    const stub = make();
    const out = await stub.handleQuery(query('mail.google.com', 55));

    expect(rcodeOf(out)).toBe(2);
    expect(dnsPacket.decode(out).id).toBe(55);
    expect(callsTo(FALLBACK)).toBe(0);
    expect(stub.getState()).toBe('ONLINE');
    expect(queue.getItems()[0]).toMatchObject({ actionTaken: 'AUTH_REJECTED' });
    expect(platform.notifications.some((n) => /not authorized/i.test(n.title))).toBe(true);
    expect(errorSpy).toHaveBeenCalled();
  });

  it('treats rate limiting (429) as an error, not as a reason to fail open', async () => {
    fetchMock.mockResolvedValue(reply(Buffer.from('{}'), { status: 429, contentType: 'application/json' }));
    const stub = make();
    const out = await stub.handleQuery(query('mail.google.com'));
    expect(rcodeOf(out)).toBe(2);
    expect(callsTo(FALLBACK)).toBe(0);
    expect(stub.getState()).toBe('ONLINE');
  });

  it.each([
    ['wrong id', () => reply(answer('mail.google.com', 999))],
    ['wrong question', () => reply(answer('other.com', 101))],
    ['wrong content type', () => reply(answer('mail.google.com'), { contentType: 'text/html' })],
    ['garbage bytes', () => reply(Buffer.from('not dns at all, sorry'))],
  ])('answers SERVFAIL for an invalid gateway response (%s) without failing open', async (_label, makeReply) => {
    fetchMock.mockImplementation(async () => makeReply());
    const stub = make();
    const out = await stub.handleQuery(query('mail.google.com'));
    expect(rcodeOf(out)).toBe(2);
    expect(callsTo(FALLBACK)).toBe(0);
    expect(stub.getState()).toBe('ONLINE');
  });

  it('stops failing open after the time limit and answers SERVFAIL without the fallback', async () => {
    fetchMock.mockImplementation(async (url: string) => {
      if (url === GATEWAY) throw new Error('connection refused');
      return reply(answer('vendor-portal.ng'));
    });
    const stub = make();
    await stub.handleQuery(query('vendor-portal.ng'));
    expect(callsTo(FALLBACK)).toBe(1);

    now += MIN_FAIL_OPEN_MS;
    const out = await stub.handleQuery(query('vendor-portal.ng'));
    expect(rcodeOf(out)).toBe(2);
    expect(stub.getState()).toBe('FAIL_CLOSED');
    expect(callsTo(FALLBACK)).toBe(1);
    expect(queue.getItems().some((e) => e.actionTaken === 'OFFLINE_BLOCKED')).toBe(true);
  });

  it('returns SERVFAIL when the fallback resolver is invalid too', async () => {
    fetchMock.mockImplementation(async (url: string) => {
      if (url === GATEWAY) throw new Error('connection refused');
      return reply(Buffer.from('nope'), { status: 502, contentType: 'text/plain' });
    });
    const out = await make().handleQuery(query('vendor-portal.ng'));
    expect(rcodeOf(out)).toBe(2);
  });

  it('on recovery delivers queued events to the sink and empties the queue', async () => {
    let gatewayUp = false;
    fetchMock.mockImplementation(async (url: string) => {
      if (url === GATEWAY) {
        if (!gatewayUp) throw new Error('connection refused');
        return reply(answer('mail.google.com', 1));
      }
      return reply(answer('vendor-portal.ng', 1));
    });
    const sink = vi.fn().mockResolvedValue(undefined);
    const stub = make({ eventSink: sink });

    await stub.handleQuery(query('vendor-portal.ng', 1));
    expect(queue.getCount()).toBe(1);

    gatewayUp = true;
    await stub.handleQuery(query('mail.google.com', 1));
    expect(stub.getState()).toBe('ONLINE');
    await vi.waitFor(() => expect(queue.getCount()).toBe(0));
    expect(sink).toHaveBeenCalledTimes(1);
    expect(sink.mock.calls[0]![0][0]).toMatchObject({ domain: 'vendor-portal.ng' });
  });

  it('on recovery without a sink keeps the events queued and never claims they were sent', async () => {
    let gatewayUp = false;
    fetchMock.mockImplementation(async (url: string) => {
      if (url === GATEWAY) {
        if (!gatewayUp) throw new Error('connection refused');
        return reply(answer('mail.google.com', 1));
      }
      return reply(answer('vendor-portal.ng', 1));
    });
    const stub = make();
    await stub.handleQuery(query('vendor-portal.ng', 1));
    gatewayUp = true;
    await stub.handleQuery(query('mail.google.com', 1));

    expect(queue.getCount()).toBe(1);
    const restored = platform.notifications.find((n) => /restored/i.test(n.title))!;
    expect(restored.message).not.toMatch(/flush|sent|delivered/i);
  });

  it('keeps queued events when the sink fails on recovery', async () => {
    let gatewayUp = false;
    fetchMock.mockImplementation(async (url: string) => {
      if (url === GATEWAY) {
        if (!gatewayUp) throw new Error('connection refused');
        return reply(answer('mail.google.com', 1));
      }
      return reply(answer('vendor-portal.ng', 1));
    });
    const sink = vi.fn().mockRejectedValue(new Error('server down'));
    const stub = make({ eventSink: sink });
    await stub.handleQuery(query('vendor-portal.ng', 1));
    gatewayUp = true;
    await stub.handleQuery(query('mail.google.com', 1));
    await vi.waitFor(() => expect(sink).toHaveBeenCalled());
    expect(queue.getCount()).toBe(1);
  });

  it('answers FORMERR with the original id for malformed queries', async () => {
    const garbage = Buffer.alloc(20, 0xff);
    garbage.writeUInt16BE(0xabcd, 0);
    const out = await make().handleQuery(garbage);
    expect(dnsPacket.decode(out).id).toBe(0xabcd);
    expect(rcodeOf(out)).toBe(1);
    expect(fetchMock).not.toHaveBeenCalled();

    const tiny = await make().handleQuery(Buffer.from([1, 2, 3]));
    expect(rcodeOf(tiny)).toBe(1);
  });

  it('refuses queries beyond the concurrency limit with SERVFAIL', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    fetchMock.mockImplementation(async () => {
      await gate;
      return reply(answer('mail.google.com', 1));
    });
    const stub = make({ maxConcurrentQueries: 1 });

    const first = stub.handleQuery(query('mail.google.com', 1));
    const second = await stub.handleQuery(query('other.example.com', 2));
    expect(rcodeOf(second)).toBe(2);
    expect(dnsPacket.decode(second).id).toBe(2);

    release();
    expect(dnsPacket.decode(await first).answers).toHaveLength(1);
    const third = await stub.handleQuery(query('mail.google.com', 3));
    expect(rcodeOf(third)).toBe(0);
  });

  it('serves real UDP queries on loopback and releases the port on stop()', async () => {
    fetchMock.mockResolvedValue(reply(answer('mail.google.com', 4321)));
    const stub = make();
    await stub.start();
    const port = stub.getPort()!;
    expect(port).toBeGreaterThan(0);
    await expect(stub.start()).rejects.toThrow(/already started/i);

    const response = await new Promise<Buffer>((resolve, reject) => {
      const socket = dgram.createSocket('udp4');
      const timer = setTimeout(() => {
        socket.close();
        reject(new Error('timed out waiting for the stub'));
      }, 2000);
      socket.on('message', (msg) => {
        clearTimeout(timer);
        socket.close();
        resolve(msg);
      });
      socket.send(query('mail.google.com', 4321), port, '127.0.0.1');
    });
    expect(dnsPacket.decode(response).id).toBe(4321);
    expect(dnsPacket.decode(response).answers).toHaveLength(1);

    await stub.stop();
    expect(stub.getPort()).toBeNull();
  });

  it('validates configuration', () => {
    const base = { loopbackPort: 0, deviceToken: 't', fetchImpl: fetchMock as unknown as typeof fetch };
    const build = (extra: Partial<DnsStubConfig>) => () =>
      new DnsStubServer({ ...base, gatewayUrl: GATEWAY, ...extra }, platform, queue);

    expect(build({})).not.toThrow();
    expect(build({ gatewayUrl: 'http://gateway.example.com/dns-query' })).toThrow(/https/i);
    expect(build({ gatewayUrl: 'http://127.0.0.1:8053/dns-query' })).not.toThrow();
    expect(build({ gatewayUrl: 'not a url' })).toThrow(/invalid gateway url/i);
    expect(build({ fallbackUpstreamDoh: 'http://1.1.1.1/dns-query' })).toThrow(/https/i);
    expect(build({ deviceToken: '  ' })).toThrow(/deviceToken/);
    expect(build({ failOpenMaxMinutes: 0 })).toThrow(/failOpenMaxMinutes/);
    expect(build({ maxConcurrentQueries: 0 })).toThrow(/maxConcurrentQueries/);
    expect(build({ loopbackPort: 70_000 })).toThrow(/loopbackPort/);
  });
});
