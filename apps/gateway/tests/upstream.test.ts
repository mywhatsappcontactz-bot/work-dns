import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import dnsPacket from 'dns-packet';
import { UpstreamResolver } from '../src/upstream.js';

const RESPONSE_FLAGS = dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE;

function query(name: string, id = 77): Buffer {
  return Buffer.from(
    dnsPacket.encode({
      type: 'query',
      id,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{ type: 'A', name }],
    })
  );
}

interface ResponseOptions {
  name?: string;
  id?: number;
  rcode?: number;
  ttl?: number;
  withAnswer?: boolean;
  soaMinimum?: number;
  soaTtl?: number;
  truncated?: boolean;
  type?: 'response' | 'query';
}

function response(opts: ResponseOptions = {}): Buffer {
  const name = opts.name ?? 'example.com';
  const withAnswer = opts.withAnswer ?? true;
  return Buffer.from(
    dnsPacket.encode({
      type: opts.type ?? 'response',
      id: opts.id ?? 0,
      flags: RESPONSE_FLAGS | (opts.rcode ?? 0) | (opts.truncated ? 0x200 : 0),
      questions: [{ type: 'A', name }],
      answers: withAnswer ? [{ type: 'A', name, ttl: opts.ttl ?? 300, data: '93.184.216.34' }] : [],
      authorities:
        opts.soaMinimum !== undefined
          ? [
              {
                type: 'SOA',
                name,
                ttl: opts.soaTtl ?? 120,
                data: {
                  mname: 'ns.example.com',
                  rname: 'hostmaster.example.com',
                  serial: 1,
                  refresh: 3600,
                  retry: 600,
                  expire: 86400,
                  minimum: opts.soaMinimum,
                },
              },
            ]
          : [],
    })
  );
}

function reply(body: Buffer, init: { status?: number; contentType?: string | null; contentLength?: string } = {}) {
  const status = init.status ?? 200;
  const headers = new Headers();
  if (init.contentType !== null) {
    headers.set('content-type', init.contentType ?? 'application/dns-message');
  }
  if (init.contentLength !== undefined) {
    headers.set('content-length', init.contentLength);
  }
  return {
    status,
    ok: status >= 200 && status < 300,
    headers,
    arrayBuffer: async () => new Uint8Array(body).buffer,
  };
}

const rcodeOf = (buf: Buffer): number => (buf[3] ?? 0) & 0x0f;

describe('UpstreamResolver', () => {
  let now: number;
  let fetchImpl: ReturnType<typeof vi.fn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  function make(overrides: ConstructorParameters<typeof UpstreamResolver>[0] = {}): UpstreamResolver {
    return new UpstreamResolver({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      now: () => now,
      ...overrides,
    });
  }

  beforeEach(() => {
    now = 1_000_000;
    fetchImpl = vi.fn();
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
  });

  it('sends ID 0 over https POST with strict options and returns the caller ID', async () => {
    fetchImpl.mockResolvedValueOnce(reply(response()));
    const out = await make().resolve(query('example.com', 4242));

    expect(out.readUInt16BE(0)).toBe(4242);
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe('https://cloudflare-dns.com/dns-query');
    expect(init.method).toBe('POST');
    expect(init.redirect).toBe('error');
    expect(init.headers['Content-Type']).toBe('application/dns-message');
    expect(dnsPacket.decode(init.body as Buffer).id).toBe(0);
  });

  it('caches answers, patches the caller ID, decays TTLs and expires entries', async () => {
    fetchImpl.mockResolvedValue(reply(response({ ttl: 300 })));
    const resolver = make();
    await resolver.resolve(query('example.com', 1));
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    now += 100_000;
    const hit = await resolver.resolve(query('example.com', 999));
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(hit.readUInt16BE(0)).toBe(999);
    expect(rcodeOf(hit)).toBe(0);
    expect(dnsPacket.decode(hit).answers?.[0]).toMatchObject({ ttl: 200 });

    now += 201_000; // 301 seconds after storing: expired
    await resolver.resolve(query('example.com', 5));
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('caches NXDOMAIN using the SOA negative TTL and preserves the response code', async () => {
    fetchImpl.mockResolvedValue(reply(response({ rcode: 3, withAnswer: false, soaMinimum: 60, soaTtl: 120 })));
    const resolver = make();
    await resolver.resolve(query('example.com'));

    now += 30_000;
    const hit = await resolver.resolve(query('example.com', 2));
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(rcodeOf(hit)).toBe(3);

    now += 31_000; // 61 seconds: past the 60 second negative TTL
    await resolver.resolve(query('example.com', 3));
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it.each([
    ['NXDOMAIN without SOA', { rcode: 3, withAnswer: false }],
    ['SERVFAIL', { rcode: 2, withAnswer: false, soaMinimum: 60 }],
    ['REFUSED', { rcode: 5, withAnswer: false, soaMinimum: 60 }],
    ['truncated response', { truncated: true }],
  ])('does not cache %s', async (_label, opts) => {
    fetchImpl.mockImplementation(async () => reply(response(opts)));
    const resolver = make();
    await resolver.resolve(query('example.com'));
    await resolver.resolve(query('example.com'));
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(resolver.getCacheSize()).toBe(0);
  });

  it.each([
    ['wrong id', () => reply(response({ id: 5 }))],
    ['wrong question', () => reply(response({ name: 'other.com' }))],
    ['not a response', () => reply(response({ type: 'query' }))],
    ['garbage bytes', () => reply(Buffer.from('definitely not dns'))],
    ['wrong content type', () => reply(response(), { contentType: 'text/html' })],
    ['missing content type', () => reply(response(), { contentType: null })],
    ['non-200 status', () => reply(response(), { status: 502 })],
    ['declared oversize body', () => reply(response(), { contentLength: '999999' })],
  ])('rejects an invalid upstream response: %s', async (_label, makeReply) => {
    fetchImpl.mockImplementation(async () => makeReply());
    const resolver = make();
    await expect(resolver.resolve(query('example.com'))).rejects.toThrow();
    expect(fetchImpl).toHaveBeenCalledTimes(2); // primary, then secondary
    expect(errorSpy).toHaveBeenCalled();
    expect(resolver.getCacheSize()).toBe(0);
  });

  it('rejects responses larger than maxResponseBytes', async () => {
    fetchImpl.mockImplementation(async () => reply(response()));
    await expect(make({ maxResponseBytes: 20 }).resolve(query('example.com'))).rejects.toThrow(/too large/i);
  });

  it('falls back to the secondary when the primary response is invalid, and logs why', async () => {
    fetchImpl
      .mockResolvedValueOnce(reply(response({ id: 9 })))
      .mockResolvedValueOnce(reply(response()));
    const out = await make().resolve(query('example.com', 12));
    expect(out.readUInt16BE(0)).toBe(12);
    expect(fetchImpl.mock.calls.map((call) => call[0])).toEqual([
      'https://cloudflare-dns.com/dns-query',
      'https://9.9.9.9/dns-query',
    ]);
    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(String(errorSpy.mock.calls[0]![0])).toContain('id mismatch');
  });

  it('bounds the cache and evicts the least recently used entry', async () => {
    fetchImpl.mockImplementation(async (_url: string, init: { body: Buffer }) => {
      const asked = dnsPacket.decode(init.body).questions![0]!.name;
      return reply(response({ name: asked }));
    });
    const resolver = make({ maxCacheEntries: 2 });
    await resolver.resolve(query('a.example.com'));
    await resolver.resolve(query('b.example.com'));
    await resolver.resolve(query('c.example.com'));
    expect(resolver.getCacheSize()).toBe(2);
    expect(fetchImpl).toHaveBeenCalledTimes(3);

    await resolver.resolve(query('a.example.com')); // was evicted
    expect(fetchImpl).toHaveBeenCalledTimes(4);
    await resolver.resolve(query('c.example.com')); // still cached
    expect(fetchImpl).toHaveBeenCalledTimes(4);
  });

  it('coalesces identical concurrent queries into one upstream request', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    fetchImpl.mockImplementation(() => gate.then(() => reply(response())));
    const resolver = make();

    const first = resolver.resolve(query('example.com', 1));
    const second = resolver.resolve(query('example.com', 2));
    release();
    const [a, b] = await Promise.all([first, second]);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(a.readUInt16BE(0)).toBe(1);
    expect(b.readUInt16BE(0)).toBe(2);
  });

  it('normalizes case when building cache keys', async () => {
    fetchImpl.mockResolvedValue(reply(response({ name: 'example.com' })));
    const resolver = make();
    await resolver.resolve(query('EXAMPLE.com'));
    await resolver.resolve(query('example.COM'));
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('rejects malformed queries and multi-question queries without fetching', async () => {
    const resolver = make();
    await expect(resolver.resolve(Buffer.alloc(5))).rejects.toThrow();
    const twoQuestions = Buffer.from(
      dnsPacket.encode({
        type: 'query',
        id: 1,
        questions: [
          { type: 'A', name: 'a.com' },
          { type: 'A', name: 'b.com' },
        ],
      })
    );
    await expect(resolver.resolve(twoQuestions)).rejects.toThrow(/exactly one question/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('aborts slow upstream requests after the timeout and reports failure', async () => {
    fetchImpl.mockImplementation(
      (_url: string, init: { signal: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new Error('aborted')));
        })
    );
    await expect(make({ timeoutMs: 20 }).resolve(query('example.com'))).rejects.toThrow(/aborted/);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('validates configuration', () => {
    expect(() => new UpstreamResolver()).not.toThrow();
    expect(() => new UpstreamResolver({ primaryUrl: 'http://1.1.1.1/dns-query' })).toThrow(/https/i);
    expect(() => new UpstreamResolver({ primaryUrl: 'http://127.0.0.1/dns-query', allowInsecureHttp: true })).not.toThrow();
    expect(() => new UpstreamResolver({ secondaryUrl: 'not a url' })).toThrow(/invalid upstream url/i);
    expect(() => new UpstreamResolver({ maxCacheEntries: 0 })).toThrow(/maxCacheEntries/);
    expect(() => new UpstreamResolver({ minTtlSeconds: 100, maxTtlSeconds: 10 })).toThrow(/minTtlSeconds/);
  });
});
