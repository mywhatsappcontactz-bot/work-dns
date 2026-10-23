import dnsPacket from 'dns-packet';

const DNS_MESSAGE_TYPE = 'application/dns-message';
const HEADER_LENGTH = 12;
const TRUNCATED_BIT = 0x02; // TC flag, in header byte 2

export interface UpstreamResolverConfig {
  primaryUrl: string; // default "https://9.9.9.9/dns-query"
  secondaryUrl: string; // default "https://cloudflare-dns.com/dns-query"
  timeoutMs: number;
  maxCacheEntries: number;
  maxResponseBytes: number;
  minTtlSeconds: number;
  maxTtlSeconds: number;
  /** Injectable for tests. */
  fetchImpl: typeof fetch;
  /** Clock in epoch milliseconds (injectable for tests). */
  now: () => number;
  /** Allow http:// upstream URLs (tests only). */
  allowInsecureHttp: boolean;
  /** How long a failing upstream is skipped before it is tried first again. 0 disables. */
  failureCooldownMs: number;
}

interface CacheEntry {
  response: Buffer;
  storedAtMs: number;
  expiresAtMs: number;
  answerCount: number;
}

interface QuerySignature {
  key: string;
  name: string;
  type: string;
  className: string;
}

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function logError(message: string, fields: Record<string, unknown> = {}): void {
  console.error(JSON.stringify({ level: 'error', message, ...fields }));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function normalizeName(name: string): string {
  const lowered = name.toLowerCase();
  return lowered.endsWith('.') ? lowered.slice(0, -1) : lowered;
}

function ttlOf(record: unknown): number | undefined {
  if (isRecord(record) && typeof record.ttl === 'number' && Number.isFinite(record.ttl)) {
    return record.ttl;
  }
  return undefined;
}

function adjustTtls(records: unknown, elapsedSeconds: number): void {
  if (!Array.isArray(records)) return;
  for (const record of records) {
    if (isRecord(record) && typeof record.ttl === 'number') {
      record.ttl = Math.max(0, record.ttl - elapsedSeconds);
    }
  }
}

/** Negative-caching TTL (RFC 2308): the smaller of the SOA record TTL and its minimum field. */
function soaNegativeTtl(authorities: unknown): number | undefined {
  if (!Array.isArray(authorities)) return undefined;
  for (const record of authorities) {
    if (isRecord(record) && record.type === 'SOA' && isRecord(record.data) && typeof record.data.minimum === 'number') {
      const recordTtl = ttlOf(record);
      return recordTtl === undefined ? record.data.minimum : Math.min(recordTtl, record.data.minimum);
    }
  }
  return undefined;
}

function withId(response: Buffer, id: number): Buffer {
  const out = Buffer.from(response);
  out.writeUInt16BE(id, 0);
  return out;
}

function assertUrlAllowed(url: string, allowInsecureHttp: boolean): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid upstream URL: ${url}`);
  }
  const secure = parsed.protocol === 'https:';
  const allowedInsecure = allowInsecureHttp && parsed.protocol === 'http:';
  if (!secure && !allowedInsecure) {
    throw new Error(`Upstream URL must use https: ${url}`);
  }
}

export class UpstreamResolver {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly inFlight = new Map<string, Promise<Buffer>>();
  private readonly downUntilMs = new Map<string, number>();
  private readonly config: UpstreamResolverConfig;

  constructor(config: Partial<UpstreamResolverConfig> = {}) {
    this.config = {
      primaryUrl: config.primaryUrl ?? 'https://9.9.9.9/dns-query',
      secondaryUrl: config.secondaryUrl ?? 'https://cloudflare-dns.com/dns-query',
      timeoutMs: config.timeoutMs ?? 2500,
      maxCacheEntries: config.maxCacheEntries ?? 10_000,
      maxResponseBytes: config.maxResponseBytes ?? 16_384,
      minTtlSeconds: config.minTtlSeconds ?? 5,
      maxTtlSeconds: config.maxTtlSeconds ?? 86_400,
      fetchImpl: config.fetchImpl ?? fetch,
      now: config.now ?? Date.now,
      allowInsecureHttp: config.allowInsecureHttp ?? false,
      failureCooldownMs: config.failureCooldownMs ?? 30_000,
    };

    assertUrlAllowed(this.config.primaryUrl, this.config.allowInsecureHttp);
    assertUrlAllowed(this.config.secondaryUrl, this.config.allowInsecureHttp);
    if (!Number.isInteger(this.config.maxCacheEntries) || this.config.maxCacheEntries < 1) {
      throw new RangeError('UpstreamResolver: maxCacheEntries must be a positive integer');
    }
    if (this.config.minTtlSeconds > this.config.maxTtlSeconds) {
      throw new RangeError('UpstreamResolver: minTtlSeconds must not exceed maxTtlSeconds');
    }
  }

  /**
   * Resolves a raw single-question DNS query via upstream DoH with validation and bounded caching.
   * The second argument is accepted for compatibility and ignored: the query bytes are authoritative.
   */
  public async resolve(queryBuffer: Buffer, _parsedPacket?: dnsPacket.Packet): Promise<Buffer> {
    if (queryBuffer.length < HEADER_LENGTH) {
      throw new Error('DNS query shorter than the 12-byte header');
    }
    const clientId = queryBuffer.readUInt16BE(0);

    // RFC 8484 recommends ID 0 on the wire. The caller's ID is restored on the way out.
    const upstreamQuery = Buffer.from(queryBuffer);
    upstreamQuery.writeUInt16BE(0, 0);
    const signature = this.signatureOf(upstreamQuery);
    const key = signature.key;

    const cached = this.cache.get(key);
    if (cached) {
      const nowMs = this.config.now();
      if (cached.expiresAtMs > nowMs) {
        try {
          const rendered = this.renderCached(cached, clientId, nowMs);
          this.cache.delete(key); // re-insert to mark as most recently used
          this.cache.set(key, cached);
          return rendered;
        } catch (err) {
          logError('cached DNS response could not be rendered; dropping entry', { key, error: errorMessageOf(err) });
          this.cache.delete(key);
        }
      } else {
        this.cache.delete(key);
      }
    }

    let pending = this.inFlight.get(key);
    if (!pending) {
      pending = this.fetchValidated(upstreamQuery, signature).finally(() => {
        this.inFlight.delete(key);
      });
      this.inFlight.set(key, pending);
    }
    const response = await pending;
    return withId(response, clientId);
  }

  /** Clears the DNS cache. */
  public clearCache(): void {
    this.cache.clear();
  }

  public getCacheSize(): number {
    return this.cache.size;
  }

  private signatureOf(query: Buffer): QuerySignature {
    let decoded: dnsPacket.Packet;
    try {
      decoded = dnsPacket.decode(query);
    } catch (err) {
      throw new Error(`DNS query is malformed: ${errorMessageOf(err)}`);
    }
    const questions = decoded.questions ?? [];
    if (decoded.type !== 'query' || questions.length !== 1) {
      throw new Error('DNS query must be a query with exactly one question');
    }
    const question = questions[0]!;
    const name = normalizeName(question.name);
    const type = String(question.type);
    const className = String(question.class ?? 'IN');
    return { key: `${name}|${type}|${className}`, name, type, className };
  }

  private isDown(url: string): boolean {
    const until = this.downUntilMs.get(url);
    return until !== undefined && until > this.config.now();
  }

  private async fetchValidated(upstreamQuery: Buffer, signature: QuerySignature): Promise<Buffer> {
    const { primaryUrl, secondaryUrl } = this.config;
    // Skip a recently failed primary, but only if the secondary is not also failing.
    const order =
      this.isDown(primaryUrl) && !this.isDown(secondaryUrl) ? [secondaryUrl, primaryUrl] : [primaryUrl, secondaryUrl];

    let lastError: unknown;
    for (const url of order) {
      try {
        const result = await this.fetchAndValidate(url, upstreamQuery, signature);
        this.downUntilMs.delete(url);
        this.store(signature.key, result.response, result.decoded);
        return result.response;
      } catch (err) {
        lastError = err;
        if (this.config.failureCooldownMs > 0) {
          this.downUntilMs.set(url, this.config.now() + this.config.failureCooldownMs);
        }
        logError('upstream failed', { url, error: errorMessageOf(err) });
      }
    }
    throw lastError;
  }

  private async fetchAndValidate(
    url: string,
    upstreamQuery: Buffer,
    signature: QuerySignature
  ): Promise<{ response: Buffer; decoded: dnsPacket.Packet }> {
    const response = await this.fetchDoh(url, upstreamQuery);
    const decoded = this.validateResponse(response, signature);
    return { response, decoded };
  }

  private validateResponse(response: Buffer, signature: QuerySignature): dnsPacket.Packet {
    if (response.length < HEADER_LENGTH) {
      throw new Error('upstream response shorter than the 12-byte DNS header');
    }
    let decoded: dnsPacket.Packet;
    try {
      decoded = dnsPacket.decode(response);
    } catch (err) {
      throw new Error(`upstream response is not a valid DNS message: ${errorMessageOf(err)}`);
    }
    if (decoded.type !== 'response') {
      throw new Error('upstream message is not a response');
    }
    if (decoded.id !== 0) {
      throw new Error(`upstream response id mismatch: expected 0, got ${decoded.id}`);
    }
    const questions = decoded.questions ?? [];
    const question = questions[0];
    if (
      questions.length !== 1 ||
      !question ||
      normalizeName(question.name) !== signature.name ||
      String(question.type) !== signature.type ||
      String(question.class ?? 'IN') !== signature.className
    ) {
      throw new Error('upstream response question does not match the query');
    }
    return decoded;
  }

  private cacheTtlSeconds(response: Buffer, decoded: dnsPacket.Packet): number | null {
    if (((response[2] ?? 0) & TRUNCATED_BIT) !== 0) {
      return null; // truncated responses are incomplete
    }
    const rcode = (response[3] ?? 0) & 0x0f;
    if (rcode !== 0 && rcode !== 3) {
      return null; // never cache SERVFAIL, REFUSED, FORMERR and similar
    }

    const answers = decoded.answers ?? [];
    let ttl: number | undefined;
    if (rcode === 0 && answers.length > 0) {
      const ttls = answers.map((answer) => ttlOf(answer)).filter((value): value is number => value !== undefined);
      if (ttls.length === 0) return null;
      ttl = Math.min(...ttls);
    } else {
      // NXDOMAIN or NODATA: only cache when the SOA gives a negative-caching TTL.
      ttl = soaNegativeTtl(decoded.authorities);
    }
    if (ttl === undefined) return null;
    return Math.max(this.config.minTtlSeconds, Math.min(ttl, this.config.maxTtlSeconds));
  }

  private store(key: string, response: Buffer, decoded: dnsPacket.Packet): void {
    const ttlSeconds = this.cacheTtlSeconds(response, decoded);
    if (ttlSeconds === null) return;

    this.cache.delete(key);
    while (this.cache.size >= this.config.maxCacheEntries) {
      const oldest = this.cache.keys().next();
      if (oldest.done) break;
      this.cache.delete(oldest.value);
    }
    const nowMs = this.config.now();
    this.cache.set(key, {
      response,
      storedAtMs: nowMs,
      expiresAtMs: nowMs + ttlSeconds * 1000,
      answerCount: decoded.answers?.length ?? 0,
    });
  }

  /**
   * Builds a response from a cache entry: reduces TTLs by the time spent in the cache, restores the
   * original header flags and response code (dns-packet re-encoding ignores the decoded rcode), and
   * verifies the rebuilt message before returning it.
   */
  private renderCached(entry: CacheEntry, clientId: number, nowMs: number): Buffer {
    const elapsedSeconds = Math.max(0, Math.floor((nowMs - entry.storedAtMs) / 1000));
    const decoded = dnsPacket.decode(entry.response);
    adjustTtls(decoded.answers, elapsedSeconds);
    adjustTtls(decoded.authorities, elapsedSeconds);
    adjustTtls(decoded.additionals, elapsedSeconds);

    const rebuilt = Buffer.from(dnsPacket.encode(decoded));
    rebuilt.writeUInt16BE(entry.response.readUInt16BE(2), 2); // flags and rcode, exactly as received
    rebuilt.writeUInt16BE(clientId, 0);

    const check = dnsPacket.decode(rebuilt);
    if ((check.answers?.length ?? 0) !== entry.answerCount) {
      throw new Error('rebuilt cached response lost answer records');
    }
    return rebuilt;
  }

  private async fetchDoh(url: string, body: Buffer): Promise<Buffer> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await this.config.fetchImpl(url, {
        method: 'POST',
        headers: {
          'Content-Type': DNS_MESSAGE_TYPE,
          Accept: DNS_MESSAGE_TYPE,
        },
        body,
        signal: controller.signal,
        redirect: 'error',
      });

      if (response.status !== 200) {
        throw new Error(`Upstream DoH HTTP ${response.status} from ${url}`);
      }
      const contentType = (response.headers.get('content-type') ?? '').split(';')[0]!.trim().toLowerCase();
      if (contentType !== DNS_MESSAGE_TYPE) {
        throw new Error(`Upstream DoH returned unexpected content type "${contentType}" from ${url}`);
      }
      const declared = response.headers.get('content-length');
      if (declared !== null && Number(declared) > this.config.maxResponseBytes) {
        throw new Error(`Upstream DoH response too large (${declared} bytes) from ${url}`);
      }

      const buffer = Buffer.from(await response.arrayBuffer());
      if (buffer.length > this.config.maxResponseBytes) {
        throw new Error(`Upstream DoH response too large (${buffer.length} bytes) from ${url}`);
      }
      return buffer;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
