import dnsPacket from 'dns-packet';

export interface UpstreamResolverConfig {
  primaryUrl: string;   // e.g. "https://1.1.1.1/dns-query"
  secondaryUrl: string; // e.g. "https://9.9.9.9/dns-query"
  timeoutMs: number;    // e.g. 2500
}

interface CacheEntry {
  responseBuffer: Buffer;
  expiresEpochMs: number;
}

export class UpstreamResolver {
  private cache = new Map<string, CacheEntry>();
  private config: UpstreamResolverConfig;

  constructor(config?: Partial<UpstreamResolverConfig>) {
    this.config = {
      primaryUrl: config?.primaryUrl ?? 'https://1.1.1.1/dns-query',
      secondaryUrl: config?.secondaryUrl ?? 'https://9.9.9.9/dns-query',
      timeoutMs: config?.timeoutMs ?? 2500,
    };
  }

  /**
   * Generates a cache key based on query question (name, type, class).
   */
  private getCacheKey(packet: dnsPacket.Packet): string | null {
    const question = packet.questions?.[0];
    if (!question) return null;
    return `${question.name.toLowerCase()}:${question.type ?? 'A'}:${question.class ?? 'IN'}`;
  }

  /**
   * Resolves a raw DNS query buffer via upstream DoH over TLS with TTL caching.
   */
  public async resolve(queryBuffer: Buffer, parsedPacket: dnsPacket.Packet): Promise<Buffer> {
    const cacheKey = this.getCacheKey(parsedPacket);
    const now = Date.now();

    // 1. Check TTL Cache
    if (cacheKey) {
      const cached = this.cache.get(cacheKey);
      if (cached && cached.expiresEpochMs > now) {
        // Rewrite the ID in cached response to match client's query ID
        const cachedPacket = dnsPacket.decode(cached.responseBuffer);
        cachedPacket.id = parsedPacket.id;
        return Buffer.from(dnsPacket.encode(cachedPacket));
      } else if (cached) {
        this.cache.delete(cacheKey);
      }
    }

    // 2. Query upstream with fallback
    let responseBuffer: Buffer;
    try {
      responseBuffer = await this.fetchDoh(this.config.primaryUrl, queryBuffer);
    } catch (primaryErr) {
      // Primary failed or timed out; try secondary upstream
      console.error(JSON.stringify({
        level: 'error',
        message: 'primary upstream failed, trying secondary',
        error: primaryErr instanceof Error ? primaryErr.message : String(primaryErr),
      }));
      responseBuffer = await this.fetchDoh(this.config.secondaryUrl, queryBuffer);
    }

    // 3. Cache the response based on the minimum answer TTL
    if (cacheKey) {
      try {
        const decoded = dnsPacket.decode(responseBuffer);
        const ttls = (decoded.answers ?? [])
          .filter((a): a is typeof a & { ttl: number } => 'ttl' in a && typeof a.ttl === 'number')
          .map((a) => a.ttl);
        const minTtl = ttls.length > 0 ? Math.min(...ttls) : 60;
        const validTtl = Math.max(5, Math.min(minTtl, 86400)); // clamp between 5s and 24h

        this.cache.set(cacheKey, {
          responseBuffer,
          expiresEpochMs: now + validTtl * 1000,
        });
      } catch (cacheErr) {
        // If decoding failed, don't cache; record why.
        console.error(JSON.stringify({
          level: 'error',
          message: 'upstream response not cached: decode failed',
          error: cacheErr instanceof Error ? cacheErr.message : String(cacheErr),
        }));
      }
    }

    return responseBuffer;
  }

  private async fetchDoh(url: string, body: Buffer): Promise<Buffer> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          Accept: 'application/dns-message',
        },
        body: body,
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Upstream DoH HTTP ${response.status} from ${url}`);
      }

      const arrayBuffer = await response.arrayBuffer();
      return Buffer.from(arrayBuffer);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Clears internal DNS cache.
   */
  public clearCache(): void {
    this.cache.clear();
  }
}
