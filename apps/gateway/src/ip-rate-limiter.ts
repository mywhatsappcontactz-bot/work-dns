export interface IpRateLimiterOptions {
  /** Maximum burst size per key. */
  burst: number;
  /** Tokens added per second per key. */
  refillPerSecond: number;
  /** Maximum tracked keys; least recently used keys are evicted first. */
  maxEntries?: number;
  /** Clock in epoch milliseconds (injectable for tests). */
  now?: () => number;
}

interface Bucket {
  tokens: number;
  lastRefillMs: number;
}

/** Token-bucket limiter keyed by client address, with a bounded number of tracked keys. */
export class IpRateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly burst: number;
  private readonly refillPerSecond: number;
  private readonly maxEntries: number;
  private readonly now: () => number;

  constructor(options: IpRateLimiterOptions) {
    if (!Number.isFinite(options.burst) || options.burst < 1) {
      throw new RangeError('IpRateLimiter: burst must be at least 1');
    }
    if (!Number.isFinite(options.refillPerSecond) || options.refillPerSecond < 0) {
      throw new RangeError('IpRateLimiter: refillPerSecond must be zero or greater');
    }
    const maxEntries = options.maxEntries ?? 10_000;
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new RangeError('IpRateLimiter: maxEntries must be a positive integer');
    }
    this.burst = options.burst;
    this.refillPerSecond = options.refillPerSecond;
    this.maxEntries = maxEntries;
    this.now = options.now ?? Date.now;
  }

  /** Consumes one token for the key. Returns false when the key is over its limit. */
  public allow(key: string): boolean {
    const now = this.now();
    let bucket = this.buckets.get(key);

    if (bucket) {
      this.buckets.delete(key); // re-inserted below to keep least-recently-used order
      const elapsedSeconds = Math.max(0, now - bucket.lastRefillMs) / 1000;
      bucket.tokens = Math.min(this.burst, bucket.tokens + elapsedSeconds * this.refillPerSecond);
      bucket.lastRefillMs = now;
    } else {
      if (this.buckets.size >= this.maxEntries) {
        const oldest = this.buckets.keys().next();
        if (!oldest.done) {
          this.buckets.delete(oldest.value);
        }
      }
      bucket = { tokens: this.burst, lastRefillMs: now };
    }
    this.buckets.set(key, bucket);

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return true;
    }
    return false;
  }

  public size(): number {
    return this.buckets.size;
  }
}
