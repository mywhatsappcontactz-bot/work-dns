import { createHash } from 'node:crypto';
import { CompanyId, DeviceId, DeviceGroupId } from '@work-dns/shared-types';

export interface AuthenticatedDeviceContext {
  deviceId: DeviceId;
  companyId: CompanyId;
  deviceGroupId: DeviceGroupId | null;
  status: 'active' | 'suspended' | 'revoked';
}

export interface RateLimitEntry {
  tokens: number;
  lastRefillEpochMs: number;
}

export class DeviceAuthenticator {
  // Keyed by SHA-256 hash of device token
  private tokenStore = new Map<string, AuthenticatedDeviceContext>();
  // Keyed by deviceId
  private rateLimits = new Map<DeviceId, RateLimitEntry>();

  // Token bucket config: 100 queries/sec burst, refills 50 tokens/sec
  private readonly maxBucketTokens = 100;
  private readonly refillTokensPerSecond = 50;

  /**
   * Hashes a raw bearer token using SHA-256.
   * Only this hash is stored server-side.
   */
  public static hashToken(rawToken: string): string {
    return createHash('sha256').update(rawToken.trim(), 'utf8').digest('hex');
  }

  /**
   * Registers or updates a device token hash in the gateway's fast in-memory cache.
   */
  public registerTokenHash(tokenHash: string, context: AuthenticatedDeviceContext): void {
    this.tokenStore.set(tokenHash, context);
  }

  /**
   * Instantly revokes a device token hash.
   */
  public revokeTokenHash(tokenHash: string): void {
    const context = this.tokenStore.get(tokenHash);
    if (context) {
      context.status = 'revoked';
    }
  }

  /**
   * Authenticates an incoming Authorization header and enforces per-device rate limiting.
   */
  public authenticateHeader(authHeader?: string): {
    authenticated: boolean;
    errorStatus?: number;
    errorMessage?: string;
    context?: AuthenticatedDeviceContext;
  } {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        authenticated: false,
        errorStatus: 401,
        errorMessage: 'Missing or malformed Authorization header (Bearer token required)',
      };
    }

    const rawToken = authHeader.slice(7).trim();
    if (!rawToken) {
      return {
        authenticated: false,
        errorStatus: 401,
        errorMessage: 'Empty bearer token',
      };
    }

    const tokenHash = DeviceAuthenticator.hashToken(rawToken);
    const deviceCtx = this.tokenStore.get(tokenHash);

    if (!deviceCtx) {
      return {
        authenticated: false,
        errorStatus: 401,
        errorMessage: 'Unknown or invalid device token',
      };
    }

    if (deviceCtx.status !== 'active') {
      return {
        authenticated: false,
        errorStatus: 403,
        errorMessage: `Device token is ${deviceCtx.status}`,
      };
    }

    // Per-device rate limiting
    if (!this.checkRateLimit(deviceCtx.deviceId)) {
      return {
        authenticated: false,
        errorStatus: 429,
        errorMessage: 'Too many DNS queries: device rate limit exceeded',
      };
    }

    return {
      authenticated: true,
      context: deviceCtx,
    };
  }

  /**
   * Token bucket rate-limiter implementation per device.
   */
  private checkRateLimit(deviceId: DeviceId): boolean {
    const now = Date.now();
    let entry = this.rateLimits.get(deviceId);

    if (!entry) {
      entry = { tokens: this.maxBucketTokens, lastRefillEpochMs: now };
      this.rateLimits.set(deviceId, entry);
    }

    // Refill tokens based on elapsed time
    const elapsedSeconds = (now - entry.lastRefillEpochMs) / 1000;
    const addedTokens = elapsedSeconds * this.refillTokensPerSecond;
    entry.tokens = Math.min(this.maxBucketTokens, entry.tokens + addedTokens);
    entry.lastRefillEpochMs = now;

    if (entry.tokens >= 1) {
      entry.tokens -= 1;
      return true;
    }

    return false;
  }
}
