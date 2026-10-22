export interface GatewayConfig {
  host: string;
  port: number;
  trustProxy: boolean;
  tokensFile: string;
  policiesFile: string;
  upstreamPrimary: string | undefined;
  upstreamSecondary: string | undefined;
  ipRateBurst: number;
  ipRatePerSecond: number;
}

function readVar(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name];
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

function checkHttpsUrl(name: string, value: string | undefined, errors: string[]): void {
  if (value === undefined) return;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    errors.push(`${name} is not a valid URL`);
    return;
  }
  if (parsed.protocol !== 'https:') {
    errors.push(`${name} must use https`);
  }
}

function parseNumber(env: NodeJS.ProcessEnv, name: string, min: number, fallback: number, errors: string[]): number {
  const raw = readVar(env, name);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < min) {
    errors.push(`${name} must be a number of at least ${min}`);
    return fallback;
  }
  return value;
}

/** Reads and validates gateway configuration from environment variables. Reports every problem at once. */
export function loadConfig(env: NodeJS.ProcessEnv): GatewayConfig {
  const errors: string[] = [];

  const host = readVar(env, 'GATEWAY_HOST') ?? '127.0.0.1';

  let port = 8053;
  const rawPort = readVar(env, 'GATEWAY_PORT');
  if (rawPort !== undefined) {
    if (!/^\d{1,5}$/.test(rawPort) || Number(rawPort) > 65_535) {
      errors.push('GATEWAY_PORT must be an integer between 0 and 65535');
    } else {
      port = Number(rawPort);
    }
  }

  let trustProxy = false;
  const rawTrust = readVar(env, 'GATEWAY_TRUST_PROXY');
  if (rawTrust !== undefined) {
    if (rawTrust === 'true') {
      trustProxy = true;
    } else if (rawTrust !== 'false') {
      errors.push('GATEWAY_TRUST_PROXY must be "true" or "false"');
    }
  }

  const tokensFile = readVar(env, 'GATEWAY_TOKENS_FILE');
  if (tokensFile === undefined) errors.push('GATEWAY_TOKENS_FILE is required');
  const policiesFile = readVar(env, 'GATEWAY_POLICIES_FILE');
  if (policiesFile === undefined) errors.push('GATEWAY_POLICIES_FILE is required');

  const upstreamPrimary = readVar(env, 'GATEWAY_UPSTREAM_PRIMARY');
  const upstreamSecondary = readVar(env, 'GATEWAY_UPSTREAM_SECONDARY');
  checkHttpsUrl('GATEWAY_UPSTREAM_PRIMARY', upstreamPrimary, errors);
  checkHttpsUrl('GATEWAY_UPSTREAM_SECONDARY', upstreamSecondary, errors);

  const ipRateBurst = parseNumber(env, 'GATEWAY_IP_RATE_BURST', 1, 1000, errors);
  const ipRatePerSecond = parseNumber(env, 'GATEWAY_IP_RATE_PER_SECOND', 0, 500, errors);

  if (errors.length > 0 || tokensFile === undefined || policiesFile === undefined) {
    throw new Error(`Invalid gateway configuration:\n- ${errors.join('\n- ')}`);
  }

  return {
    host,
    port,
    trustProxy,
    tokensFile,
    policiesFile,
    upstreamPrimary,
    upstreamSecondary,
    ipRateBurst,
    ipRatePerSecond,
  };
}
