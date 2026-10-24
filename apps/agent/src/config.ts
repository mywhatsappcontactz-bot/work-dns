import * as fs from 'node:fs';

export interface AgentConfig {
  gatewayUrl: string;
  deviceTokenFile: string;
  loopbackPort: number;
  fallbackDohUrl: string;
  queueFile: string | undefined;
}

const DEFAULT_FALLBACK_DOH = 'https://cloudflare-dns.com/dns-query';

function readVar(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name];
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

function checkUrl(name: string, value: string | undefined, allowLoopbackHttp: boolean, errors: string[]): void {
  if (value === undefined) return;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    errors.push(`${name} is not a valid URL`);
    return;
  }
  if (parsed.protocol === 'https:') return;
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname);
  if (allowLoopbackHttp && parsed.protocol === 'http:' && loopback) return;
  errors.push(allowLoopbackHttp ? `${name} must use https (http is allowed only for loopback)` : `${name} must use https`);
}

/** Reads and validates agent configuration from environment variables. Reports every problem at once. */
export function loadAgentConfig(env: NodeJS.ProcessEnv): AgentConfig {
  const errors: string[] = [];

  const gatewayUrl = readVar(env, 'AGENT_GATEWAY_URL');
  if (gatewayUrl === undefined) errors.push('AGENT_GATEWAY_URL is required');
  checkUrl('AGENT_GATEWAY_URL', gatewayUrl, true, errors);

  const deviceTokenFile = readVar(env, 'AGENT_DEVICE_TOKEN_FILE');
  if (deviceTokenFile === undefined) errors.push('AGENT_DEVICE_TOKEN_FILE is required');

  let loopbackPort = 53;
  const rawPort = readVar(env, 'AGENT_LOOPBACK_PORT');
  if (rawPort !== undefined) {
    if (!/^\d{1,5}$/.test(rawPort) || Number(rawPort) > 65_535) {
      errors.push('AGENT_LOOPBACK_PORT must be an integer between 0 and 65535');
    } else {
      loopbackPort = Number(rawPort);
    }
  }

  const fallbackDohUrl = readVar(env, 'AGENT_FALLBACK_DOH') ?? DEFAULT_FALLBACK_DOH;
  checkUrl('AGENT_FALLBACK_DOH', fallbackDohUrl, false, errors);

  const queueFile = readVar(env, 'AGENT_QUEUE_FILE');

  if (errors.length > 0 || gatewayUrl === undefined || deviceTokenFile === undefined) {
    throw new Error(`Invalid agent configuration:\n- ${errors.join('\n- ')}`);
  }
  return { gatewayUrl, deviceTokenFile, loopbackPort, fallbackDohUrl, queueFile };
}

/** Reads the device token from a file that only its owner may read. */
export function readDeviceToken(file: string): string {
  let st: fs.Stats;
  try {
    st = fs.statSync(file);
  } catch (err) {
    throw new Error(`Cannot read device token file ${file}: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!st.isFile()) {
    throw new Error(`Device token path ${file} is not a regular file`);
  }
  if ((st.mode & 0o077) !== 0) {
    throw new Error(`Device token file ${file} must not be readable by group or others (run: chmod 600 ${file})`);
  }
  const token = fs.readFileSync(file, 'utf8').trim();
  if (token === '') {
    throw new Error(`Device token file ${file} is empty`);
  }
  return token;
}
