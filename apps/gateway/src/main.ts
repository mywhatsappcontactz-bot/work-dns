import { PolicyEngine } from '@work-dns/policy-engine';
import { DeviceAuthenticator } from './auth.js';
import { loadConfig } from './config.js';
import { DnsHandler } from './dns-handler.js';
import { GatewayEventQueue } from './event-queue.js';
import { loadPolicies, loadTokenRecords } from './loaders.js';
import { DohServer } from './server.js';
import { UpstreamResolver, UpstreamResolverConfig } from './upstream.js';

export interface GatewayDependencies {
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
}

export interface RunningGateway {
  port: number;
  /** Stops the server and drains the event queue. Safe to call more than once. */
  stop(): Promise<void>;
}

function log(level: 'info' | 'warn' | 'error', message: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ level, message, ...fields });
  if (level === 'error') {
    console.error(line);
  } else if (level === 'warn') {
    console.warn(line);
  } else {
    console.log(line);
  }
}

/** Builds and starts the gateway from environment variables. Never logs tokens. */
export async function startGateway(env: NodeJS.ProcessEnv, deps: GatewayDependencies = {}): Promise<RunningGateway> {
  const config = loadConfig(env);
  const tokenRecords = loadTokenRecords(config.tokensFile);
  const policies = loadPolicies(config.policiesFile);

  const authenticator = new DeviceAuthenticator();
  for (const record of tokenRecords) {
    authenticator.registerTokenHash(record.tokenHash, record.context);
  }

  const upstreamConfig: Partial<UpstreamResolverConfig> = {
    ...(config.upstreamPrimary !== undefined ? { primaryUrl: config.upstreamPrimary } : {}),
    ...(config.upstreamSecondary !== undefined ? { secondaryUrl: config.upstreamSecondary } : {}),
    ...(deps.fetchImpl !== undefined ? { fetchImpl: deps.fetchImpl } : {}),
  };

  const eventQueue = new GatewayEventQueue();
  const handler = new DnsHandler({
    policyEngine: new PolicyEngine(),
    upstreamResolver: new UpstreamResolver(upstreamConfig),
    eventQueue,
  });
  for (const policy of policies) {
    handler.updateCompiledPolicy(policy);
  }

  const companiesWithPolicy = new Set(policies.map((policy) => policy.companyId));
  const companiesWithoutPolicy = new Set(
    tokenRecords.map((record) => record.context.companyId).filter((companyId) => !companiesWithPolicy.has(companyId))
  );
  for (const companyId of companiesWithoutPolicy) {
    log('warn', 'company has device tokens but no policy: every query from its devices will be blocked', { companyId });
  }

  eventQueue.start();
  const server = new DohServer(authenticator, handler);
  try {
    await server.start({
      port: config.port,
      host: config.host,
      trustProxy: config.trustProxy,
      ipRateLimit: { burst: config.ipRateBurst, refillPerSecond: config.ipRatePerSecond },
    });
  } catch (err) {
    await eventQueue.stop();
    throw err;
  }

  const port = server.getPort();
  if (port === null) {
    await server.stop();
    await eventQueue.stop();
    throw new Error('Gateway started but could not determine its listening port');
  }

  log('info', 'gateway started', {
    host: config.host,
    port,
    trustProxy: config.trustProxy,
    devices: tokenRecords.length,
    policies: policies.length,
  });

  let stopping: Promise<void> | null = null;
  return {
    port,
    stop(): Promise<void> {
      if (!stopping) {
        stopping = (async (): Promise<void> => {
          await server.stop();
          await eventQueue.stop();
          log('info', 'gateway stopped');
        })();
      }
      return stopping;
    },
  };
}
