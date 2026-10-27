import * as path from 'node:path';
import dnsPacket from 'dns-packet';
import { AgentAuditReporter } from './audit-reporter.js';
import { loadAgentConfig, readDeviceToken } from './config.js';
import { DnsStubServer, GatewayState } from './dns-stub.js';
import { DnsDriftWatcher, DriftResult, MonitorHandle, spawnNmcliMonitor } from './dns-watcher.js';
import { AgentEventSender } from './event-sender.js';
import { LocalEventQueue } from './local-queue.js';
import { AgentOutbox } from './outbox.js';
import { LinuxPlatformAdapter } from './platform/linux-adapter.js';

export type AgentLog = (level: 'info' | 'error', message: string, fields?: Record<string, unknown>) => void;

export interface AgentStub {
  start(): Promise<void>;
  stop(): Promise<void>;
  getState(): GatewayState;
  handleQuery(queryBuffer: Buffer): Promise<Buffer>;
}

export interface AgentAdapter {
  setDnsLoopback(port: number): Promise<void>;
  restoreDns(): Promise<void>;
  reapplyIfDrifted(port: number): Promise<DriftResult>;
}

/** What the agent reports to the audit log. The real implementation is AgentAuditReporter. */
export interface AgentAuditSink {
  agentStarted(): void;
  agentStopped(reason: 'signal' | 'crash_recovered' | 'error' | 'unknown', dnsRestored: boolean): void;
  enforcementApplied(devices: readonly string[]): void;
  enforcementReset(detectedAt: Date, reappliedAt: Date): void;
  enforcementRestored(
    devices: readonly string[],
    trigger: 'shutdown' | 'crash_recovery' | 'manual' | 'startup_failure',
    success: boolean
  ): void;
}

/** Delivers recorded audit events to the gateway. The real implementation is AgentEventSender. */
export interface AgentEventDelivery {
  start(): void;
  stop(options?: { finalFlushMs?: number }): Promise<void>;
}

export interface AgentAudit {
  reporter: AgentAuditSink;
  sender: AgentEventDelivery;
  /** Devices currently enforced. Read before restoring: a successful restore clears the list. */
  enforcedDevices: () => string[];
  /** Time allowed for one last delivery attempt at shutdown (default 5000). */
  finalFlushMs?: number;
}

export interface AgentDeps {
  stub: AgentStub;
  adapter: AgentAdapter;
  /** The port the operating system is pointed at (the stub must listen on it). */
  port: number;
  startMonitor: (onActivity: () => void, onExit: () => void) => MonitorHandle;
  restoreAttempts?: number;
  restoreDelayMs?: number;
  log?: AgentLog;
  /** Optional audit reporting. Without it the agent behaves exactly as before. */
  audit?: AgentAudit;
}

export interface AgentHandle {
  stop(): Promise<void>;
}

function defaultLog(level: 'info' | 'error', message: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ level, message, ...fields });
  if (level === 'error') {
    console.error(line);
  } else {
    console.log(line);
  }
}

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Shared by the stub's fail-open limit and the audit reporter, so the log states the limit actually in force. */
const FAIL_OPEN_MAX_MINUTES = 15;

/** The stub must answer through a reachable, accepting gateway before the OS is pointed at it. */
async function startupCheck(stub: AgentStub): Promise<void> {
  const query = Buffer.from(
    dnsPacket.encode({
      type: 'query',
      id: 0x7771,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{ type: 'A', name: 'startup-check.work-dns.invalid' }],
    })
  );
  const response = await stub.handleQuery(query);
  const state = stub.getState();
  if (state !== 'ONLINE') {
    throw new Error(`refusing to enforce DNS: the gateway is not reachable (stub state ${state})`);
  }
  const rcode = (response[3] ?? 0) & 0x0f;
  if (response.length < 12 || (rcode !== 0 && rcode !== 3)) {
    throw new Error(`refusing to enforce DNS: the startup check got response code ${rcode} (gateway rejected the device or failed)`);
  }
}

/** Starts the stub, enforces DNS through it, and keeps enforcement in place until stop(). */
export async function runAgent(deps: AgentDeps): Promise<AgentHandle> {
  const log: AgentLog = deps.log ?? defaultLog;
  const attempts = deps.restoreAttempts ?? 3;
  const delayMs = deps.restoreDelayMs ?? 500;
  const audit = deps.audit;

  // Reporting must never break enforcement or shutdown: every failure is logged and swallowed here.
  const report = (fn: (sink: AgentAuditSink) => void): void => {
    if (!audit) return;
    try {
      fn(audit.reporter);
    } catch (err) {
      log('error', 'audit reporting failed', { error: errorMessageOf(err) });
    }
  };
  const enforcedNow = (): string[] => {
    if (!audit) return [];
    try {
      return audit.enforcedDevices();
    } catch (err) {
      log('error', 'could not list the enforced network devices', { error: errorMessageOf(err) });
      return [];
    }
  };

  const restoreWithRetry = async (): Promise<void> => {
    let lastErr: unknown;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        await deps.adapter.restoreDns();
        return;
      } catch (err) {
        lastErr = err;
        log('error', 'restoring DNS failed', { attempt, error: errorMessageOf(err) });
        if (attempt < attempts) await sleep(delayMs);
      }
    }
    throw new Error(
      `could not restore DNS after ${attempts} attempts: ${errorMessageOf(lastErr)}. ` +
        'DNS may still point at the local stub; restore it by hand (see docs/adr/0007)'
    );
  };

  await deps.stub.start();
  try {
    await startupCheck(deps.stub);
    await deps.adapter.setDnsLoopback(deps.port);
  } catch (err) {
    try {
      await restoreWithRetry();
      await deps.stub.stop();
    } catch (restoreErr) {
      log('error', 'startup failed and DNS could not be restored; leaving the stub running', {
        error: errorMessageOf(restoreErr),
      });
    }
    throw err;
  }

  report((sink) => sink.agentStarted());
  report((sink) => sink.enforcementApplied(enforcedNow()));
  audit?.sender.start();

  const watcher = new DnsDriftWatcher({
    check: async () => {
      const detectedAt = new Date();
      const result = await deps.adapter.reapplyIfDrifted(deps.port);
      if (result === 'reapplied') {
        const reappliedAt = new Date();
        report((sink) => sink.enforcementReset(detectedAt, reappliedAt));
      }
      return result;
    },
    startMonitor: deps.startMonitor,
    ...(deps.log ? { log: deps.log } : {}),
  });
  watcher.start();
  log('info', 'agent started: DNS is enforced through the local stub', { port: deps.port });

  let stopping: Promise<void> | null = null;
  return {
    stop: () => {
      if (!stopping) {
        stopping = (async () => {
          const devices = enforcedNow(); // before restoring: a successful restore clears the list
          await watcher.stop(); // first, so it cannot re-enforce while we restore
          let restoreError: unknown = null;
          try {
            await restoreWithRetry();
          } catch (err) {
            restoreError = err;
          }
          const restored = restoreError === null;
          report((sink) => sink.enforcementRestored(devices, 'shutdown', restored));
          report((sink) => sink.agentStopped('signal', restored));
          if (audit) {
            // After the restore, so a gateway reached by name can still be looked up through the router.
            try {
              await audit.sender.stop({ finalFlushMs: audit.finalFlushMs ?? 5_000 });
            } catch (err) {
              log('error', 'final delivery of audit events failed; they stay in the outbox', { error: errorMessageOf(err) });
            }
          }
          if (restoreError !== null) throw restoreError;
          await deps.stub.stop(); // only after DNS no longer points at it
          log('info', 'agent stopped: DNS restored', {});
        })();
      }
      return stopping;
    },
  };
}

/** Reads configuration from the environment and starts the real agent (Linux only). */
export async function startAgent(env: NodeJS.ProcessEnv): Promise<AgentHandle> {
  if (process.platform !== 'linux') {
    throw new Error('The agent supports Linux only for now (Windows enforcement is not implemented)');
  }
  const config = loadAgentConfig(env);
  const token = readDeviceToken(config.deviceTokenFile);
  const adapter = new LinuxPlatformAdapter();
  const queue = new LocalEventQueue(config.queueFile === undefined ? undefined : { filePath: config.queueFile });
  // Audit events wait in an owner-only outbox beside the queue file until the gateway confirms them.
  const outbox = new AgentOutbox(
    config.queueFile === undefined ? {} : { filePath: path.join(path.dirname(config.queueFile), 'agent-outbox.jsonl') }
  );
  const sender = new AgentEventSender({ outbox, gatewayUrl: config.gatewayUrl, deviceToken: token });
  const reporter = new AgentAuditReporter({
    outbox,
    failOpenMaxMinutes: FAIL_OPEN_MAX_MINUTES,
    onRecorded: () => sender.kick(),
  });
  const stub = new DnsStubServer(
    {
      loopbackPort: config.loopbackPort,
      gatewayUrl: config.gatewayUrl,
      deviceToken: token,
      fallbackUpstreamDoh: config.fallbackDohUrl,
      failOpenMaxMinutes: FAIL_OPEN_MAX_MINUTES,
      onStateChange: (change) => reporter.gatewayStateChanged(change),
    },
    adapter,
    queue
  );
  return runAgent({
    stub,
    adapter,
    port: config.loopbackPort,
    startMonitor: spawnNmcliMonitor,
    audit: { reporter, sender, enforcedDevices: () => adapter.enforcedDevices() },
  });
}
