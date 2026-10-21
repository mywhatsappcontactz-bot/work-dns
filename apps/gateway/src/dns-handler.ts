import dnsPacket from 'dns-packet';
import { PolicyEngine } from '@work-dns/policy-engine';
import { PolicyDefinition, PolicyContext } from '@work-dns/shared-types';
import { AuthenticatedDeviceContext } from './auth.js';
import { UpstreamResolver } from './upstream.js';
import { GatewayEventQueue } from './event-queue.js';
import { buildErrorResponse } from './dns-response.js';

export const MAX_DNS_PACKET_SIZE = 4096;
const MAX_DOMAIN_LENGTH = 253;
const UNSUPPORTED_QUERY_TYPES = new Set(['ANY', '*', 'AXFR', 'IXFR']);

export interface DnsHandlerResult {
  statusCode: number;
  responseBuffer?: Buffer;
  errorMessage?: string;
  action: 'ALLOW' | 'BLOCK' | 'REJECT';
  domain?: string;
  upstreamError?: string;
  latencyMicroseconds: number;
}

function normalizeDomain(name: string): string | null {
  const lowered = name.toLowerCase();
  const trimmed = lowered.endsWith('.') ? lowered.slice(0, -1) : lowered;
  if (trimmed.length === 0 || trimmed.length > MAX_DOMAIN_LENGTH) {
    return null;
  }
  return trimmed;
}

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function logError(message: string, fields: Record<string, unknown>): void {
  console.error(JSON.stringify({ level: 'error', message, ...fields }));
}

export class DnsHandler {
  private policyEngine: PolicyEngine;
  private upstreamResolver: UpstreamResolver;
  private eventQueue: GatewayEventQueue;
  // Keyed by companyId
  private compiledPolicies = new Map<string, PolicyDefinition>();

  constructor(options: {
    policyEngine: PolicyEngine;
    upstreamResolver: UpstreamResolver;
    eventQueue: GatewayEventQueue;
  }) {
    this.policyEngine = options.policyEngine;
    this.upstreamResolver = options.upstreamResolver;
    this.eventQueue = options.eventQueue;
  }

  /** Updates or sets the compiled in-memory policy for a tenant company. */
  public updateCompiledPolicy(policy: PolicyDefinition): void {
    this.compiledPolicies.set(policy.companyId, policy);
  }

  /** Processes a raw RFC 8484 DNS message with strict validation and latency tracking. */
  public async handleDnsMessage(
    rawBuffer: Buffer,
    deviceCtx: AuthenticatedDeviceContext,
    clientIp?: string
  ): Promise<DnsHandlerResult> {
    const startTime = process.hrtime.bigint();
    const elapsedMicroseconds = (): number =>
      Number(process.hrtime.bigint() - startTime) / 1000;
    const reject = (statusCode: number, errorMessage: string): DnsHandlerResult => ({
      statusCode,
      errorMessage,
      action: 'REJECT',
      latencyMicroseconds: elapsedMicroseconds(),
    });

    // 1. Size checks
    if (rawBuffer.length > MAX_DNS_PACKET_SIZE) {
      return reject(
        413,
        `Payload Too Large: DNS message exceeds maximum permitted size (${MAX_DNS_PACKET_SIZE} bytes)`
      );
    }
    if (rawBuffer.length < 12) {
      return reject(400, 'Bad Request: DNS message buffer shorter than standard 12-byte header');
    }

    // 2. Strict parse
    let packet: dnsPacket.Packet;
    try {
      packet = dnsPacket.decode(rawBuffer);
    } catch (parseError) {
      return reject(400, `Malformed DNS packet: ${errorMessageOf(parseError)}`);
    }

    // 3. Structural validation: must be a standard query with exactly one question
    if (packet.type !== 'query') {
      return reject(400, 'Invalid DNS packet: message is not a query');
    }
    // Opcode is bits 3-6 of header byte 2 (dns-packet does not expose it).
    const opcode = (rawBuffer[2]! >> 3) & 0x0f;
    if (opcode !== 0) {
      return reject(400, `Invalid DNS packet: unsupported opcode ${opcode}`);
    }
    const questions = packet.questions ?? [];
    if (questions.length === 0) {
      return reject(400, 'Invalid DNS packet: Missing Question section');
    }
    if (questions.length > 1) {
      return reject(400, 'Invalid DNS packet: exactly one question is required');
    }
    const question = questions[0]!;
    if (!question.name) {
      return reject(400, 'Invalid DNS packet: Missing Question section');
    }
    if (question.class && question.class !== 'IN') {
      return reject(400, `Unsupported query class: ${question.class}`);
    }
    if (UNSUPPORTED_QUERY_TYPES.has(String(question.type))) {
      return reject(400, `Unsupported query type: ${String(question.type)}`);
    }

    const queriedDomain = normalizeDomain(question.name);
    if (queriedDomain === null) {
      return reject(400, 'Invalid DNS packet: domain name empty or too long');
    }

    // 4. Policy evaluation (default deny when no policy exists)
    const policy = this.compiledPolicies.get(deviceCtx.companyId);
    let action: 'ALLOW' | 'BLOCK' = 'BLOCK';
    let reasonCode = 'NO_POLICY_CONFIGURED';

    if (policy) {
      const policyContext: PolicyContext = {
        companyId: deviceCtx.companyId,
        deviceId: deviceCtx.deviceId,
        deviceGroupId: deviceCtx.deviceGroupId,
        queriedDomain,
        clientTimestamp: Date.now(),
        timezone: policy.timezone || 'Africa/Lagos',
        policyVersion: policy.version,
      };
      const decision = this.policyEngine.evaluate(policy, policyContext);
      action = decision.action;
      reasonCode = decision.reasonCode;
    }

    // 5a. ALLOW: forward a re-encoded, single-question query (no client EDNS/extras)
    if (action === 'ALLOW') {
      const upstreamQuery = Buffer.from(
        dnsPacket.encode({
          type: 'query',
          id: packet.id,
          flags: dnsPacket.RECURSION_DESIRED,
          questions: [{ type: question.type, name: queriedDomain, class: 'IN' }],
        })
      );

      try {
        const responseBuffer = await this.upstreamResolver.resolve(upstreamQuery, packet);
        return {
          statusCode: 200,
          responseBuffer,
          action: 'ALLOW',
          domain: queriedDomain,
          latencyMicroseconds: elapsedMicroseconds(),
        };
      } catch (upstreamErr) {
        const message = errorMessageOf(upstreamErr);
        logError('upstream resolution failed', {
          companyId: deviceCtx.companyId,
          deviceId: deviceCtx.deviceId,
          domain: queriedDomain,
          error: message,
        });
        return {
          statusCode: 200,
          responseBuffer: buildErrorResponse(packet, 'SERVFAIL'),
          action: 'ALLOW',
          domain: queriedDomain,
          upstreamError: message,
          latencyMicroseconds: elapsedMicroseconds(),
        };
      }
    }

    // 5b. BLOCK: synthesize NXDOMAIN and record the attempt without affecting the answer
    const nxdomainBuffer = this.synthesizeNxdomain(packet);
    try {
      this.eventQueue.enqueueBlockedAttempt({
        companyId: deviceCtx.companyId,
        deviceId: deviceCtx.deviceId,
        domain: queriedDomain,
        // UNVERIFIED placeholder: replace with the real OS user reported by the agent.
        loggedOsUser: 'unknown',
        policyVersion: policy?.version ?? 1,
        reasonCode,
        ...(clientIp !== undefined ? { clientIp } : {}),
      });
    } catch (enqueueErr) {
      logError('failed to enqueue blocked-attempt event', {
        companyId: deviceCtx.companyId,
        deviceId: deviceCtx.deviceId,
        domain: queriedDomain,
        error: errorMessageOf(enqueueErr),
      });
    }

    return {
      statusCode: 200,
      responseBuffer: nxdomainBuffer,
      action: 'BLOCK',
      domain: queriedDomain,
      latencyMicroseconds: elapsedMicroseconds(),
    };
  }

  public synthesizeNxdomain(queryPacket: dnsPacket.Packet): Buffer {
    return buildErrorResponse(queryPacket, 'NXDOMAIN');
  }

  public synthesizeServfail(queryPacket: dnsPacket.Packet): Buffer {
    return buildErrorResponse(queryPacket, 'SERVFAIL');
  }
}
