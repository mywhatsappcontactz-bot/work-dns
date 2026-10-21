import { createHash } from 'node:crypto';
import { EventEnvelope, EventType, CompanyId, DeviceId } from '@work-dns/shared-types';
import { canonicalJson } from './canonical-json.js';

export const GENESIS_HASH = '0'.repeat(64);

export interface CreateEventParams<T = Record<string, unknown>> {
  id: string;
  type: EventType;
  schemaVersion?: number;
  companyId: CompanyId;
  deviceId?: DeviceId | null;
  occurredAt?: string;
  payload: T;
  prevHash: string;
}

/**
 * Canonical structure hashed for each event in the tamper-evident chain.
 * Structured canonical JSON replaces vulnerable delimiter-joined strings.
 */
export interface EventHashStructure<T = Record<string, unknown>> {
  id: string;
  type: EventType;
  schemaVersion: number;
  companyId: CompanyId;
  deviceId: DeviceId | null;
  occurredAt: string;
  payload: T;
  prevHash: string;
}

/**
 * Computes the cryptographic SHA-256 hash for an event.
 * Hashes a structured object using canonical JSON, guaranteeing:
 * 1. Event ID is cryptographically bound inside the hash.
 * 2. Complete delimiter collision immunity (no '|' string concatenations).
 * 3. Strict RFC 8785 determinism across runtimes and locales.
 */
export function computeEventHash<T = Record<string, unknown>>(params: {
  id: string;
  type: EventType;
  schemaVersion: number;
  companyId: CompanyId;
  deviceId: DeviceId | null;
  occurredAt: string;
  payload: T;
  prevHash: string;
}): string {
  const structuredData: EventHashStructure<T> = {
    id: params.id,
    type: params.type,
    schemaVersion: params.schemaVersion,
    companyId: params.companyId,
    deviceId: params.deviceId ?? null,
    occurredAt: params.occurredAt,
    payload: params.payload,
    prevHash: params.prevHash,
  };

  const canonicalData = canonicalJson(structuredData);
  return createHash('sha256').update(canonicalData, 'utf8').digest('hex');
}

/**
 * Creates a fully validated, hashed event envelope ready for append-only persistence.
 */
export function createEventEnvelope<T = Record<string, unknown>>(params: CreateEventParams<T>): EventEnvelope<T> {
  const schemaVersion = params.schemaVersion ?? 1;
  const occurredAt = params.occurredAt ?? new Date().toISOString();
  const deviceId = params.deviceId ?? null;

  const hash = computeEventHash({
    id: params.id,
    type: params.type,
    schemaVersion,
    companyId: params.companyId,
    deviceId,
    occurredAt,
    payload: params.payload,
    prevHash: params.prevHash,
  });

  return {
    id: params.id,
    type: params.type,
    schemaVersion,
    companyId: params.companyId,
    deviceId,
    occurredAt,
    payload: params.payload,
    prevHash: params.prevHash,
    hash,
  };
}

/**
 * Verifies that an individual event's hash matches its contents.
 */
export function verifyEventHash<T = Record<string, unknown>>(event: EventEnvelope<T>): boolean {
  const expectedHash = computeEventHash({
    id: event.id,
    type: event.type,
    schemaVersion: event.schemaVersion,
    companyId: event.companyId,
    deviceId: event.deviceId,
    occurredAt: event.occurredAt,
    payload: event.payload,
    prevHash: event.prevHash,
  });

  return event.hash === expectedHash;
}

export interface ChainVerificationResult {
  valid: boolean;
  brokenIndex?: number;
  error?: string;
}

export interface VerifyEventChainOptions {
  expectedAnchorHash?: string;
  expectedCompanyId?: CompanyId;
}

/**
 * Verifies an ordered sequence of events for a single company tenant.
 * 
 * Invariants enforced:
 * 1. Genesis/Anchor verification: The first event's prevHash must match the expected anchor hash.
 * 2. Multi-tenant isolation: All events in the chain must strictly share the same companyId.
 * 3. Identity uniqueness: Every event id in the chain must be distinct (rejects duplicate ids).
 * 4. Content integrity: Each event's internal hash must verify against its canonical structured payload.
 * 5. Chain linkage: Each event's prevHash must match the immediately preceding event's hash.
 */
export function verifyEventChain(
  events: EventEnvelope[],
  expectedAnchorOrOptions: string | VerifyEventChainOptions = GENESIS_HASH
): ChainVerificationResult {
  if (events.length === 0) {
    return { valid: true };
  }

  const expectedAnchorHash =
    typeof expectedAnchorOrOptions === 'string'
      ? expectedAnchorOrOptions
      : (expectedAnchorOrOptions.expectedAnchorHash ?? GENESIS_HASH);

  const expectedCompanyId =
    typeof expectedAnchorOrOptions === 'object'
      ? expectedAnchorOrOptions.expectedCompanyId
      : undefined;

  // 1. Verify anchor linkage on the first event
  const firstEvent = events[0]!;
  if (firstEvent.prevHash !== expectedAnchorHash) {
    return {
      valid: false,
      brokenIndex: 0,
      error: `First event ${firstEvent.id} prevHash does not match expected anchor hash: expected ${expectedAnchorHash}, got ${firstEvent.prevHash}`,
    };
  }

  const targetCompanyId = expectedCompanyId ?? firstEvent.companyId;
  const seenIds = new Set<string>();

  for (let i = 0; i < events.length; i++) {
    const current = events[i]!;

    // 2. Multi-tenant isolation: All events must belong to the exact same companyId
    if (current.companyId !== targetCompanyId) {
      return {
        valid: false,
        brokenIndex: i,
        error: `Mixed-company chain detected at index ${i}: event ${current.id} belongs to "${current.companyId}", expected "${targetCompanyId}"`,
      };
    }

    // 3. Reject duplicate event IDs
    if (seenIds.has(current.id)) {
      return {
        valid: false,
        brokenIndex: i,
        error: `Duplicate event id detected at index ${i}: "${current.id}" is reused in chain`,
      };
    }
    seenIds.add(current.id);

    // 4. Verify internal content hash integrity
    if (!verifyEventHash(current)) {
      return {
        valid: false,
        brokenIndex: i,
        error: `Event ${current.id} at index ${i} has an invalid internal hash (tampering detected)`,
      };
    }

    // 5. Verify chain linkage with predecessor
    if (i > 0) {
      const prev = events[i - 1]!;
      if (current.prevHash !== prev.hash) {
        return {
          valid: false,
          brokenIndex: i,
          error: `Event ${current.id} at index ${i} has broken prevHash linkage: expected ${prev.hash}, got ${current.prevHash}`,
        };
      }
    }
  }

  return { valid: true };
}
