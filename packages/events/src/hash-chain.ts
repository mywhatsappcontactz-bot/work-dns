import { createHash } from 'node:crypto';
import { EventEnvelope, EventType, CompanyId, DeviceId } from '@work-dns/shared-types';
import { canonicalJson } from './canonical-json.js';

export const GENESIS_HASH = '0'.repeat(64);

export interface CreateEventParams<T = Record<string, unknown>> {
  id: string;
  sequenceNumber: number; // Strictly monotonic per-company sequence (1, 2, 3...)
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
  sequenceNumber: number;
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
 * 1. Event ID and sequenceNumber are cryptographically bound inside the hash.
 * 2. Complete delimiter collision immunity (no '|' string concatenations).
 * 3. Strict RFC 8785 determinism across runtimes and locales.
 */
export function computeEventHash<T = Record<string, unknown>>(params: {
  id: string;
  sequenceNumber: number;
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
    sequenceNumber: params.sequenceNumber,
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
    sequenceNumber: params.sequenceNumber,
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
    sequenceNumber: params.sequenceNumber,
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
    sequenceNumber: event.sequenceNumber,
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
  expectedCompanyId: CompanyId; // REQUIRED: Caller must explicitly bind verification to a tenant
  expectedAnchorHash?: string;  // First event prevHash (defaults to GENESIS_HASH)
  expectedHeadHash?: string;    // Optional: Asserts the chain terminates with this head hash
  expectedLength?: number;      // Optional: Asserts total event count matches
}

/**
 * Verifies an ordered sequence of events for a single company tenant.
 * 
 * Invariants enforced:
 * 1. Multi-tenant isolation: expectedCompanyId is REQUIRED and all events must match it.
 * 2. Genesis/Anchor verification: The first event's prevHash must match the expected anchor hash.
 * 3. Monotonic sequence continuity: sequenceNumber must be contiguous (prev + 1, starting at 1 for genesis).
 * 4. Identity uniqueness: Every event id in the chain must be distinct (rejects duplicate ids).
 * 5. Content integrity: Each event's internal hash must verify against its canonical structured payload.
 * 6. Chain linkage: Each event's prevHash must match the immediately preceding event's hash.
 * 7. Head hash & length checks: Optional assertions for expectedHeadHash and expectedLength.
 */
export function verifyEventChain(
  events: EventEnvelope[],
  options: VerifyEventChainOptions
): ChainVerificationResult {
  if (!options || !options.expectedCompanyId || typeof options.expectedCompanyId !== 'string' || options.expectedCompanyId.trim().length === 0) {
    return {
      valid: false,
      error: 'verifyEventChain requires a valid expectedCompanyId to enforce multi-tenant isolation',
    };
  }

  // 1. Length check if specified
  if (options.expectedLength !== undefined && events.length !== options.expectedLength) {
    return {
      valid: false,
      error: `Chain length mismatch: expected ${options.expectedLength}, got ${events.length}`,
    };
  }

  if (events.length === 0) {
    if (options.expectedHeadHash !== undefined) {
      return {
        valid: false,
        error: `Chain is empty but expectedHeadHash was specified: ${options.expectedHeadHash}`,
      };
    }
    return { valid: true };
  }

  const expectedAnchorHash = options.expectedAnchorHash ?? GENESIS_HASH;

  // 2. Verify anchor linkage on the first event
  const firstEvent = events[0]!;
  if (firstEvent.prevHash !== expectedAnchorHash) {
    return {
      valid: false,
      brokenIndex: 0,
      error: `First event ${firstEvent.id} prevHash does not match expected anchor hash: expected ${expectedAnchorHash}, got ${firstEvent.prevHash}`,
    };
  }

  // Genesis chain starts at sequenceNumber 1
  if (expectedAnchorHash === GENESIS_HASH && firstEvent.sequenceNumber !== 1) {
    return {
      valid: false,
      brokenIndex: 0,
      error: `First event ${firstEvent.id} in genesis chain must have sequenceNumber 1, got ${firstEvent.sequenceNumber}`,
    };
  }

  const seenIds = new Set<string>();

  for (let i = 0; i < events.length; i++) {
    const current = events[i]!;

    // 3. Multi-tenant isolation: All events must belong to options.expectedCompanyId
    if (current.companyId !== options.expectedCompanyId) {
      return {
        valid: false,
        brokenIndex: i,
        error: `Mixed-company chain detected at index ${i}: event ${current.id} belongs to "${current.companyId}", expected "${options.expectedCompanyId}"`,
      };
    }

    // 4. Reject duplicate event IDs
    if (seenIds.has(current.id)) {
      return {
        valid: false,
        brokenIndex: i,
        error: `Duplicate event id detected at index ${i}: "${current.id}" is reused in chain`,
      };
    }
    seenIds.add(current.id);

    // 5. Monotonic sequenceNumber continuity
    if (i > 0) {
      const prev = events[i - 1]!;
      if (current.sequenceNumber !== prev.sequenceNumber + 1) {
        return {
          valid: false,
          brokenIndex: i,
          error: `Sequence number gap or regression at index ${i}: expected ${prev.sequenceNumber + 1}, got ${current.sequenceNumber}`,
        };
      }
    }

    // 6. Verify internal content hash integrity
    if (!verifyEventHash(current)) {
      return {
        valid: false,
        brokenIndex: i,
        error: `Event ${current.id} at index ${i} has an invalid internal hash (tampering detected)`,
      };
    }

    // 7. Verify chain linkage with predecessor
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

  // 8. Head hash verification if specified
  if (options.expectedHeadHash !== undefined) {
    const lastEvent = events[events.length - 1]!;
    if (lastEvent.hash !== options.expectedHeadHash) {
      return {
        valid: false,
        brokenIndex: events.length - 1,
        error: `Head hash mismatch: expected ${options.expectedHeadHash}, got ${lastEvent.hash}`,
      };
    }
  }

  return { valid: true };
}
