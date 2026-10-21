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
 * Computes the cryptographic SHA-256 hash for an event.
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
  const canonicalPayload = canonicalJson(params.payload);
  const data = [
    params.prevHash,
    params.occurredAt,
    params.type,
    params.schemaVersion.toString(),
    params.companyId,
    params.deviceId ?? '',
    canonicalPayload,
  ].join('|');

  return createHash('sha256').update(data, 'utf8').digest('hex');
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

/**
 * Verifies an ordered sequence of events for a single company tenant.
 * Ensures each event's prevHash matches the prior event's hash, and all content hashes are valid.
 */
export function verifyEventChain(events: EventEnvelope[]): ChainVerificationResult {
  if (events.length === 0) {
    return { valid: true };
  }

  for (let i = 0; i < events.length; i++) {
    const current = events[i]!;

    // 1. Verify internal hash validity
    if (!verifyEventHash(current)) {
      return {
        valid: false,
        brokenIndex: i,
        error: `Event ${current.id} at index ${i} has an invalid internal hash (tampering detected)`,
      };
    }

    // 2. Verify chain linkage
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
