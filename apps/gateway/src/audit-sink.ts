import type { AuditEventStore } from '@work-dns/events';
import type { DnsBlockedPayload } from '@work-dns/shared-types';
import type { BlockedAttemptRecord, BlockedAttemptSink } from './event-queue.js';

function toPayload(record: BlockedAttemptRecord): DnsBlockedPayload {
  return {
    domain: record.domain,
    loggedOsUser: record.loggedOsUser,
    policyVersion: record.policyVersion,
    reasonCode: record.reasonCode,
    firstSeenAt: record.occurredAt,
    count: record.count,
    ...(record.clientIp !== undefined ? { clientIp: record.clientIp } : {}),
  };
}

/**
 * Turns queued blocked attempts into audit events. The queue puts a whole batch back after a failure,
 * so this must be safe to run twice on the same record: a record whose id is already stored is skipped.
 * Failures are rethrown so the queue retries. The store assigns sequence numbers and hashes, never this code.
 * Limit: a record that can never be stored is retried forever and holds up the queue behind it.
 */
export function createAuditSink(store: Pick<AuditEventStore, 'append' | 'hasEvent'>): BlockedAttemptSink {
  return async (records) => {
    for (const record of records) {
      if (store.hasEvent(record.id)) continue;
      store.append({
        id: record.id,
        type: 'dns_blocked',
        companyId: record.companyId,
        deviceId: record.deviceId,
        payload: toPayload(record),
      });
    }
  };
}
