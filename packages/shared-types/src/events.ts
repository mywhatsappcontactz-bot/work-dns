import { CompanyId, DeviceId } from './tenant.js';

export type EventType =
  | 'device_enrolled'
  | 'aup_acknowledged'
  | 'heartbeat_missed'
  | 'gateway_unreachable'
  | 'dns_blocked'
  | 'access_requested'
  | 'access_approved'
  | 'access_denied'
  | 'policy_changed'
  | 'admin_login'
  | 'operator_access'
  | 'agent_started'
  | 'agent_stopped'
  | 'enforcement_applied'
  | 'enforcement_reset'
  | 'enforcement_restored'
  | 'fail_open_entered'
  | 'fail_open_exited'
  | 'auth_rejected'
  | 'device_revoked'
  | 'dns_allowed_summary'
  | 'retention_expired';

export interface EventEnvelope<T = Record<string, unknown>> {
  id: string;
  sequenceNumber: number; // Strictly monotonic per-company integer: 1, 2, 3...
  type: EventType;
  schemaVersion: number;
  companyId: CompanyId;
  deviceId: DeviceId | null;
  occurredAt: string; // ISO 8601 UTC
  payload: T;
  prevHash: string;   // Hex SHA-256 of preceding event in tenant chain, or 64 '0's for genesis
  hash: string;       // Hex SHA-256 of canonical event data
}

export interface DnsBlockedPayload {
  domain: string;
  loggedOsUser: string;
  policyVersion: number;
  reasonCode: string;
  clientIp?: string;
  confidence?: 'high' | 'medium' | 'low';
  /** DNS record type queried, for example "A" or "AAAA". */
  recordType?: string;
  /** Id of the policy rule that decided the block, when a rule (not a default) decided it. */
  ruleId?: string;
  /** When the device says the attempt happened. occurredAt is the server's own time. */
  deviceReportedAt?: string;
  /** Whether the device was being enforced when the attempt happened. */
  enforcementState?: 'enforced' | 'fail_open' | 'unknown';
  /** How many identical attempts were merged into this event. */
  count?: number;
  /** When the gateway first saw the attempt. occurredAt is when the event was written. */
  firstSeenAt?: string;
}

export interface DeviceEnrolledPayload {
  hostname: string;
  os: string;
  agentVersion: string;
  enrollmentCodeId: string;
}

export interface AupAcknowledgedPayload {
  loggedOsUser: string;
  textVersion: string;
  acknowledgedAt: string;
}

export interface AccessRequestedPayload {
  requestId: string;
  domain: string;
  loggedOsUser: string;
  reason?: string;
}

export interface AccessApprovedPayload {
  requestId: string;
  approverId: string;
  domain: string;
  scope: 'device' | 'group' | 'company';
  duration: 'today' | 'permanent';
}

export interface PolicyChangedPayload {
  previousVersion: number;
  newVersion: number;
  changedByAdminId: string;
  summary: string;
}

export interface OperatorAccessPayload {
  operatorId: string;
  reason: string;
  accessedResource: string;
}

export interface AgentStartedPayload {
  agentVersion: string;
  os: string;
  loggedOsUser: string;
  policyVersion: number;
}

export interface AgentStoppedPayload {
  reason: 'signal' | 'crash_recovered' | 'error' | 'unknown';
  dnsRestored: boolean;
}

export interface EnforcementAppliedPayload {
  networkDevices: string[];
  method: string; // for example "nmcli-runtime"
}

export interface EnforcementResetPayload {
  detectedAt: string;
  reappliedAt?: string;
  windowSeconds?: number;
}

export interface EnforcementRestoredPayload {
  networkDevices: string[];
  trigger: 'shutdown' | 'crash_recovery' | 'manual' | 'startup_failure';
  success: boolean;
}

export interface FailOpenEnteredPayload {
  reason: 'gateway_unreachable';
  maxMinutes: number;
}

export interface FailOpenExitedPayload {
  durationSeconds: number;
  cause: 'gateway_recovered' | 'time_limit_reached';
}

export interface AuthRejectedPayload {
  httpStatus: number;
  attempts: number;
}

export interface DeviceRevokedPayload {
  revokedByAdminId: string;
  reason: string;
}

/** Hourly counts for allowed queries, so the log stays small and holds no per-lookup history. */
export interface DnsAllowedSummaryPayload {
  windowStart: string;
  windowEnd: string;
  allowedCount: number;
  blockedCount: number;
}

/** Records that old events passed their retention period and were released. */
export interface RetentionExpiredPayload {
  throughSequenceNumber: number;
  retentionDays: number;
  checkpointHash: string;
}
