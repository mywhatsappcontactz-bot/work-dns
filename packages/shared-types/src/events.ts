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
  | 'operator_access';

export interface EventEnvelope<T = Record<string, unknown>> {
  id: string;
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
