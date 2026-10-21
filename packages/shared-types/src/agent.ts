import { CompanyId, DeviceId } from './tenant.js';

export interface AgentConfig {
  companyId: CompanyId;
  deviceId: DeviceId;
  gatewayUrl: string; // e.g. "https://gateway.work-dns.local/dns-query"
  heartbeatIntervalSeconds: number; // default: 60
  failOpenMaxMinutes: number; // default: 15
  policyVersion: number;
  aupText: string;
  aupVersion: string;
}

export interface AgentHeartbeatRequest {
  deviceId: DeviceId;
  agentVersion: string;
  loggedOsUser: string;
  os: 'windows' | 'linux' | 'macos';
  policyVersion: number;
  status: 'healthy' | 'degraded' | 'fail_open';
  queuedEventsCount: number;
}

export interface AgentHeartbeatResponse {
  acknowledged: boolean;
  serverTime: string;
  latestPolicyVersion: number;
  configChanged: boolean;
}

export interface AupAckRequest {
  deviceId: DeviceId;
  loggedOsUser: string;
  aupVersion: string;
}
