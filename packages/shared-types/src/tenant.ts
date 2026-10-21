export type CompanyId = string;
export type DeviceId = string;
export type AdminId = string;
export type DeviceGroupId = string;

export type AdminRole = 'operator' | 'company_admin' | 'viewer';

export interface Company {
  id: CompanyId;
  name: string;
  slug: string;
  timezone: string; // e.g. "Africa/Lagos"
  createdAt: string;
  updatedAt: string;
}

export interface Device {
  id: DeviceId;
  companyId: CompanyId;
  hostname: string;
  os: 'windows' | 'linux' | 'macos';
  agentVersion: string;
  lastOsUser: string;
  lastHeartbeatAt: string | null;
  status: 'active' | 'pending_enrollment' | 'suspended' | 'revoked';
  groupId: DeviceGroupId | null;
  tokenHash: string;
  createdAt: string;
  updatedAt: string;
}

export interface EnrollmentCode {
  id: string;
  companyId: CompanyId;
  code: string;
  maxDevices: number;
  enrolledDevicesCount: number;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}
