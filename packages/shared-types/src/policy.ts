import { CompanyId, DeviceGroupId, DeviceId } from './tenant.js';

export type PolicyMode = 'strict' | 'moderate' | 'audit_only';
export type DecisionAction = 'ALLOW' | 'BLOCK';

export interface PolicyContext {
  companyId: CompanyId;
  deviceId: DeviceId;
  deviceGroupId: DeviceGroupId | null;
  queriedDomain: string;
  clientTimestamp: number; // UTC unix epoch ms
  timezone: string; // e.g. "Africa/Lagos"
  policyVersion: number;
}

export interface PolicyDecision {
  action: DecisionAction;
  reasonCode: string;
  ruleId: string | null;
  policyVersion: number;
  matchedRuleType?: string;
  debugNote?: string;
}

export interface PolicyDefinition {
  id: string;
  companyId: CompanyId;
  version: number;
  mode: PolicyMode;
  defaultActionDuringEnforcedHours: DecisionAction;
  defaultActionOutsideEnforcedHours: DecisionAction;
  timezone: string;
  rules: import('./rules.js').Rule[];
  updatedAt: string;
}
