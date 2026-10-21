import { DeviceGroupId } from './tenant.js';
import { PolicyContext } from './policy.js';

export type RuleEffect = 'ALLOW' | 'DENY';

export interface BaseRule {
  id: string;
  type: string;
  priority: number; // lower number evaluated first
  description?: string;
  scope?: {
    deviceGroupIds?: DeviceGroupId[];
    deviceIds?: string[];
  };
}

export interface DomainAllowRule extends BaseRule {
  type: 'domain_allow';
  pattern: string; // e.g., "example.com" or "*.example.com"
  effect: 'ALLOW';
}

export interface DaySchedule {
  dayOfWeek: 0 | 1 | 2 | 3 | 4 | 5 | 6; // 0 = Sunday, 1 = Monday, ..., 6 = Saturday
  startMinuteOfDay: number; // 0 to 1439 (e.g., 8:00 AM = 480)
  endMinuteOfDay: number;   // 0 to 1439 (e.g., 6:00 PM = 1080)
}

export interface ScheduleRule extends BaseRule {
  type: 'schedule';
  enforcedWindows: DaySchedule[];
  // If inside enforced window: applies defaultActionDuringEnforcedHours
  // If outside enforced window: applies defaultActionOutsideEnforcedHours
}

export interface DeviceGroupScopeRule extends BaseRule {
  type: 'device_group_scope';
  allowedGroupIds: DeviceGroupId[];
}

export type BuiltInRule = DomainAllowRule | ScheduleRule | DeviceGroupScopeRule;

export type Rule = BuiltInRule | (BaseRule & Record<string, unknown>);

export interface IRuleEvaluator<R extends BaseRule = BaseRule> {
  readonly ruleType: string;
  matches(rule: R, context: PolicyContext): boolean;
  evaluate(rule: R, context: PolicyContext): RuleEvaluationResult;
}

export interface RuleEvaluationResult {
  matched: boolean;
  action?: 'ALLOW' | 'BLOCK';
  reasonCode?: string;
}
