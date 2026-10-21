import {
  PolicyDefinition,
  PolicyContext,
  PolicyDecision,
  DomainAllowRule,
  ScheduleRule,
  Rule,
  IRuleEvaluator,
} from '@work-dns/shared-types';
import { matchesDomainPattern } from './rules/domain-matcher.js';
import { isWithinScheduleWindows } from './rules/schedule-evaluator.js';

export class PolicyEngine {
  private customEvaluators = new Map<string, IRuleEvaluator>();

  /**
   * Registers a custom rule evaluator (e.g. from an extension module).
   */
  public registerEvaluator(evaluator: IRuleEvaluator): void {
    this.customEvaluators.set(evaluator.ruleType, evaluator);
  }

  /**
   * Evaluates a DNS query against the compiled tenant policy.
   * Pure function: Zero I/O, synchronous, deterministic.
   */
  public evaluate(policy: PolicyDefinition, context: PolicyContext): PolicyDecision {
    const policyVersion = policy.version;

    // 1. Audit-only mode bypass
    if (policy.mode === 'audit_only') {
      return {
        action: 'ALLOW',
        reasonCode: 'AUDIT_ONLY_MODE',
        ruleId: null,
        policyVersion,
        debugNote: 'Allowed because tenant policy is operating in audit-only mode',
      };
    }

    // 2. Schedule evaluation
    const scheduleRule = policy.rules.find((r): r is ScheduleRule => r.type === 'schedule');
    let isEnforcedWindow = true;

    if (scheduleRule && scheduleRule.enforcedWindows.length > 0) {
      isEnforcedWindow = isWithinScheduleWindows(
        context.clientTimestamp,
        context.timezone || policy.timezone,
        scheduleRule.enforcedWindows
      );

      // If outside enforced window and policy specifies relaxed allow:
      if (!isEnforcedWindow && policy.defaultActionOutsideEnforcedHours === 'ALLOW') {
        return {
          action: 'ALLOW',
          reasonCode: 'OUTSIDE_WORK_HOURS',
          ruleId: scheduleRule.id,
          policyVersion,
          debugNote: 'Allowed because query occurred outside configured working hours',
        };
      }
    }

    // 3. Sort rules by priority (lowest number = highest precedence)
    const sortedRules = [...policy.rules].sort((a, b) => a.priority - b.priority);

    for (const rule of sortedRules) {
      // Check device scope
      if (!this.matchesScope(rule, context)) {
        continue;
      }

      // Built-in DomainAllow rule
      if (rule.type === 'domain_allow') {
        const domainRule = rule as DomainAllowRule;
        if (matchesDomainPattern(domainRule.pattern, context.queriedDomain)) {
          return {
            action: 'ALLOW',
            reasonCode: 'ALLOWLIST_MATCH',
            ruleId: rule.id,
            policyVersion,
            matchedRuleType: 'domain_allow',
            debugNote: `Matched allowlist pattern: ${domainRule.pattern}`,
          };
        }
      }

      // Custom extension rule evaluators
      const customEvaluator = this.customEvaluators.get(rule.type);
      if (customEvaluator) {
        if (customEvaluator.matches(rule, context)) {
          const result = customEvaluator.evaluate(rule, context);
          if (result.matched && result.action) {
            return {
              action: result.action,
              reasonCode: result.reasonCode ?? `CUSTOM_RULE_${rule.type.toUpperCase()}`,
              ruleId: rule.id,
              policyVersion,
              matchedRuleType: rule.type,
            };
          }
        }
      }
    }

    // 4. Default action (Default-Deny)
    const defaultAction = isEnforcedWindow
      ? policy.defaultActionDuringEnforcedHours
      : policy.defaultActionOutsideEnforcedHours;

    return {
      action: defaultAction,
      reasonCode: defaultAction === 'BLOCK' ? 'DEFAULT_DENY_UNLISTED_DOMAIN' : 'DEFAULT_ALLOW',
      ruleId: null,
      policyVersion,
      debugNote: 'No matching allowlist rule found; applied default policy',
    };
  }

  /**
   * Checks if a rule applies to the context's device or device group.
   */
  private matchesScope(rule: Rule, context: PolicyContext): boolean {
    if (!rule.scope) {
      return true; // No scope restrictions -> applies to all devices
    }

    if (rule.scope.deviceIds && rule.scope.deviceIds.length > 0) {
      if (!rule.scope.deviceIds.includes(context.deviceId)) {
        return false;
      }
    }

    if (rule.scope.deviceGroupIds && rule.scope.deviceGroupIds.length > 0) {
      if (!context.deviceGroupId || !rule.scope.deviceGroupIds.includes(context.deviceGroupId)) {
        return false;
      }
    }

    return true;
  }
}

/**
 * Global pure evaluate function instance for easy imports.
 */
export const defaultPolicyEngine = new PolicyEngine();
export const evaluatePolicy = (policy: PolicyDefinition, context: PolicyContext): PolicyDecision =>
  defaultPolicyEngine.evaluate(policy, context);
