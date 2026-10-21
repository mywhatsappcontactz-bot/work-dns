import { describe, it, expect } from 'vitest';
import {
  PolicyEngine,
  matchesDomainPattern,
  normalizeDomain,
  isWithinScheduleWindows,
  STARTER_TEMPLATES,
  compileTemplateToRules,
} from '../src/index.js';
import {
  PolicyDefinition,
  PolicyContext,
  DomainAllowRule,
  ScheduleRule,
} from '@work-dns/shared-types';

describe('Domain Matcher', () => {
  it('normalizes domains by lowercasing and trimming trailing dots', () => {
    expect(normalizeDomain('  SLACK.COM.  ')).toBe('slack.com');
    expect(normalizeDomain('Docs.Google.Com')).toBe('docs.google.com');
  });

  it('matches exact domain names', () => {
    expect(matchesDomainPattern('slack.com', 'slack.com')).toBe(true);
    expect(matchesDomainPattern('slack.com', 'api.slack.com')).toBe(false);
    expect(matchesDomainPattern('slack.com', 'myslack.com')).toBe(false);
  });

  it('matches wildcard subdomains and the root base domain', () => {
    expect(matchesDomainPattern('*.slack.com', 'slack.com')).toBe(true);
    expect(matchesDomainPattern('*.slack.com', 'api.slack.com')).toBe(true);
    expect(matchesDomainPattern('*.slack.com', 'edge.api.slack.com')).toBe(true);
    expect(matchesDomainPattern('*.slack.com', 'evil-slack.com')).toBe(false);
    expect(matchesDomainPattern('*.slack.com', 'slack.com.attacker.com')).toBe(false);
  });
});

describe('Schedule Evaluator', () => {
  it('detects when timestamp falls within configured working hours in target timezone', () => {
    // 2026-10-21 is a Wednesday (dayOfWeek = 3)
    // 10:00 AM UTC in Africa/Lagos (UTC+1) is 11:00 AM local time = 11 * 60 = 660 mins
    const testDate = new Date('2026-10-21T10:00:00Z').getTime();

    const windows = [
      {
        dayOfWeek: 3 as const, // Wednesday
        startMinuteOfDay: 480,  // 8:00 AM
        endMinuteOfDay: 1020,   // 5:00 PM (17:00)
      },
    ];

    expect(isWithinScheduleWindows(testDate, 'Africa/Lagos', windows)).toBe(true);

    // Test time outside window: 8:00 PM local = 1200 mins (19:00 UTC)
    const lateDate = new Date('2026-10-21T19:00:00Z').getTime();
    expect(isWithinScheduleWindows(lateDate, 'Africa/Lagos', windows)).toBe(false);
  });
});

describe('PolicyEngine - Core Pure Evaluation', () => {
  const samplePolicy: PolicyDefinition = {
    id: 'pol-1',
    companyId: 'comp-100',
    version: 4,
    mode: 'strict',
    defaultActionDuringEnforcedHours: 'BLOCK',
    defaultActionOutsideEnforcedHours: 'ALLOW',
    timezone: 'Africa/Lagos',
    rules: [
      {
        id: 'rule-google',
        type: 'domain_allow',
        pattern: '*.google.com',
        effect: 'ALLOW',
        priority: 10,
      } as DomainAllowRule,
      {
        id: 'rule-slack',
        type: 'domain_allow',
        pattern: 'slack.com',
        effect: 'ALLOW',
        priority: 20,
      } as DomainAllowRule,
      {
        id: 'rule-reception-portal',
        type: 'domain_allow',
        pattern: 'hotel-pms.internal.com',
        effect: 'ALLOW',
        priority: 5,
        scope: {
          deviceGroupIds: ['front-desk-group'],
        },
      } as DomainAllowRule,
      {
        id: 'rule-work-schedule',
        type: 'schedule',
        priority: 1,
        enforcedWindows: [
          {
            dayOfWeek: 3, // Wednesday
            startMinuteOfDay: 480, // 08:00
            endMinuteOfDay: 1080,  // 18:00
          },
        ],
      } as ScheduleRule,
    ],
    updatedAt: new Date().toISOString(),
  };

  const engine = new PolicyEngine();

  it('allows queries that match the domain allowlist during work hours', () => {
    // Wednesday 10:00 AM UTC = 11:00 AM Lagos (inside work hours)
    const context: PolicyContext = {
      companyId: 'comp-100',
      deviceId: 'dev-1',
      deviceGroupId: 'back-office',
      queriedDomain: 'mail.google.com',
      clientTimestamp: new Date('2026-10-21T10:00:00Z').getTime(),
      timezone: 'Africa/Lagos',
      policyVersion: 4,
    };

    const decision = engine.evaluate(samplePolicy, context);
    expect(decision.action).toBe('ALLOW');
    expect(decision.reasonCode).toBe('ALLOWLIST_MATCH');
    expect(decision.ruleId).toBe('rule-google');
    expect(decision.policyVersion).toBe(4);
  });

  it('blocks unlisted domains with default-deny during enforced hours', () => {
    const context: PolicyContext = {
      companyId: 'comp-100',
      deviceId: 'dev-1',
      deviceGroupId: 'back-office',
      queriedDomain: 'facebook.com',
      clientTimestamp: new Date('2026-10-21T10:00:00Z').getTime(),
      timezone: 'Africa/Lagos',
      policyVersion: 4,
    };

    const decision = engine.evaluate(samplePolicy, context);
    expect(decision.action).toBe('BLOCK');
    expect(decision.reasonCode).toBe('DEFAULT_DENY_UNLISTED_DOMAIN');
  });

  it('relaxes policy outside working hours when configured to allow', () => {
    // 11:00 PM Lagos (outside 8am-6pm)
    const context: PolicyContext = {
      companyId: 'comp-100',
      deviceId: 'dev-1',
      deviceGroupId: 'back-office',
      queriedDomain: 'facebook.com',
      clientTimestamp: new Date('2026-10-21T22:00:00Z').getTime(),
      timezone: 'Africa/Lagos',
      policyVersion: 4,
    };

    const decision = engine.evaluate(samplePolicy, context);
    expect(decision.action).toBe('ALLOW');
    expect(decision.reasonCode).toBe('OUTSIDE_WORK_HOURS');
  });

  it('enforces device group scoping on rules', () => {
    const time = new Date('2026-10-21T10:00:00Z').getTime();

    // Device in 'front-desk-group' can access hotel-pms.internal.com
    const frontDeskCtx: PolicyContext = {
      companyId: 'comp-100',
      deviceId: 'dev-front-1',
      deviceGroupId: 'front-desk-group',
      queriedDomain: 'hotel-pms.internal.com',
      clientTimestamp: time,
      timezone: 'Africa/Lagos',
      policyVersion: 4,
    };
    expect(engine.evaluate(samplePolicy, frontDeskCtx).action).toBe('ALLOW');

    // Device in 'housekeeping' group is blocked from hotel-pms.internal.com
    const housekeepingCtx: PolicyContext = {
      companyId: 'comp-100',
      deviceId: 'dev-hk-1',
      deviceGroupId: 'housekeeping',
      queriedDomain: 'hotel-pms.internal.com',
      clientTimestamp: time,
      timezone: 'Africa/Lagos',
      policyVersion: 4,
    };
    expect(engine.evaluate(samplePolicy, housekeepingCtx).action).toBe('BLOCK');
  });

  it('allows all queries when policy is in audit-only mode', () => {
    const auditOnlyPolicy: PolicyDefinition = {
      ...samplePolicy,
      mode: 'audit_only',
    };

    const context: PolicyContext = {
      companyId: 'comp-100',
      deviceId: 'dev-1',
      deviceGroupId: null,
      queriedDomain: 'unlisted-site.com',
      clientTimestamp: new Date('2026-10-21T10:00:00Z').getTime(),
      timezone: 'Africa/Lagos',
      policyVersion: 4,
    };

    const decision = engine.evaluate(auditOnlyPolicy, context);
    expect(decision.action).toBe('ALLOW');
    expect(decision.reasonCode).toBe('AUDIT_ONLY_MODE');
  });

  it('compiles starter templates into valid domain rules', () => {
    const rules = compileTemplateToRules('google_workspace');
    expect(rules.length).toBeGreaterThan(5);
    expect(rules[0]?.type).toBe('domain_allow');
    expect(STARTER_TEMPLATES['slack']?.domains).toContain('slack.com');
  });
});
