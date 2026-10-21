import { describe, it, expect } from 'vitest';
import { ModuleRegistry } from '@work-dns/module-contract';
import { PolicyEngine } from '@work-dns/policy-engine';
import { PolicyDefinition, PolicyContext } from '@work-dns/shared-types';
import { CategoryRulesModule, CategoryRule } from '../src/index.js';

describe('Category Rules Module - Extensibility Contract Proof', () => {
  it('registers into PolicyEngine without any core code changes and blocks category domains', () => {
    // 1. Core engine initialized with empty registry
    const engine = new PolicyEngine();
    const registry = new ModuleRegistry();

    // 2. Register the extension module
    registry.register(CategoryRulesModule);
    registry.bindRulesToEngine(engine);

    // 3. Define a policy that incorporates the new category_rule type
    const policyWithCategoryRule: PolicyDefinition = {
      id: 'pol-hotel-ext',
      companyId: 'comp-hotel-1',
      version: 1,
      mode: 'strict',
      defaultActionDuringEnforcedHours: 'ALLOW', // baseline allow to test explicit category block
      defaultActionOutsideEnforcedHours: 'ALLOW',
      timezone: 'Africa/Lagos',
      rules: [
        {
          id: 'rule-block-gambling',
          type: 'category_rule',
          category: 'gambling',
          effect: 'BLOCK',
          priority: 5,
        } as CategoryRule,
        {
          id: 'rule-block-social',
          type: 'category_rule',
          category: 'social_media',
          effect: 'BLOCK',
          priority: 10,
        } as CategoryRule,
      ],
      updatedAt: new Date().toISOString(),
    };

    const baseContext: PolicyContext = {
      companyId: 'comp-hotel-1',
      deviceId: 'dev-reception-1',
      deviceGroupId: null,
      queriedDomain: 'bet9ja.com',
      clientTimestamp: Date.now(),
      timezone: 'Africa/Lagos',
      policyVersion: 1,
    };

    // 4. Test Nigerian gambling domain is blocked by category rule
    const decisionGambling = engine.evaluate(policyWithCategoryRule, {
      ...baseContext,
      queriedDomain: 'sports.bet9ja.com',
    });
    expect(decisionGambling.action).toBe('BLOCK');
    expect(decisionGambling.reasonCode).toBe('CATEGORY_GAMBLING_BLOCK');
    expect(decisionGambling.ruleId).toBe('rule-block-gambling');

    // 5. Test social media domain is blocked by category rule
    const decisionSocial = engine.evaluate(policyWithCategoryRule, {
      ...baseContext,
      queriedDomain: 'instagram.com',
    });
    expect(decisionSocial.action).toBe('BLOCK');
    expect(decisionSocial.reasonCode).toBe('CATEGORY_SOCIAL_MEDIA_BLOCK');
    expect(decisionSocial.ruleId).toBe('rule-block-social');

    // 6. Test benign domain is not matched by category rule and falls through
    const decisionBenign = engine.evaluate(policyWithCategoryRule, {
      ...baseContext,
      queriedDomain: 'hotel-supplier.ng',
    });
    expect(decisionBenign.action).toBe('ALLOW');
  });

  it('exposes routes and dashboard contributions via ModuleContract', () => {
    expect(CategoryRulesModule.id).toBe('category-rules');
    expect(CategoryRulesModule.dashboardPages).toBeDefined();
    expect(CategoryRulesModule.dashboardPages?.[0]?.title).toBe('Category Policies');

    // Verify route handler
    const mockRouter = {
      get: (path: string, handler: Function) => {
        expect(path).toBe('/categories');
        const res = handler();
        expect(res.categories.length).toBeGreaterThan(0);
      },
      post: () => {},
      put: () => {},
      delete: () => {},
    };

    CategoryRulesModule.registerRoutes?.(mockRouter as any, {
      logger: { info: () => {}, warn: () => {}, error: () => {} },
    });
  });
});
