import {
  ModuleContract,
  ModuleContext,
  ModuleRouteRegistry,
} from '@work-dns/module-contract';
import {
  CategoryRuleEvaluator,
  CATEGORY_DOMAINS,
} from './category-rule-evaluator.js';

export * from './category-rule-evaluator.js';

export const CategoryRulesModule: ModuleContract = {
  id: 'category-rules',
  name: 'Category Rules Extension',
  version: '0.1.0',
  description: 'Enforces web filtering by high-level category classifications (e.g. social media, gambling, streaming)',

  rules: [new CategoryRuleEvaluator()],

  registerRoutes(router: ModuleRouteRegistry, _context: ModuleContext) {
    router.get('/categories', () => {
      const summary = Object.entries(CATEGORY_DOMAINS).map(([category, domains]) => ({
        category,
        domainCount: domains.length,
      }));
      return { categories: summary };
    });
  },

  eventHandlers: {
    dns_blocked: async (event, context) => {
      const payload = event.payload as { domain?: string };
      context.logger.info(`[category-rules] Tracked blocked domain: ${payload.domain ?? 'unknown'}`);
    },
  },

  dashboardPages: [
    {
      path: '/policies/categories',
      title: 'Category Policies',
      navSection: 'policies',
      icon: 'ShieldAlert',
      componentName: 'CategoryPoliciesPage',
    },
  ],
};
