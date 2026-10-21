# Adding a Module to Work-Only DNS Platform
*Extensibility Guide & Architecture Standard*

---

## 1. The Zero-Core-Modification Rule

In this platform, **adding a feature must never require modifying core packages** (`packages/policy-engine`, `packages/events`, `apps/api`, `apps/gateway`).

Every new capability must be encapsulated as a self-contained module in:
```
packages/modules/<module-name>/
```

### The Module Contract
Each module exports an implementation of `ModuleContract`:
1. **Rule Types**: Custom rule evaluation logic registered with the policy engine (e.g., `CategoryRule`, `KeywordRule`, `IPRangeRule`).
2. **API Routes**: Sub-router for module-specific endpoints (e.g., `/api/v1/modules/<module-name>/*`).
3. **Event Handlers**: Subscribers for system-wide audit and telemetry events.
4. **Database Migrations / Schema Extensions**: Dedicated tenant-isolated tables or schema additions.
5. **Dashboard Components**: Metadata and React/Next.js dashboard page contributions.

---

## 2. Step-by-Step: Creating a New Module

### Step 1: Create the directory
Create `packages/modules/<module-name>/` with the standard layout:
```
packages/modules/category-rules/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts          # Main module entry point implementing ModuleContract
│   ├── rules/            # Custom policy-engine rule implementations
│   ├── routes/           # Fastify/Express route plugins
│   ├── handlers/         # Async event handlers
│   └── types.ts          # Module-specific DTOs and types
└── tests/
    └── category-rule.test.ts
```

### Step 2: Implement `ModuleContract`
In `src/index.ts`:
```typescript
import { ModuleContract, ModuleContext } from '@work-dns/module-contract';
import { CategoryRuleHandler } from './rules/category-rule.js';

export const CategoryRulesModule: ModuleContract = {
  id: 'category-rules',
  name: 'Category Rules Extension',
  version: '1.0.0',
  description: 'Enforces web filtering by high-level category classifications',
  
  // Register rule types
  rules: [
    new CategoryRuleHandler(),
  ],

  // Register routes (optional)
  registerRoutes(router, context: ModuleContext) {
    router.get('/categories', async (req, reply) => {
      return { categories: ['social-media', 'gambling', 'streaming', 'work-tools'] };
    });
  },

  // Event handlers (optional)
  eventHandlers: {
    'dns_blocked': async (event, context) => {
      // Custom module analytics or alerting
    },
  },
};
```

### Step 3: Register in the Module Registry (Single Line)
In `packages/modules/registry.ts`:
```typescript
import { CategoryRulesModule } from '@work-dns/module-category-rules';

export const ENABLED_MODULES = [
  CategoryRulesModule, // <-- Only 1 line added!
];
```

---

## 3. Strict Boundary Rules (Architectural Invariants)

1. **No Cross-Module Imports**: A module in `packages/modules/A` must **never** import from `packages/modules/B`.
2. **No Core Internal Leaks**: Modules must **only** import from public package exports (`@work-dns/module-contract`, `@work-dns/shared-types`, `@work-dns/events`).
3. **Multi-Tenant Isolation**: Any module query or state access must respect `company_id`.
4. **Pure Rule Evaluation**: Rule evaluation functions must be pure and synchronous, with zero network or disk I/O in the DNS query resolution path.

These boundaries are automatically verified in CI using `dependency-cruiser` and architectural unit tests.
