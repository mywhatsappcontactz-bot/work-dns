# ADR 0002: Modular Architecture, Plugin Contracts & Dependency Enforcement

## Status
Accepted

## Context
The platform needs to support rapid feature additions (e.g., Category-based filtering, Time-quotas, DLP stubs, SIEM connectors) without turning into an unmaintainable monolith where every change requires editing core routing, policy evaluation, or event pipelines.

## Decision
1. **Core Package Segregation**: Core infrastructure (`packages/policy-engine`, `packages/events`, `packages/shared-types`, `apps/gateway`, `apps/api`) contains zero domain-specific feature logic.
2. **Explicit Module Contract**: All features are implemented in isolated directories under `packages/modules/<module-name>/` implementing the standardized `ModuleContract` interface:
   - Rule type registration with `PolicyEngine`
   - Route registration with API router
   - Event subscriber registration with `EventBus`
3. **Registration by Inversion of Control**: Registering a module requires exactly one line in `packages/modules/registry.ts`.
4. **Architectural Verification**: Dependency graph constraints are statically asserted using automated tooling (e.g. `dependency-cruiser` and Vitest):
   - Modules cannot import other modules (`modules/A` -> `modules/B` is forbidden).
   - Modules cannot import internal private files of core packages.
   - Core packages cannot import individual modules directly (only the registry).

## Consequences
- **Pros**: Completely decoupled features; enables independent testing, feature gating per tenant plan, and clean deprecation.
- **Cons**: Requires boilerplate contract adherence for trivial features.
