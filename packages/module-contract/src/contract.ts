import { IRuleEvaluator, CompanyId, EventEnvelope } from '@work-dns/shared-types';

export interface ModuleContext {
  companyId?: CompanyId;
  logger: {
    info(msg: string, meta?: Record<string, unknown>): void;
    warn(msg: string, meta?: Record<string, unknown>): void;
    error(msg: string, error?: unknown): void;
  };
}

export interface ModuleRouteRegistry {
  get(path: string, handler: (req: unknown, reply: unknown) => Promise<unknown> | unknown): void;
  post(path: string, handler: (req: unknown, reply: unknown) => Promise<unknown> | unknown): void;
  put(path: string, handler: (req: unknown, reply: unknown) => Promise<unknown> | unknown): void;
  delete(path: string, handler: (req: unknown, reply: unknown) => Promise<unknown> | unknown): void;
}

export interface ModuleMigration {
  version: number;
  description: string;
  sqlUp: string;
}

export interface ModuleDashboardPage {
  path: string;
  title: string;
  navSection: 'policies' | 'reports' | 'settings' | 'extensions';
  icon?: string;
  componentName: string;
}

export interface ModuleContract {
  /** Unique machine identifier for this module */
  readonly id: string;
  /** Human-readable display name */
  readonly name: string;
  /** Semantic version string */
  readonly version: string;
  /** Brief description of capability */
  readonly description: string;

  /** Optional custom rule evaluators registered into the policy engine */
  readonly rules?: IRuleEvaluator[];

  /** Optional REST API routes registered under /api/v1/modules/:id */
  registerRoutes?(router: ModuleRouteRegistry, context: ModuleContext): void;

  /** Optional asynchronous event handlers triggered on system events */
  readonly eventHandlers?: Record<string, (event: EventEnvelope, context: ModuleContext) => Promise<void>>;

  /** Optional SQL migrations for module-specific database tables */
  readonly migrations?: ModuleMigration[];

  /** Optional admin dashboard UI page contributions */
  readonly dashboardPages?: ModuleDashboardPage[];
}
