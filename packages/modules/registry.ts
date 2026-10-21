import { ModuleContract } from '@work-dns/module-contract';
import { CategoryRulesModule } from '@work-dns/module-category-rules';

/**
 * Global array of all enabled feature modules.
 * Adding a new feature module requires adding exactly ONE entry here.
 */
export const ENABLED_MODULES: ModuleContract[] = [
  CategoryRulesModule,
];
