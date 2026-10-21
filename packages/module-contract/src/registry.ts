import { ModuleContract, ModuleContext } from './contract.js';
import { PolicyEngine } from '@work-dns/policy-engine';
import { EventEnvelope } from '@work-dns/shared-types';

export class ModuleRegistry {
  private modules = new Map<string, ModuleContract>();

  /**
   * Registers a feature module that implements ModuleContract.
   */
  public register(module: ModuleContract): void {
    if (this.modules.has(module.id)) {
      throw new Error(`Module with id '${module.id}' is already registered.`);
    }
    this.modules.set(module.id, module);
  }

  /**
   * Returns all currently registered modules.
   */
  public getAllModules(): ModuleContract[] {
    return Array.from(this.modules.values());
  }

  /**
   * Returns a specific module by ID.
   */
  public getModule(id: string): ModuleContract | undefined {
    return this.modules.get(id);
  }

  /**
   * Binds all module rules into the policy engine.
   */
  public bindRulesToEngine(engine: PolicyEngine): void {
    for (const module of this.modules.values()) {
      if (module.rules) {
        for (const ruleEvaluator of module.rules) {
          engine.registerEvaluator(ruleEvaluator);
        }
      }
    }
  }

  /**
   * Dispatches an event to all module event handlers registered for that event type.
   */
  public async dispatchEvent(event: EventEnvelope, context: ModuleContext): Promise<void> {
    for (const module of this.modules.values()) {
      if (module.eventHandlers && module.eventHandlers[event.type]) {
        try {
          await module.eventHandlers[event.type]!(event, context);
        } catch (err) {
          context.logger.error(`Error executing event handler in module '${module.id}' for event '${event.type}'`, err);
        }
      }
    }
  }
}

export const globalModuleRegistry = new ModuleRegistry();
