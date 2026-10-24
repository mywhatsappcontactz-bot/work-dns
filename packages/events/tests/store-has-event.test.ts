import { describe, it, expect, afterEach } from 'vitest';
import type { CompanyId } from '@work-dns/shared-types';
import { SqliteEventStore } from '../src/sqlite-store.js';

describe('SqliteEventStore.hasEvent', () => {
    let store: SqliteEventStore | undefined;

    afterEach(() => {
        store?.close();
    });

    it('is true only for ids that were stored', () => {
        store = new SqliteEventStore(':memory:');
        expect(store.hasEvent('e1')).toBe(false);
        store.append({ id: 'e1', type: 'agent_started', companyId: 'comp-a' as CompanyId, payload: { agentVersion: '0.1.0' } });
        expect(store.hasEvent('e1')).toBe(true);
        expect(store.hasEvent('e2')).toBe(false);
    });
});
