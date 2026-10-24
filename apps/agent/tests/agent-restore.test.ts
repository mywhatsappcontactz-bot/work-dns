import { describe, it, expect } from 'vitest';
import { runRestore } from '../src/restore.js';

function adapterFailing(times: number) {
    let calls = 0;
    return {
        calls: () => calls,
        adapter: {
            restoreDns: async () => {
                calls += 1;
                if (calls <= times) throw new Error('nmcli unavailable');
            },
        },
    };
}

describe('runRestore', () => {
    it('returns 0 after one successful restore', async () => {
        const f = adapterFailing(0);
        expect(await runRestore(f.adapter, { delayMs: 1, log: () => {} })).toBe(0);
        expect(f.calls()).toBe(1);
    });

    it('retries and returns 0 when a later attempt succeeds', async () => {
        const f = adapterFailing(2);
        expect(await runRestore(f.adapter, { attempts: 3, delayMs: 1, log: () => {} })).toBe(0);
        expect(f.calls()).toBe(3);
    });

    it('returns 1 and reports a manual fix when every attempt fails', async () => {
        const f = adapterFailing(99);
        const messages: string[] = [];
        const code = await runRestore(f.adapter, { attempts: 3, delayMs: 1, log: (_l, m) => messages.push(m) });
        expect(code).toBe(1);
        expect(f.calls()).toBe(3);
        expect(messages[messages.length - 1]).toMatch(/by hand/);
    });
});
