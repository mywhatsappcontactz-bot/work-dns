import { describe, it, expect } from 'vitest';
import { loadConfig } from '../src/config.js';

const base = { GATEWAY_TOKENS_FILE: '/tmp/tokens.json', GATEWAY_POLICIES_FILE: '/tmp/policies.json' };

describe('GATEWAY_ROLLUP_WINDOW_SECONDS', () => {
    it('defaults to five minutes', () => {
        expect(loadConfig(base).rollupWindowSeconds).toBe(300);
    });

    it('reads a custom value', () => {
        expect(loadConfig({ ...base, GATEWAY_ROLLUP_WINDOW_SECONDS: '60' }).rollupWindowSeconds).toBe(60);
    });

    it('rejects zero, negative and non-numeric values', () => {
        for (const value of ['0', '-5', 'abc']) {
            expect(() => loadConfig({ ...base, GATEWAY_ROLLUP_WINDOW_SECONDS: value })).toThrow(/GATEWAY_ROLLUP_WINDOW_SECONDS/);
        }
    });
});
