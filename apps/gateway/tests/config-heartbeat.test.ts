import { describe, it, expect } from 'vitest';
import { loadConfig } from '../src/config.js';

const base = { GATEWAY_TOKENS_FILE: '/tmp/tokens.json', GATEWAY_POLICIES_FILE: '/tmp/policies.json' };

describe('GATEWAY_HEARTBEAT_THRESHOLD_SECONDS', () => {
    it('defaults to five minutes', () => {
        expect(loadConfig(base).heartbeatThresholdSeconds).toBe(300);
    });

    it('reads a custom value', () => {
        expect(loadConfig({ ...base, GATEWAY_HEARTBEAT_THRESHOLD_SECONDS: '10' }).heartbeatThresholdSeconds).toBe(10);
    });

    it('rejects zero, negative and non-numeric values', () => {
        for (const value of ['0', '-5', 'abc']) {
            expect(() => loadConfig({ ...base, GATEWAY_HEARTBEAT_THRESHOLD_SECONDS: value })).toThrow(/GATEWAY_HEARTBEAT_THRESHOLD_SECONDS/);
        }
    });
});
