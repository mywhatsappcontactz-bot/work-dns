import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadPolicies, loadTokenRecords } from '../src/loaders.js';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

describe('config file loaders', () => {
  let dir: string;

  const write = (name: string, content: unknown, mode = 0o600): string => {
    const file = path.join(dir, name);
    fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content), { mode });
    fs.chmodSync(file, mode);
    return file;
  };

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'work-dns-loaders-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  describe('loadTokenRecords', () => {
    const entry = (extra: Record<string, unknown> = {}) => ({
      tokenHash: HASH_A,
      deviceId: 'dev-1',
      companyId: 'comp-1',
      deviceGroupId: null,
      status: 'active',
      ...extra,
    });

    it('loads valid records and defaults a missing group to null', () => {
      const { deviceGroupId: _omit, ...withoutGroup } = entry({ tokenHash: HASH_B, deviceId: 'dev-2' });
      const records = loadTokenRecords(write('tokens.json', [entry({ deviceGroupId: 'front-desk' }), withoutGroup]));
      expect(records).toEqual([
        { tokenHash: HASH_A, context: { deviceId: 'dev-1', companyId: 'comp-1', deviceGroupId: 'front-desk', status: 'active' } },
        { tokenHash: HASH_B, context: { deviceId: 'dev-2', companyId: 'comp-1', deviceGroupId: null, status: 'active' } },
      ]);
    });

    it('accepts several hashes for one device (token rotation)', () => {
      const records = loadTokenRecords(write('tokens.json', [entry(), entry({ tokenHash: HASH_B })]));
      expect(records).toHaveLength(2);
    });

    it('reports every invalid field with its index and never echoes hashes', () => {
      const file = write('tokens.json', [
        entry({ tokenHash: 'short' }),
        entry({ deviceId: '' }),
        entry({ companyId: 5 }),
        entry({ status: 'enabled' }),
        entry({ deviceGroupId: '' }),
        'not an object',
        entry({ tokenHash: HASH_B }),
        entry({ tokenHash: HASH_B, deviceId: 'dev-9' }),
      ]);
      let message = '';
      try {
        loadTokenRecords(file);
      } catch (err) {
        message = (err as Error).message;
      }
      for (const fragment of [
        'tokens[0].tokenHash',
        'tokens[1].deviceId',
        'tokens[2].companyId',
        'tokens[3].status',
        'tokens[4].deviceGroupId',
        'tokens[5] must be an object',
        'tokens[7].tokenHash duplicates',
      ]) {
        expect(message).toContain(fragment);
      }
      expect(message).not.toContain(HASH_B);
    });

    it('rejects uppercase hex (hashes are compared as lowercase)', () => {
      expect(() => loadTokenRecords(write('tokens.json', [entry({ tokenHash: 'A'.repeat(64) })]))).toThrow(/tokenHash/);
    });

    it('rejects files that are not a JSON array, are invalid JSON or are missing', () => {
      expect(() => loadTokenRecords(write('a.json', {}))).toThrow(/JSON array/);
      expect(() => loadTokenRecords(write('b.json', '{oops'))).toThrow(/not valid JSON/);
      expect(() => loadTokenRecords(path.join(dir, 'missing.json'))).toThrow(/cannot be read/);
      expect(() => loadTokenRecords(dir)).toThrow(/not a regular file/);
    });

    it.skipIf(process.platform === 'win32')('refuses a tokens file readable by group or others', () => {
      expect(() => loadTokenRecords(write('tokens.json', [entry()], 0o644))).toThrow(/chmod 600/);
      expect(() => loadTokenRecords(write('tokens2.json', [entry()], 0o640))).toThrow(/chmod 600/);
    });
  });

  describe('loadPolicies', () => {
    const policy = (extra: Record<string, unknown> = {}) => ({
      id: 'pol-1',
      companyId: 'comp-1',
      version: 1,
      mode: 'strict',
      defaultActionDuringEnforcedHours: 'BLOCK',
      defaultActionOutsideEnforcedHours: 'BLOCK',
      timezone: 'Africa/Lagos',
      rules: [{ id: 'r1', type: 'domain_allow', pattern: '*.google.com', effect: 'ALLOW', priority: 1 }],
      updatedAt: '2026-10-21T00:00:00.000Z',
      ...extra,
    });

    it('loads valid policies and does not require a private file', () => {
      const policies = loadPolicies(write('policies.json', [policy(), policy({ id: 'pol-2', companyId: 'comp-2' })], 0o644));
      expect(policies.map((p) => p.companyId)).toEqual(['comp-1', 'comp-2']);
    });

    it('reports every problem with its index', () => {
      const file = write('policies.json', [
        policy({ id: '' }),
        policy({ companyId: 'comp-2', version: 0 }),
        policy({ companyId: 'comp-3', timezone: 'Mars/Olympus' }),
        policy({ companyId: 'comp-4', rules: 'nope' }),
        policy({ companyId: 'comp-5', rules: [{ id: 'r1', type: 'domain_allow' }] }),
        policy({ companyId: 'comp-6', rules: [5] }),
        policy({ companyId: 'comp-1' }),
        42,
      ]);
      let message = '';
      try {
        loadPolicies(file);
      } catch (err) {
        message = (err as Error).message;
      }
      for (const fragment of [
        'policies[0].id',
        'policies[1].version',
        'policies[2].timezone',
        'policies[3].rules must be an array',
        'policies[4].rules[0].pattern',
        'policies[5].rules[0] must be an object',
        'policies[6].companyId duplicates',
        'policies[7] must be an object',
      ]) {
        expect(message).toContain(fragment);
      }
    });

    it('rejects non-array and invalid JSON files', () => {
      expect(() => loadPolicies(write('a.json', {}))).toThrow(/JSON array/);
      expect(() => loadPolicies(write('b.json', 'nope'))).toThrow(/not valid JSON/);
    });
  });
});
