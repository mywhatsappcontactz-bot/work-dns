import * as fs from 'node:fs';
import type { PolicyDefinition } from '@work-dns/shared-types';
import type { AuthenticatedDeviceContext } from './auth.js';

export interface TokenRecord {
  tokenHash: string;
  context: AuthenticatedDeviceContext;
}

const HASH_PATTERN = /^[0-9a-f]{64}$/;
const STATUSES: ReadonlySet<string> = new Set(['active', 'suspended', 'revoked']);
const MAX_ID_LENGTH = 200;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= MAX_ID_LENGTH;
}

function errorMessageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function isValidTimeZone(timeZone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone });
    return true;
  } catch {
    return false; // Intl rejects unknown zones; that is the answer, not a swallowed failure
  }
}

function readJson(file: string, label: string, requirePrivate: boolean): unknown {
  let stats: fs.Stats;
  try {
    stats = fs.statSync(file);
  } catch (err) {
    throw new Error(`${label} file ${file} cannot be read: ${errorMessageOf(err)}`);
  }
  if (!stats.isFile()) {
    throw new Error(`${label} file ${file} is not a regular file`);
  }
  if (requirePrivate && process.platform !== 'win32' && (stats.mode & 0o077) !== 0) {
    throw new Error(`${label} file ${file} must not be accessible by group or others (run: chmod 600 ${file})`);
  }
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (err) {
    throw new Error(`${label} file ${file} cannot be read: ${errorMessageOf(err)}`);
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new Error(`${label} file ${file} is not valid JSON: ${errorMessageOf(err)}`);
  }
}

function failIfAny(errors: string[], label: string, file: string): void {
  if (errors.length > 0) {
    throw new Error(`Invalid ${label} file ${file}:\n- ${errors.join('\n- ')}`);
  }
}

/**
 * Loads device token records. The file holds SHA-256 hashes only, never raw tokens:
 * [{ "tokenHash": "<64 hex>", "deviceId": "...", "companyId": "...", "deviceGroupId": null, "status": "active" }]
 */
export function loadTokenRecords(file: string): TokenRecord[] {
  const data = readJson(file, 'Tokens', true);
  if (!Array.isArray(data)) {
    throw new Error(`Tokens file ${file} must contain a JSON array`);
  }

  const errors: string[] = [];
  const seen = new Set<string>();
  const records: TokenRecord[] = [];

  data.forEach((entry: unknown, index: number) => {
    const where = `tokens[${index}]`;
    if (!isRecord(entry)) {
      errors.push(`${where} must be an object`);
      return;
    }
    const { tokenHash, deviceId, companyId, status } = entry;
    const deviceGroupId = entry.deviceGroupId === undefined ? null : entry.deviceGroupId;

    let valid = true;
    if (typeof tokenHash !== 'string' || !HASH_PATTERN.test(tokenHash)) {
      errors.push(`${where}.tokenHash must be 64 lowercase hex characters (a SHA-256 hash)`);
      valid = false;
    } else if (seen.has(tokenHash)) {
      errors.push(`${where}.tokenHash duplicates an earlier entry`);
      valid = false;
    }
    if (!isNonEmptyString(deviceId)) {
      errors.push(`${where}.deviceId must be a non-empty string`);
      valid = false;
    }
    if (!isNonEmptyString(companyId)) {
      errors.push(`${where}.companyId must be a non-empty string`);
      valid = false;
    }
    if (deviceGroupId !== null && !isNonEmptyString(deviceGroupId)) {
      errors.push(`${where}.deviceGroupId must be null or a non-empty string`);
      valid = false;
    }
    if (typeof status !== 'string' || !STATUSES.has(status)) {
      errors.push(`${where}.status must be one of active, suspended, revoked`);
      valid = false;
    }

    if (valid) {
      seen.add(tokenHash as string);
      records.push({
        tokenHash: tokenHash as string,
        context: {
          deviceId: deviceId as string,
          companyId: companyId as string,
          deviceGroupId: deviceGroupId as string | null,
          status: status as AuthenticatedDeviceContext['status'],
        },
      });
    }
  });

  failIfAny(errors, 'tokens', file);
  return records;
}

/**
 * Loads policy definitions (one per company). The gateway checks the fields it reads; rule-specific
 * fields are not deeply validated here (UNKNOWN whether the policy engine validates them).
 */
export function loadPolicies(file: string): PolicyDefinition[] {
  const data = readJson(file, 'Policies', false);
  if (!Array.isArray(data)) {
    throw new Error(`Policies file ${file} must contain a JSON array`);
  }

  const errors: string[] = [];
  const companies = new Set<string>();
  const policies: PolicyDefinition[] = [];

  data.forEach((entry: unknown, index: number) => {
    const where = `policies[${index}]`;
    if (!isRecord(entry)) {
      errors.push(`${where} must be an object`);
      return;
    }
    const before = errors.length;

    for (const field of ['id', 'companyId', 'mode', 'defaultActionDuringEnforcedHours', 'defaultActionOutsideEnforcedHours', 'updatedAt']) {
      if (!isNonEmptyString(entry[field])) {
        errors.push(`${where}.${field} must be a non-empty string`);
      }
    }
    if (typeof entry.version !== 'number' || !Number.isInteger(entry.version) || entry.version < 1) {
      errors.push(`${where}.version must be a positive integer`);
    }
    if (typeof entry.timezone !== 'string' || !isValidTimeZone(entry.timezone)) {
      errors.push(`${where}.timezone must be a valid IANA time zone such as Africa/Lagos`);
    }
    if (!Array.isArray(entry.rules)) {
      errors.push(`${where}.rules must be an array`);
    } else {
      entry.rules.forEach((rule: unknown, ruleIndex: number) => {
        const ruleWhere = `${where}.rules[${ruleIndex}]`;
        if (!isRecord(rule) || !isNonEmptyString(rule.id) || !isNonEmptyString(rule.type)) {
          errors.push(`${ruleWhere} must be an object with a string id and type`);
        } else if (rule.type === 'domain_allow' && !isNonEmptyString(rule.pattern)) {
          errors.push(`${ruleWhere}.pattern must be a non-empty string`);
        }
      });
    }
    if (isNonEmptyString(entry.companyId)) {
      if (companies.has(entry.companyId)) {
        errors.push(`${where}.companyId duplicates an earlier policy (one policy per company)`);
      }
      companies.add(entry.companyId);
    }

    if (errors.length === before) {
      // Cast is deliberate: every field the gateway reads was verified above.
      policies.push(entry as unknown as PolicyDefinition);
    }
  });

  failIfAny(errors, 'policies', file);
  return policies;
}
