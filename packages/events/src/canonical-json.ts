/**
 * Deterministic JSON stringifier adhering to RFC 8785 (JSON Canonicalization Scheme).
 * 
 * Guarantees:
 * 1. Deterministic object key ordering based strictly on UTF-16 code units (locale-independent).
 * 2. Strict rejection of non-deterministic or invalid types: Date instances, NaN, Infinity, BigInt,
 *    undefined elements in arrays, Map, Set, Buffer, RegExp, and class instances. Only plain objects,
 *    arrays, and valid JSON primitives are allowed.
 * 3. Enforced maximum nesting depth limit to prevent stack exhaustion attacks.
 * 4. Consistent cryptographic hashes across all platforms, operating systems, and runtimes.
 */

export const DEFAULT_MAX_DEPTH = 64;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

export function canonicalJson(
  value: unknown,
  depth: number = 0,
  maxDepth: number = DEFAULT_MAX_DEPTH
): string {
  if (depth > maxDepth) {
    throw new RangeError(`canonicalJson: Maximum nesting depth of ${maxDepth} exceeded`);
  }

  if (value === undefined) {
    throw new TypeError('canonicalJson: undefined is not valid canonical JSON');
  }

  if (typeof value === 'bigint') {
    throw new TypeError('canonicalJson: BigInt is not supported in canonical JSON');
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('canonicalJson: NaN and Infinity are not allowed in canonical JSON');
    }
    // Handle -0 normalization per RFC 8785
    return Object.is(value, -0) ? '0' : JSON.stringify(value);
  }

  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }

  if (typeof value === 'symbol' || typeof value === 'function') {
    throw new TypeError(`canonicalJson: Unsupported type: ${typeof value}`);
  }

  if (value instanceof Date || Object.prototype.toString.call(value) === '[object Date]') {
    throw new TypeError('canonicalJson: Date instances are not allowed; format to ISO-8601 string before serialization');
  }

  if (value instanceof RegExp || Object.prototype.toString.call(value) === '[object RegExp]') {
    throw new TypeError('canonicalJson: RegExp instances are not allowed in canonical JSON');
  }

  if (value instanceof Map || Object.prototype.toString.call(value) === '[object Map]') {
    throw new TypeError('canonicalJson: Map instances are not allowed in canonical JSON');
  }

  if (value instanceof Set || Object.prototype.toString.call(value) === '[object Set]') {
    throw new TypeError('canonicalJson: Set instances are not allowed in canonical JSON');
  }

  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) {
    throw new TypeError('canonicalJson: Buffer instances are not allowed in canonical JSON');
  }

  if (Array.isArray(value)) {
    const elements = value.map((item, index) => {
      if (item === undefined) {
        throw new TypeError(`canonicalJson: undefined in arrays is not allowed (at index ${index})`);
      }
      return canonicalJson(item, depth + 1, maxDepth);
    });
    return '[' + elements.join(',') + ']';
  }

  if (typeof value === 'object') {
    if (!isPlainObject(value)) {
      const className = (value as any)?.constructor?.name ?? 'NonPlainObject';
      throw new TypeError(`canonicalJson: Class instances and non-plain objects are not allowed: ${className}`);
    }

    const entries = Object.entries(value)
      .filter(([_, v]) => v !== undefined)
      // Strictly sort by UTF-16 code-unit values (RFC 8785 Section 3.2.3), NOT localeCompare
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

    return '{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + canonicalJson(v, depth + 1, maxDepth)).join(',') + '}';
  }

  throw new TypeError(`canonicalJson: Unsupported value: ${String(value)}`);
}
