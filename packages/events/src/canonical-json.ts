/**
 * Deterministic JSON stringifier adhering to RFC 8785 (JSON Canonicalization Scheme).
 * 
 * Guarantees:
 * 1. Deterministic object key ordering based strictly on UTF-16 code units (locale-independent).
 * 2. Strict rejection of non-deterministic or invalid types: Date instances, NaN, Infinity, BigInt,
 *    and undefined elements in arrays.
 * 3. Consistent cryptographic hashes across all platforms, operating systems, and runtimes.
 */

export function canonicalJson(value: unknown): string {
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

  if (value instanceof Date || Object.prototype.toString.call(value) === '[object Date]') {
    throw new TypeError('canonicalJson: Date instances are not allowed; format to ISO-8601 string before serialization');
  }

  if (typeof value === 'symbol' || typeof value === 'function') {
    throw new TypeError(`canonicalJson: Unsupported type: ${typeof value}`);
  }

  if (Array.isArray(value)) {
    const elements = value.map((item, index) => {
      if (item === undefined) {
        throw new TypeError(`canonicalJson: undefined in arrays is not allowed (at index ${index})`);
      }
      return canonicalJson(item);
    });
    return '[' + elements.join(',') + ']';
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([_, v]) => v !== undefined)
      // Strictly sort by UTF-16 code-unit values (RFC 8785 Section 3.2.3), NOT localeCompare
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

    return '{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + canonicalJson(v)).join(',') + '}';
  }

  throw new TypeError(`canonicalJson: Unsupported value: ${String(value)}`);
}
