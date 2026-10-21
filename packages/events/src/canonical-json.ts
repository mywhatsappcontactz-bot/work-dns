/**
 * Deterministic JSON stringifier that sorts object keys lexicographically.
 * Ensures consistent cryptographic hashes across platforms and runtimes.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']';
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([_, v]) => v !== undefined)
    .sort(([a], [b]) => a.localeCompare(b));

  return '{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + canonicalJson(v)).join(',') + '}';
}
