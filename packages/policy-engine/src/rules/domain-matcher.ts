/**
 * Normalizes a queried domain name:
 * - converts to lowercase
 * - strips leading/trailing whitespaces and trailing dot (e.g. "example.com." -> "example.com")
 */
export function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.+$/, '');
}

/**
 * Checks if a queried domain matches an allow pattern.
 * Supports:
 * - Exact match: "google.com" matches "google.com"
 * - Wildcard match: "*.google.com" matches "mail.google.com", "docs.google.com", and "google.com"
 */
export function matchesDomainPattern(pattern: string, queriedDomain: string): boolean {
  const normPattern = normalizeDomain(pattern);
  const normDomain = normalizeDomain(queriedDomain);

  if (normPattern === normDomain) {
    return true;
  }

  if (normPattern.startsWith('*.')) {
    const baseDomain = normPattern.slice(2);
    // Matches the base domain itself (e.g. *.slack.com matches slack.com)
    if (normDomain === baseDomain) {
      return true;
    }
    // Matches subdomains (e.g. *.slack.com matches api.slack.com and foo.api.slack.com)
    if (normDomain.endsWith('.' + baseDomain)) {
      return true;
    }
  }

  return false;
}
