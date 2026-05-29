/**
 * Stable JSON serialization (sorted object keys) — identical to art12PackSigningService.js.
 * @param {unknown} value
 * @returns {string}
 */
export function stableStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  const keys = Object.keys(/** @type {Record<string, unknown>} */ (value)).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${stableStringify(/** @type {Record<string, unknown>} */ (value)[key])}`)
    .join(',')}}`;
}
