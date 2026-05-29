/**
 * Deep canonicalize — identical to aegisTrust.canonicalize().
 * @param {unknown} value
 */
export function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === 'object') {
    return Object.keys(/** @type {Record<string, unknown>} */ (value))
      .sort()
      .reduce((accumulator, key) => {
        accumulator[key] = canonicalize(/** @type {Record<string, unknown>} */ (value)[key]);
        return accumulator;
      }, /** @type {Record<string, unknown>} */ ({}));
  }
  return value;
}
