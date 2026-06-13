/**
 * JSON Canonicalization Scheme (JCS / RFC 8785) — deterministic UTF-8 serialization
 * for offline-verifiable receipt digests.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8785.html
 */

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * RFC 8785 §3.2.3 — ES6 Number.toString() with -0 normalized to 0.
 * @param {number} n
 */
export function serializeJcsNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new TypeError('JCS: non-finite numbers are not permitted');
  }
  if (Object.is(n, -0)) {
    return '0';
  }
  if (Number.isInteger(n) && Math.abs(n) < 1e21) {
    return n.toFixed(1).replace(/\.0$/, '');
  }
  let s = n.toString();
  if (s.includes('e') || s.includes('E')) {
    return s.replace('e+', 'E+').replace('e-', 'E-');
  }
  if (s.startsWith('0.') && s.length > 2) {
    s = s.replace(/^0\./, '.');
  }
  return s;
}

/**
 * @param {unknown} value
 * @returns {string}
 */
export function serializeJcs(value: unknown): string {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') return serializeJcsNumber(value as number);
  if (t === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => serializeJcs(item)).join(',')}]`;
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${serializeJcs(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError(`JCS: unsupported type ${t}`);
}

/** Alias for RFC 8785 canonicalization. */
export const canonicalizeJcs = serializeJcs;
