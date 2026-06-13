/** Keys that must never appear in JCS-bound payloads (prototype pollution / key confusion). */
export const FORBIDDEN_OBJECT_KEYS = ['__proto__', 'constructor', 'prototype'] as const;

export type ForbiddenObjectKey = (typeof FORBIDDEN_OBJECT_KEYS)[number];

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Depth-first scan — throws TypeError if a forbidden key is present anywhere in the tree.
 */
export function assertNoForbiddenKeys(value: unknown, path = ''): void {
  if (!isPlainObject(value)) {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1) {
        assertNoForbiddenKeys(value[i], `${path}[${i}]`);
      }
    }
    return;
  }

  for (const key of Object.keys(value)) {
    if ((FORBIDDEN_OBJECT_KEYS as readonly string[]).includes(key)) {
      const at = path ? ` at ${path}` : '';
      throw new TypeError(`Forbidden key "${key}" in payload${at}`);
    }
    assertNoForbiddenKeys(value[key], path ? `${path}.${key}` : key);
  }
}

/**
 * Copy enumerable own keys onto a null-prototype object after forbidden-key validation.
 */
export function toNullPrototypeRecord(value: Record<string, unknown>): Record<string, unknown> {
  assertNoForbiddenKeys(value);
  const out = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(value)) {
    out[key] = value[key];
  }
  return out;
}

/**
 * Unicode NFKC normalization for AttestMCP manifest strings and receipt leaf fields.
 */
export function normalizeUnicodeNfkc(value: string): string {
  return String(value ?? '').normalize('NFKC').trim();
}
