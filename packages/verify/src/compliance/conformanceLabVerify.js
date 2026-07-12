/**
 * Wave 3.1 — offline validation for aevesa.conformance-lab/1 manifest.
 */

/**
 * @param {unknown} manifest
 */
export function validateConformanceLabManifest(manifest) {
  const errors = [];
  if (!manifest || typeof manifest !== 'object') {
    return { ok: false, errors: ['manifest must be an object'] };
  }

  const m = /** @type {Record<string, unknown>} */ (manifest);

  if (m.schema !== 'aevesa.conformance-lab/1') {
    errors.push(`schema must be aevesa.conformance-lab/1 (got ${String(m.schema)})`);
  }
  if (m.sku !== 'kovera-conformance-lab-v1') {
    errors.push(`sku must be kovera-conformance-lab-v1 (got ${String(m.sku)})`);
  }

  const programs = m.conformance_programs;
  if (!Array.isArray(programs) || programs.length < 3) {
    errors.push('conformance_programs must be an array with at least 3 programs');
  }

  const interop = m.interop;
  if (!interop || typeof interop !== 'object') {
    errors.push('interop object required');
  } else {
    const ih = String(/** @type {Record<string, unknown>} */ (interop).entry_hash || '');
    if (ih && !/^[a-f0-9]{64}$/.test(ih)) {
      errors.push('interop.entry_hash must be 64-char hex when present');
    }
  }

  return { ok: errors.length === 0, errors };
}

export default { validateConformanceLabManifest };
