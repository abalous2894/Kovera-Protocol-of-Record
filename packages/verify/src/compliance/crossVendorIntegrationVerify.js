/**
 * Wave 3.2 — offline validation for aevesa.cross-vendor-integration/1 manifest.
 */

/**
 * @param {unknown} manifest
 */
export function validateCrossVendorIntegrationManifest(manifest) {
  const errors = [];
  if (!manifest || typeof manifest !== 'object') {
    return { ok: false, errors: ['manifest must be an object'] };
  }

  const m = /** @type {Record<string, unknown>} */ (manifest);

  if (m.schema !== 'aevesa.cross-vendor-integration/1') {
    errors.push(`schema must be aevesa.cross-vendor-integration/1 (got ${String(m.schema)})`);
  }
  if (m.sku !== 'kovera-cross-vendor-integration-v1') {
    errors.push(`sku must be kovera-cross-vendor-integration-v1 (got ${String(m.sku)})`);
  }

  const packs = m.integration_packs;
  if (!Array.isArray(packs) || packs.length < 5) {
    errors.push('integration_packs must be an array with at least 5 packs');
  } else {
    const ids = packs.map((p) => String(/** @type {Record<string, unknown>} */ (p).id || ''));
    for (const required of [
      'kovera-cross-vendor-evidence-push-v1',
      'aevesa-witness-transparency-v1',
      'aevesa-gateway-otlp-pilot-v1',
    ]) {
      if (!ids.includes(required)) {
        errors.push(`integration_packs must include ${required}`);
      }
    }
  }

  const rekor = /** @type {Record<string, unknown>} */ (
    /** @type {Record<string, unknown>} */ (m.witness_transparency || {})?.rekor || {}
  );
  if (rekor.uuid && !String(rekor.uuid).includes('-')) {
    errors.push('witness_transparency.rekor.uuid should be UUID-shaped when present');
  }

  return { ok: errors.length === 0, errors };
}

export default { validateCrossVendorIntegrationManifest };
