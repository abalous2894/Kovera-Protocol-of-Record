/**
 * Wave 2.3 — offline validation for kovera-incident-custody-pack/1 manifest.
 */

const REQUIRED_MANIFEST_FIELDS = [
  'incident_custody_pack_format_version',
  'product',
  'sku',
  'schema',
  'incident_ref',
  'freeze_anchor_entry_hash',
  'file_integrity',
];

/**
 * @param {unknown} manifest
 */
export function validateIncidentCustodyPackManifest(manifest) {
  const errors = [];
  if (!manifest || typeof manifest !== 'object') {
    return { ok: false, errors: ['manifest must be an object'] };
  }

  const m = /** @type {Record<string, unknown>} */ (manifest);

  for (const field of REQUIRED_MANIFEST_FIELDS) {
    if (m[field] == null || m[field] === '') {
      errors.push(`missing required field: ${field}`);
    }
  }

  if (m.schema !== 'kovera-incident-custody-pack/1') {
    errors.push(`schema must be kovera-incident-custody-pack/1 (got ${String(m.schema)})`);
  }

  if (m.sku !== 'kovera-incident-custody-pack-v1') {
    errors.push(`sku must be kovera-incident-custody-pack-v1 (got ${String(m.sku)})`);
  }

  const freezeHash = String(m.freeze_anchor_entry_hash || '');
  if (freezeHash && !/^[a-f0-9]{64}$/.test(freezeHash)) {
    errors.push('freeze_anchor_entry_hash must be 64-char hex when present');
  }

  const integrity = m.file_integrity;
  if (integrity && typeof integrity === 'object') {
    const requiredFiles = [
      'incident/freeze-receipt.json',
      'custody/receipt-index.json',
      'custody/legal-holds.json',
    ];
    for (const rel of requiredFiles) {
      if (!(/** @type {Record<string, unknown>} */ (integrity)[rel])) {
        errors.push(`file_integrity missing ${rel}`);
      }
    }
  } else {
    errors.push('file_integrity must be an object');
  }

  return { ok: errors.length === 0, errors };
}

export default { validateIncidentCustodyPackManifest };
