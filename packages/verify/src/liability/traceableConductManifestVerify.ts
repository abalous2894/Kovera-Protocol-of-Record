import { sha256HexUtf8 } from '../core/sha256.js';
import { TRACEABLE_CONDUCT_MANIFEST_SCHEMA } from '../core/traceableConductManifest.js';
import { stableStringify } from '../core/stableStringify.js';

export const TRACEABLE_CONDUCT_MANIFEST_SKU = 'aevesa-traceable-conduct-manifest-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;

export interface TraceableConductManifestVerifyResult {
  schema: typeof TRACEABLE_CONDUCT_MANIFEST_SCHEMA;
  sku: typeof TRACEABLE_CONDUCT_MANIFEST_SKU;
  ok: boolean;
  manifest_digest_matches: boolean;
  material_entries_present: boolean;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function verifyTraceableConductManifest(docInput: unknown): TraceableConductManifestVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA;
  const organizationIdPresent = Boolean(String(doc?.organization_id || '').trim());
  const sessionIdPresent = Boolean(String(doc?.session_id || '').trim());
  const material = Array.isArray(doc?.material_entry_hashes) ? doc.material_entry_hashes : [];
  const material_entries_present = material.length > 0;

  let manifest_digest_matches = false;
  if (doc && typeof doc.manifest_digest === 'string' && HEX64.test(doc.manifest_digest)) {
    const { manifest_digest, ...rest } = doc;
    const recomputed = sha256HexUtf8(stableStringify(rest));
    manifest_digest_matches = recomputed === manifest_digest;
  }

  const ok =
    schemaValid &&
    organizationIdPresent &&
    sessionIdPresent &&
    material_entries_present &&
    manifest_digest_matches;

  return {
    schema: TRACEABLE_CONDUCT_MANIFEST_SCHEMA,
    sku: TRACEABLE_CONDUCT_MANIFEST_SKU,
    ok,
    manifest_digest_matches,
    material_entries_present,
    note: ok ? 'Traceable conduct manifest verified offline.' : 'Traceable conduct manifest incomplete.',
  };
}

export default verifyTraceableConductManifest;
