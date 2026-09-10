import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 10 Track T / Wave 8 Track P lite — hash-only conduct reconstruction manifest. */

export const TRACEABLE_CONDUCT_MANIFEST_SCHEMA = 'aevesa.traceable-conduct-manifest/v1' as const;

export interface TraceableConductMemberArtifact {
  member_schema: string;
  member_digest: string;
  label: string;
  entry_count?: number | null;
}

export interface TraceableConductManifestInput {
  organization_id: string;
  session_id: string;
  generated_at?: string;
  delegation_chain_digest: string | null;
  material_entry_hashes: string[];
  denial_entry_hashes?: string[];
  member_artifacts?: TraceableConductMemberArtifact[];
  verify_manifest?: {
    offline_cli: string;
    portal_base: string;
    delegation_chain_schema: string;
    flight_recorder_schema: string;
  };
}



function sortHex64(values: string[]): string[] {
  return [...values]
    .map((v) => String(v || '').trim().toLowerCase())
    .filter((v) => /^[a-f0-9]{64}$/.test(v))
    .sort();
}

export function buildTraceableConductManifestPreimage(
  input: TraceableConductManifestInput & { generated_at: string },
): Record<string, unknown> {
  const material_entry_hashes = sortHex64(input.material_entry_hashes || []);
  const denial_entry_hashes = sortHex64(input.denial_entry_hashes || []);
  const member_artifacts = [...(input.member_artifacts || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      label: String(m.label || '').trim(),
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  return {
    schema: TRACEABLE_CONDUCT_MANIFEST_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    generated_at: input.generated_at,
    delegation_chain_digest: input.delegation_chain_digest
      ? String(input.delegation_chain_digest).trim().toLowerCase()
      : null,
    material_entry_hashes,
    denial_entry_hashes,
    member_artifacts,
    verify_manifest: input.verify_manifest ?? {
      offline_cli: 'npx @aevesa/verify',
      portal_base: 'https://verify.aevesa.com',
      delegation_chain_schema: 'kovera-delegation-chain/1',
      flight_recorder_schema: 'aevesa.flight-recorder-export/v1',
    },
  };
}

export function buildTraceableConductManifestDocument(input: TraceableConductManifestInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildTraceableConductManifestPreimage({ ...input, generated_at });
  const manifest_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    manifest_digest,
  };
}
