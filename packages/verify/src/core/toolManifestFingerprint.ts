import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 9 Track R — MCP manifest session bind on material-action liability receipts (ASI04). */

export const TOOL_MANIFEST_FINGERPRINT_SCHEMA = 'aevesa.tool-manifest-fingerprint/v1' as const;

export const TOOL_MANIFEST_FINGERPRINT_SKU = 'aevesa-tool-manifest-fingerprint-v1' as const;

export const ATTEST_MCP_MANIFEST_PROFILE = 'attestmcp/tool-manifest/v1' as const;

export const TOOL_MANIFEST_ABSENT_REASONS = [
  'attest_mcp_disabled',
  'no_mcp_server',
  'manifest_unpinned',
  'non_material_action',
  'provider_unavailable',
] as const;

export type ToolManifestAbsentReason = (typeof TOOL_MANIFEST_ABSENT_REASONS)[number];

export interface ToolManifestFingerprintInput {
  present: boolean;
  manifest_fingerprint?: string | null;
  tool_composite_hash?: string | null;
  mcp_server_id?: string | null;
  tool_name?: string | null;
  manifest_version?: number | null;
  attest_profile?: string | null;
  external_attestation_ref?: string | null;
  captured_at?: string | null;
  session_id?: string | null;
  provider_id?: string | null;
  absent_reason?: ToolManifestAbsentReason | string | null;
}



export function buildToolManifestFingerprintPreimage(
  input: ToolManifestFingerprintInput,
): Record<string, unknown> {
  const provider_id = String(input.provider_id || 'aevesa.attestmcp').trim() || 'aevesa.attestmcp';

  if (input.present === true) {
    return {
      schema: TOOL_MANIFEST_FINGERPRINT_SCHEMA,
      present: true,
      manifest_fingerprint: String(input.manifest_fingerprint || '')
        .trim()
        .toLowerCase(),
      tool_composite_hash: String(input.tool_composite_hash || '')
        .trim()
        .toLowerCase(),
      mcp_server_id: input.mcp_server_id ?? null,
      tool_name: input.tool_name ?? null,
      manifest_version: input.manifest_version ?? 1,
      attest_profile: input.attest_profile ?? ATTEST_MCP_MANIFEST_PROFILE,
      external_attestation_ref: input.external_attestation_ref ?? null,
      captured_at: input.captured_at ?? null,
      session_id: input.session_id ?? null,
      provider_id,
    };
  }

  return {
    schema: TOOL_MANIFEST_FINGERPRINT_SCHEMA,
    present: false,
    absent_reason: input.absent_reason ?? 'manifest_unpinned',
    mcp_server_id: input.mcp_server_id ?? null,
    tool_name: input.tool_name ?? null,
    session_id: input.session_id ?? null,
    provider_id,
  };
}

export function buildToolManifestFingerprintDocument(input: ToolManifestFingerprintInput) {
  const preimage = buildToolManifestFingerprintPreimage(input);
  const bind_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    bind_digest,
  };
}
