import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 12 Track C — hash-only manifest of evidence artifacts for executive attestation scope. */

export const ATTESTED_EVIDENCE_SET_SCHEMA = 'aevesa.attested-evidence-set/v1' as const;

export interface AttestedEvidenceMemberRef {
  member_schema: string;
  member_digest: string;
  label: string;
  verify_ok?: boolean;
  entry_count?: number | null;
}

export interface AttestedEvidenceSetInput {
  organization_id: string;
  period_label: string;
  generated_at?: string;
  scope_label?: string | null;
  members: AttestedEvidenceMemberRef[];
}



export function buildAttestedEvidenceSetPreimage(
  input: AttestedEvidenceSetInput & { generated_at: string },
): Record<string, unknown> {
  const members = [...(input.members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      label: String(m.label || '').trim(),
      verify_ok: m.verify_ok === true,
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  return {
    schema: ATTESTED_EVIDENCE_SET_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    period_label: String(input.period_label || '').trim(),
    generated_at: input.generated_at,
    scope_label: input.scope_label ? String(input.scope_label).trim() : null,
    members,
    member_count: members.length,
  };
}

export function buildAttestedEvidenceSetDocument(input: AttestedEvidenceSetInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildAttestedEvidenceSetPreimage({ ...input, generated_at });
  const evidence_set_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    evidence_set_digest,
  };
}

export default {
  ATTESTED_EVIDENCE_SET_SCHEMA,
  buildAttestedEvidenceSetDocument,
};
