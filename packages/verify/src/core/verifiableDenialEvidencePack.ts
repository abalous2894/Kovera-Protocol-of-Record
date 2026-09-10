import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 11 Track A — third-party-verifiable denial evidence for enforcement vendors. */

export const VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA =
  'aevesa.verifiable-denial-evidence-pack/v1' as const;

export type DenialReadiness = 'complete' | 'partial' | 'denial_only';

export type EnforcementPlane =
  | 'ai_agent_gateway'
  | 'runtime_pep'
  | 'kill_switch'
  | 'gateway_attestation';

export interface ComposedDenialMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  entry_count?: number | null;
}

export interface DenialAssertionsInput {
  pre_execution: boolean;
  execution_occurred: boolean;
  third_party_verifiable: boolean;
  completeness_bound: boolean;
  silence_window_observed?: boolean;
}

export interface VerifiableDenialEvidencePackInput {
  organization_id: string;
  session_id: string;
  correlation_id?: string | null;
  generated_at?: string;
  enforcement_plane: EnforcementPlane;
  enforcement_vendor_ref?: string | null;
  denial_assertions: DenialAssertionsInput;
  composed_members: ComposedDenialMemberRef[];
  disclaimer?: string;
}



export function deriveDenialReadiness(members: ComposedDenialMemberRef[]): DenialReadiness {
  const denied = (members || []).find(
    (m) => m.member_schema === 'liability-receipt/v1' && m.verify_ok === true,
  );
  const completeness = (members || []).find(
    (m) => m.member_schema === 'aevesa.set-completeness/v1' && m.verify_ok === true,
  );
  const silence = (members || []).find(
    (m) => m.member_schema === 'aevesa.shutdown-drill-bundle/v1' && m.verify_ok === true,
  );
  if (denied && completeness && silence) return 'complete';
  if (denied && completeness) return 'partial';
  if (denied) return 'denial_only';
  return 'denial_only';
}

export function buildDenialAssertionsBlock(input: DenialAssertionsInput, members: ComposedDenialMemberRef[]) {
  const readiness = deriveDenialReadiness(members);
  const hasCompleteness = (members || []).some(
    (m) => m.member_schema === 'aevesa.set-completeness/v1' && m.verify_ok === true,
  );
  const hasSilence = (members || []).some(
    (m) => m.member_schema === 'aevesa.shutdown-drill-bundle/v1' && m.verify_ok === true,
  );
  return {
    pre_execution: input.pre_execution === true,
    execution_occurred: input.execution_occurred === true,
    third_party_verifiable: input.third_party_verifiable === true,
    completeness_bound: hasCompleteness || input.completeness_bound === true,
    silence_window_observed: hasSilence || input.silence_window_observed === true,
    denial_readiness: readiness,
  };
}

export function buildVerifiableDenialEvidencePackPreimage(
  input: Omit<VerifiableDenialEvidencePackInput, 'disclaimer'> & {
    generated_at: string;
    denial_assertions: ReturnType<typeof buildDenialAssertionsBlock>;
    composed_members: ComposedDenialMemberRef[];
  },
): Record<string, unknown> {
  const members = [...(input.composed_members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  return {
    schema: VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    correlation_id: input.correlation_id ? String(input.correlation_id).trim() : null,
    generated_at: input.generated_at,
    enforcement_plane: input.enforcement_plane,
    enforcement_vendor_ref: input.enforcement_vendor_ref
      ? String(input.enforcement_vendor_ref).trim()
      : null,
    denial_assertions: input.denial_assertions,
    composed_members: members,
  };
}

export function buildVerifiableDenialEvidencePackDocument(input: VerifiableDenialEvidencePackInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const denial_assertions = buildDenialAssertionsBlock(input.denial_assertions, input.composed_members);
  const preimage = buildVerifiableDenialEvidencePackPreimage({
    ...input,
    generated_at,
    denial_assertions,
    composed_members: input.composed_members,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    pack_digest,
    disclaimer:
      input.disclaimer ||
      'Evidence export only — Aevesa does not adjudicate disputes or certify enforcement vendor behavior.',
  };
}

export default {
  VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA,
  deriveDenialReadiness,
  buildDenialAssertionsBlock,
  buildVerifiableDenialEvidencePackDocument,
  buildVerifiableDenialEvidencePackPreimage,
};
