import { sha256HexUtf8 } from '../core/sha256.js';
import { VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA, buildVerifiableDenialEvidencePackPreimage, deriveDenialReadiness } from '../core/verifiableDenialEvidencePack.js';
import { stableStringify } from '../core/stableStringify.js';
import type { DenialReadiness, EnforcementPlane } from '../core/verifiableDenialEvidencePack.js';

export const VERIFIABLE_DENIAL_EVIDENCE_PACK_SKU =
  'aevesa-verifiable-denial-evidence-pack-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

const ENFORCEMENT_PLANES = new Set<EnforcementPlane>([
  'ai_agent_gateway',
  'runtime_pep',
  'kill_switch',
  'gateway_attestation',
]);

export interface VerifiableDenialEvidencePackDocument {
  schema?: string;
  organization_id?: string;
  session_id?: string;
  correlation_id?: string | null;
  generated_at?: string;
  enforcement_plane?: EnforcementPlane;
  enforcement_vendor_ref?: string | null;
  denial_assertions?: {
    pre_execution?: boolean;
    execution_occurred?: boolean;
    third_party_verifiable?: boolean;
    completeness_bound?: boolean;
    silence_window_observed?: boolean;
    denial_readiness?: DenialReadiness;
  };
  composed_members?: Array<{
    member_schema?: string;
    member_digest?: string;
    verify_ok?: boolean;
    label?: string;
    entry_count?: number | null;
  }>;
  pack_digest?: string;
}

export interface VerifiableDenialEvidencePackVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  sessionIdPresent: boolean;
  enforcementPlaneValid: boolean;
  composedMembersPresent: boolean;
  memberDigestsValid: boolean;
  denialAssertionsConsistent: boolean;
  packDigestMatches: boolean;
  hashOnlySurface: boolean;
  readinessConsistent: boolean;
  profileComplete: boolean;
}

export interface VerifiableDenialEvidencePackVerifyResult {
  schema: typeof VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA;
  sku: typeof VERIFIABLE_DENIAL_EVIDENCE_PACK_SKU;
  ok: boolean;
  checks: VerifiableDenialEvidencePackVerifyChecks;
  denial_readiness: DenialReadiness | null;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hasForbiddenKeys(value: unknown, depth = 0): boolean {
  if (depth > 8 || value == null) return false;
  if (Array.isArray(value)) {
    return value.some((v) => hasForbiddenKeys(v, depth + 1));
  }
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyVerifiableDenialEvidencePack(
  docInput: unknown,
): VerifiableDenialEvidencePackVerifyResult {
  const doc = asRecord(docInput) as VerifiableDenialEvidencePackDocument | null;
  const schemaValid = doc?.schema === VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA;

  const organization_id = String(doc?.organization_id || '').trim();
  const organizationIdPresent = organization_id.length > 0;

  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const plane = doc?.enforcement_plane;
  const enforcementPlaneValid = ENFORCEMENT_PLANES.has(plane as EnforcementPlane);

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const composedMembersPresent = members.length >= 1;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const derivedReadiness = deriveDenialReadiness(
    members.map((m) => ({
      member_schema: String(m?.member_schema || ''),
      member_digest: String(m?.member_digest || ''),
      verify_ok: m?.verify_ok === true,
      label: String(m?.label || ''),
      entry_count: m?.entry_count ?? null,
    })),
  );

  const assertions = doc?.denial_assertions || {};
  const deniedMemberOk = members.some(
    (m) => m?.member_schema === 'liability-receipt/v1' && m?.verify_ok === true,
  );
  const completenessMemberOk = members.some(
    (m) => m?.member_schema === 'aevesa.set-completeness/v1' && m?.verify_ok === true,
  );

  let denialAssertionsConsistent =
    assertions.pre_execution === true &&
    assertions.execution_occurred !== true &&
    assertions.third_party_verifiable === true;
  if (derivedReadiness === 'complete' || derivedReadiness === 'partial') {
    denialAssertionsConsistent =
      denialAssertionsConsistent &&
      assertions.completeness_bound === true &&
      deniedMemberOk &&
      completenessMemberOk;
  } else {
    denialAssertionsConsistent = denialAssertionsConsistent && deniedMemberOk;
  }

  const readinessConsistent = assertions.denial_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && enforcementPlaneValid) {
    const preimage = buildVerifiableDenialEvidencePackPreimage({
      organization_id,
      session_id,
      correlation_id: doc.correlation_id ?? null,
      generated_at: String(doc.generated_at || ''),
      enforcement_plane: plane as EnforcementPlane,
      enforcement_vendor_ref: doc.enforcement_vendor_ref ?? null,
      denial_assertions: {
        pre_execution: assertions.pre_execution === true,
        execution_occurred: assertions.execution_occurred === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        completeness_bound: assertions.completeness_bound === true,
        silence_window_observed: assertions.silence_window_observed === true,
        denial_readiness: String(assertions.denial_readiness || derivedReadiness) as DenialReadiness,
      },
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        entry_count: m?.entry_count ?? null,
      })),
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    sessionIdPresent &&
    enforcementPlaneValid &&
    composedMembersPresent &&
    memberDigestsValid &&
    denialAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    readinessConsistent;

  const ok = profileComplete;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA}`;
  else if (!enforcementPlaneValid) note = 'enforcement_plane invalid';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!denialAssertionsConsistent) note = 'denial_assertions inconsistent with composed members';
  else if (!readinessConsistent) note = 'denial_readiness inconsistent with member verify state';
  else if (!memberDigestsValid) note = 'composed member_digest must be SHA-256 hex';

  return {
    schema: VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA,
    sku: VERIFIABLE_DENIAL_EVIDENCE_PACK_SKU,
    ok,
    checks: {
      schemaValid,
      organizationIdPresent,
      sessionIdPresent,
      enforcementPlaneValid,
      composedMembersPresent,
      memberDigestsValid,
      denialAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      profileComplete,
    },
    denial_readiness: derivedReadiness,
    gtmLine:
      'The gateway blocked it in their UI. Aevesa proves the block happened before execution — offline, with set-completeness bound.',
    note,
  };
}
