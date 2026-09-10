import { sha256HexUtf8 } from '../core/sha256.js';
import { ATTESTED_EVIDENCE_SET_SCHEMA, buildAttestedEvidenceSetPreimage } from '../core/attestedEvidenceSet.js';
import { stableStringify } from '../core/stableStringify.js';

export const ATTESTED_EVIDENCE_SET_SKU = 'aevesa-attested-evidence-set-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface AttestedEvidenceSetVerifyResult {
  schema: typeof ATTESTED_EVIDENCE_SET_SCHEMA;
  sku: typeof ATTESTED_EVIDENCE_SET_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hasForbiddenKeys(value: unknown, depth = 0): boolean {
  if (depth > 8 || value == null) return false;
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKeys(v, depth + 1));
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyAttestedEvidenceSet(docInput: unknown): AttestedEvidenceSetVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === ATTESTED_EVIDENCE_SET_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const periodLabelPresent = String(doc?.period_label || '').trim().length > 0;

  const members = Array.isArray(doc?.members) ? doc.members : [];
  const membersPresent = members.length >= 1;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const memberCountConsistent = Number(doc?.member_count) === members.length;

  let evidenceSetDigestMatches = false;
  if (schemaValid && doc && membersPresent && memberDigestsValid) {
    const preimage = buildAttestedEvidenceSetPreimage({
      organization_id: String(doc.organization_id),
      period_label: String(doc.period_label),
      generated_at: String(doc.generated_at || ''),
      scope_label: doc.scope_label != null ? String(doc.scope_label) : null,
      members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        label: String(m?.label || ''),
        verify_ok: m?.verify_ok === true,
        entry_count: m?.entry_count ?? null,
      })),
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    evidenceSetDigestMatches =
      String(doc.evidence_set_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    periodLabelPresent &&
    membersPresent &&
    memberDigestsValid &&
    memberCountConsistent &&
    evidenceSetDigestMatches &&
    hashOnlySurface;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${ATTESTED_EVIDENCE_SET_SCHEMA}`;
  else if (!evidenceSetDigestMatches) note = 'evidence_set_digest does not match canonical preimage';
  else if (!memberCountConsistent) note = 'member_count inconsistent with members array';

  return {
    schema: ATTESTED_EVIDENCE_SET_SCHEMA,
    sku: ATTESTED_EVIDENCE_SET_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      periodLabelPresent,
      membersPresent,
      memberDigestsValid,
      memberCountConsistent,
      evidenceSetDigestMatches,
      hashOnlySurface,
      profileComplete,
    },
    note,
  };
}
