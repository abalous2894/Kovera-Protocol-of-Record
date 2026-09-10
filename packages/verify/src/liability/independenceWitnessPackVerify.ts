import { sha256HexUtf8 } from '../core/sha256.js';
import { INDEPENDENCE_WITNESS_PACK_SCHEMA, buildIndependenceWitnessPackPreimage, deriveIndependenceReadiness } from '../core/independenceWitnessPack.js';
import { stableStringify } from '../core/stableStringify.js';
import type { IndependenceReadiness } from '../core/independenceWitnessPack.js';
import {
  verifyWitnessDiversityBlock,
  type WitnessDiversityVerifyOptions,
} from './witnessDiversityVerify.js';

export const INDEPENDENCE_WITNESS_PACK_SKU = 'aevesa-independence-witness-pack-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface IndependenceWitnessPackDocument {
  schema?: string;
  organization_id?: string;
  session_id?: string;
  generated_at?: string;
  competitor_context_ref?: string | null;
  independence_assertions?: {
    witness_cosign_present?: boolean;
    anchor_coverage_sufficient?: boolean;
    custodian_path_verified?: boolean;
    operator_self_sign_excluded?: boolean;
    third_party_verifiable?: boolean;
    independence_readiness?: IndependenceReadiness;
  };
  composed_members?: Array<{
    member_schema?: string;
    member_digest?: string;
    verify_ok?: boolean;
    label?: string;
    entry_count?: number | null;
  }>;
  independence_verify?: {
    offline_cli?: string;
    portal_base?: string;
    no_operator_login_required?: boolean;
    guardian_schema?: string;
    anchor_coverage_schema?: string;
    bundle_schema?: string;
  };
  pack_digest?: string;
  witness_diversity?: Record<string, unknown> | null;
}

export interface IndependenceWitnessPackVerifyOptions extends WitnessDiversityVerifyOptions {
  requireWitnessDiversity?: boolean;
}

export interface IndependenceWitnessPackVerifyResult {
  schema: typeof INDEPENDENCE_WITNESS_PACK_SCHEMA;
  sku: typeof INDEPENDENCE_WITNESS_PACK_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  independence_readiness: IndependenceReadiness | null;
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
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKeys(v, depth + 1));
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyIndependenceWitnessPack(
  docInput: unknown,
  options: IndependenceWitnessPackVerifyOptions = {},
): IndependenceWitnessPackVerifyResult {
  const doc = asRecord(docInput) as IndependenceWitnessPackDocument | null;
  const schemaValid = doc?.schema === INDEPENDENCE_WITNESS_PACK_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const sessionIdPresent = String(doc?.session_id || '').trim().length > 0;

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const composedMembersPresent = members.length >= 3;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const manifest = doc?.independence_verify || {};
  const independenceManifestPresent =
    String(manifest.offline_cli || '').trim().length > 0 &&
    manifest.no_operator_login_required === true &&
    String(manifest.bundle_schema || '').trim() === INDEPENDENCE_WITNESS_PACK_SCHEMA;

  const assertions = doc?.independence_assertions || {};
  const derivedReadiness = deriveIndependenceReadiness(
    members.map((m) => ({
      member_schema: String(m?.member_schema || ''),
      member_digest: String(m?.member_digest || ''),
      verify_ok: m?.verify_ok === true,
      label: String(m?.label || ''),
      entry_count: m?.entry_count ?? null,
    })),
  );

  const guardianOk = members.some(
    (m) => m?.member_schema === 'aevesa.independent-guardian-bundle/v1' && m?.verify_ok === true,
  );
  const anchorOk = members.some(
    (m) => m?.member_schema === 'aevesa.anchor-coverage-forensic-pack/v1' && m?.verify_ok === true,
  );
  const witnessPathOk = members.some(
    (m) => m?.member_schema === 'aevesa.witness-custody-path/v1' && m?.verify_ok === true,
  );

  let independenceAssertionsConsistent =
    assertions.operator_self_sign_excluded === true &&
    assertions.third_party_verifiable === true;
  if (derivedReadiness === 'independent') {
    independenceAssertionsConsistent =
      independenceAssertionsConsistent &&
      assertions.witness_cosign_present === true &&
      assertions.anchor_coverage_sufficient === true &&
      assertions.custodian_path_verified === true &&
      guardianOk &&
      anchorOk &&
      witnessPathOk;
  } else if (derivedReadiness === 'partial') {
    independenceAssertionsConsistent =
      independenceAssertionsConsistent && (guardianOk || anchorOk);
  }

  const readinessConsistent = assertions.independence_readiness === derivedReadiness;

  let packDigestMatches = false;
  const witnessDiversityBlock = doc?.witness_diversity ?? null;
  if (schemaValid && doc && independenceManifestPresent) {
    const preimage = buildIndependenceWitnessPackPreimage({
      organization_id: String(doc.organization_id),
      session_id: String(doc.session_id),
      generated_at: String(doc.generated_at || ''),
      competitor_context_ref: doc.competitor_context_ref ?? null,
      independence_assertions: {
        witness_cosign_present: assertions.witness_cosign_present === true,
        anchor_coverage_sufficient: assertions.anchor_coverage_sufficient === true,
        custodian_path_verified: assertions.custodian_path_verified === true,
        operator_self_sign_excluded: assertions.operator_self_sign_excluded === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        independence_readiness: String(
          assertions.independence_readiness || derivedReadiness,
        ) as IndependenceReadiness,
      },
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        entry_count: m?.entry_count ?? null,
      })),
      independence_verify: {
        offline_cli: String(manifest.offline_cli || ''),
        portal_base: String(manifest.portal_base || ''),
        no_operator_login_required: manifest.no_operator_login_required === true,
        guardian_schema: String(manifest.guardian_schema || ''),
        anchor_coverage_schema: String(manifest.anchor_coverage_schema || ''),
        bundle_schema: String(manifest.bundle_schema || ''),
      },
      witness_diversity: witnessDiversityBlock as never,
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const requireWitnessDiversity = options.requireWitnessDiversity === true;
  const witnessDiversityPresent = witnessDiversityBlock != null;
  const witnessDiversityVerify = witnessDiversityPresent
    ? verifyWitnessDiversityBlock(witnessDiversityBlock, {
        requireDiversityMet: requireWitnessDiversity,
        minLogs: options.minLogs,
        minOperators: options.minOperators,
      })
    : null;
  const witnessDiversityOk =
    (!requireWitnessDiversity && !witnessDiversityPresent)
    || (witnessDiversityVerify?.ok === true);
  const witnessDiversityMet = witnessDiversityVerify?.diversity_met === true;

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    sessionIdPresent &&
    composedMembersPresent &&
    memberDigestsValid &&
    independenceManifestPresent &&
    independenceAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    readinessConsistent &&
    witnessDiversityOk &&
    (!requireWitnessDiversity || witnessDiversityMet);

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${INDEPENDENCE_WITNESS_PACK_SCHEMA}`;
  else if (!independenceManifestPresent) note = 'independence_verify manifest incomplete';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!independenceAssertionsConsistent) {
    note = 'independence_assertions inconsistent with composed members';
  } else if (!readinessConsistent) note = 'independence_readiness inconsistent with member verify state';
  else if (!witnessDiversityOk) note = witnessDiversityVerify?.note || 'witness_diversity verification failed';

  return {
    schema: INDEPENDENCE_WITNESS_PACK_SCHEMA,
    sku: INDEPENDENCE_WITNESS_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      sessionIdPresent,
      composedMembersPresent,
      memberDigestsValid,
      independenceManifestPresent,
      independenceAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      witnessDiversityPresent,
      witnessDiversityOk,
      witnessDiversityMet,
      profileComplete,
    },
    independence_readiness: derivedReadiness,
    gtmLine:
      'Operator-signed receipts fail independence tests. Aevesa composes witness cosign, five-class anchor coverage, and custodian path — verified offline.',
    note,
  };
}
