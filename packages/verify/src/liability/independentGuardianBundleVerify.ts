import { sha256HexUtf8 } from '../core/sha256.js';
import { INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA, INDEPENDENT_GUARDIAN_BUNDLE_MODES, buildIndependentGuardianBundlePreimage, type IndependentGuardianBundleMode, type IndependentGuardianMember } from '../core/independentGuardianBundle.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  verifyEvidenceCustodianBundle,
  type EvidenceCustodianVerifyResult,
} from './evidenceCustodianVerify.js';
import {
  verifyWitnessDiversityBlock,
  type WitnessDiversityVerifyOptions,
} from './witnessDiversityVerify.js';
import { verifyTransparencyLogMonitorAttestation } from './transparencyLogMonitorAttestationVerify.js';
import {
  verifyProveBundle,
  type ProveBundleVerifyOptions,
  type ProveBundleVerifyResult,
} from './proveBundleVerify.js';
import {
  isDeniedReceiptProfile,
  validateDeniedReceiptProfile,
} from './deniedReceiptProfile.js';

export const INDEPENDENT_GUARDIAN_BUNDLE_SKU = 'aevesa-independent-guardian-bundle-v1' as const;

export interface IndependentGuardianMemberVerifyContext extends ProveBundleVerifyOptions {
  member_id?: string;
}

export interface IndependentGuardianMemberVerifyResult {
  member_id: string;
  entry_hash: string;
  receipt_profile: string;
  ok: boolean;
  custodian: EvidenceCustodianVerifyResult | null;
  proveBundle: ProveBundleVerifyResult | null;
  deniedProfileOk: boolean;
  note: string | null;
}

export interface IndependentGuardianVerifyOptions {
  /** Per-member prove/custodian context keyed by member_id or entry_hash */
  memberContexts?: Record<string, IndependentGuardianMemberVerifyContext>;
  /** When true (default), custodian members require witness cosign */
  requireCustodianWitness?: boolean;
  /** When true (default for dual_profile), require valid DENIED + custodian members */
  requireDualProfile?: boolean;
  /** When true, require witness_diversity block with diversity_met */
  requireWitnessDiversity?: boolean;
  minWitnessLogs?: number;
  minWitnessOperators?: number;
  /** When true, require transparency_log_monitor_attestation with healthy state */
  requireMonitorAttestation?: boolean;
  /** Entry digests for offline monitor attestation consistency proof verify */
  monitorAttestationEntryDigests?: string[];
}

export interface IndependentGuardianVerifyChecks {
  schemaValid: boolean;
  bundleModeValid: boolean;
  organizationIdPresent: boolean;
  membersPresent: boolean;
  bundleDigestMatches: boolean;
  memberEntryHashesValid: boolean;
  deniedMemberValid: boolean;
  custodianMemberValid: boolean;
  dualProfileSatisfied: boolean;
  witnessDiversityPresent: boolean;
  witnessDiversityOk: boolean;
  witnessDiversityMet: boolean;
  monitorAttestationPresent: boolean;
  monitorAttestationOk: boolean;
  profileComplete: boolean;
}

export interface IndependentGuardianVerifyResult {
  schema: typeof INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA;
  sku: typeof INDEPENDENT_GUARDIAN_BUNDLE_SKU;
  ok: boolean;
  bundle_mode: IndependentGuardianBundleMode | null;
  checks: IndependentGuardianVerifyChecks;
  members: IndependentGuardianMemberVerifyResult[];
  gtmLine: string;
  note: string | null;
}

function isHex64(value: unknown): boolean {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function resolveMemberContext(
  member: IndependentGuardianMember,
  contexts: Record<string, IndependentGuardianMemberVerifyContext> | undefined,
): IndependentGuardianMemberVerifyContext {
  if (!contexts) return {};
  return (
    contexts[member.member_id] ||
    contexts[member.entry_hash] ||
    contexts[String(member.entry_hash).toLowerCase()] ||
    {}
  );
}

function verifyMember(
  member: IndependentGuardianMember,
  options: {
    requireCustodianWitness: boolean;
    context: IndependentGuardianMemberVerifyContext;
  },
): IndependentGuardianMemberVerifyResult {
  const receipt = member.receipt;
  const base: IndependentGuardianMemberVerifyResult = {
    member_id: member.member_id,
    entry_hash: member.entry_hash,
    receipt_profile: member.receipt_profile,
    ok: false,
    custodian: null,
    proveBundle: null,
    deniedProfileOk: false,
    note: null,
  };

  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return { ...base, note: 'member.receipt missing or invalid' };
  }

  const proveOpts: ProveBundleVerifyOptions = {
    ...options.context,
    entryHash: options.context.entryHash || member.entry_hash,
  };

  const useDeniedPath =
    member.receipt_profile === 'DENIED'
      ? true
      : member.receipt_profile === 'PERMITTED'
        ? false
        : isDeniedReceiptProfile(receipt);

  if (useDeniedPath) {
    const deniedProfile = validateDeniedReceiptProfile(receipt);
    const proveBundle = verifyProveBundle(receipt, {
      ...proveOpts,
      requireWitnessCosign: false,
      requireScittRefusalWitness: proveOpts.requireScittRefusalWitness ?? false,
    });
    const deniedProfileOk = deniedProfile.ok === true;
    const ok = deniedProfileOk && proveBundle.ok;
    return {
      ...base,
      ok,
      proveBundle,
      deniedProfileOk,
      note: ok
        ? 'DENIED member verified — pre-execution refusal profile + receipt crypto'
        : deniedProfileOk
          ? proveBundle.note
          : deniedProfile.errors?.join('; ') || 'DENIED profile invalid',
    };
  }

  const custodian = verifyEvidenceCustodianBundle(receipt, {
    ...proveOpts,
    requireCustodianWitness: options.requireCustodianWitness,
  });
  const ok = custodian.ok;
  return {
    ...base,
    ok,
    custodian,
    proveBundle: custodian.proveBundle,
    deniedProfileOk: false,
    note: ok ? custodian.note : custodian.note,
  };
}

/**
 * Independent Guardian bundle — composes evidence custodian (PERMITTED) and DENIED refusal
 * receipts into one offline-verifiable diligence profile (Wave 8 Track F).
 */
export function verifyIndependentGuardianBundle(
  input: unknown,
  options: IndependentGuardianVerifyOptions = {},
): IndependentGuardianVerifyResult {
  const doc =
    input != null && typeof input === 'object' && !Array.isArray(input)
      ? (input as Record<string, unknown>)
      : null;

  const schemaValid = doc?.schema === INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA;
  const bundleMode = doc?.bundle_mode as IndependentGuardianBundleMode | undefined;
  const bundleModeValid =
    typeof bundleMode === 'string' &&
    (INDEPENDENT_GUARDIAN_BUNDLE_MODES as readonly string[]).includes(bundleMode);
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const membersRaw = Array.isArray(doc?.members) ? (doc!.members as IndependentGuardianMember[]) : [];
  const membersPresent = membersRaw.length > 0;

  let bundleDigestMatches = false;
  if (
    schemaValid &&
    bundleModeValid &&
    organizationIdPresent &&
    doc?.bundle_id &&
    doc?.exported_at &&
    doc?.verify_manifest
  ) {
    const manifest = doc.verify_manifest as {
      offline_cli?: string;
      portal_base?: string;
      receipt_schema?: string;
      custodian_verify_schema?: string;
      bundle_schema?: string;
    };
    const expected = sha256HexUtf8(
      stableStringify(
        buildIndependentGuardianBundlePreimage({
          bundle_id: String(doc.bundle_id),
          organization_id: String(doc.organization_id),
          bundle_mode: bundleMode!,
          members: membersRaw.map((m) => ({
            member_id: String(m.member_id || ''),
            entry_hash: String(m.entry_hash || ''),
            receipt_profile: m.receipt_profile,
            receipt: m.receipt ?? null,
          })),
          verify_manifest: {
            offline_cli: String(manifest.offline_cli || ''),
            portal_base: String(manifest.portal_base || ''),
            receipt_schema: String(manifest.receipt_schema || 'liability-receipt/v1'),
            custodian_verify_schema: String(
              manifest.custodian_verify_schema || 'aevesa.evidence-custodian-verify/v1',
            ),
            bundle_schema: INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA,
          },
          exported_at: String(doc.exported_at),
          non_goals: Array.isArray(doc.non_goals) ? (doc.non_goals as string[]) : [],
          witness_diversity: (doc.witness_diversity as never) ?? undefined,
          transparency_log_monitor_attestation:
            (doc.transparency_log_monitor_attestation as never) ?? undefined,
        }),
      ),
    );
    bundleDigestMatches = Boolean(doc.bundle_digest) && doc.bundle_digest === expected;
  }

  const memberEntryHashesValid =
    membersPresent && membersRaw.every((m) => isHex64(m.entry_hash) && String(m.member_id || '').trim());

  const requireCustodianWitness = options.requireCustodianWitness !== false;
  const memberResults = membersRaw.map((member) =>
    verifyMember(member, {
      requireCustodianWitness,
      context: resolveMemberContext(member, options.memberContexts),
    }),
  );

  const deniedMemberValid = memberResults.some(
    (m) => m.receipt_profile === 'DENIED' && m.ok && m.deniedProfileOk,
  );
  const custodianMemberValid = memberResults.some(
    (m) => m.receipt_profile === 'PERMITTED' && m.ok && m.custodian?.ok === true,
  );

  const requireDual =
    options.requireDualProfile ??
    (bundleMode === 'dual_profile' || (!bundleModeValid && options.requireDualProfile !== false));

  let dualProfileSatisfied = true;
  if (bundleMode === 'dual_profile' || (requireDual && bundleModeValid)) {
    dualProfileSatisfied = deniedMemberValid && custodianMemberValid;
  } else if (bundleMode === 'custodian_only') {
    dualProfileSatisfied = custodianMemberValid;
  } else if (bundleMode === 'denied_only') {
    dualProfileSatisfied = deniedMemberValid;
  }

  const profileCompleteMembers =
    schemaValid &&
    bundleModeValid &&
    organizationIdPresent &&
    membersPresent &&
    bundleDigestMatches &&
    memberEntryHashesValid &&
    dualProfileSatisfied &&
    memberResults.every((m) => m.ok);

  const requireWitnessDiversity = options.requireWitnessDiversity === true;
  const witnessDiversityBlock = doc?.witness_diversity ?? null;
  const witnessDiversityPresent = witnessDiversityBlock != null;
  const witnessDiversityVerify = witnessDiversityPresent
    ? verifyWitnessDiversityBlock(witnessDiversityBlock, {
        requireDiversityMet: requireWitnessDiversity,
        minLogs: options.minWitnessLogs,
        minOperators: options.minWitnessOperators,
      })
    : null;
  const witnessDiversityOk =
    (!requireWitnessDiversity && !witnessDiversityPresent)
    || witnessDiversityVerify?.ok === true;
  const witnessDiversityMet = witnessDiversityVerify?.diversity_met === true;

  const requireMonitorAttestation = options.requireMonitorAttestation === true;
  const monitorAttestationBlock = doc?.transparency_log_monitor_attestation ?? null;
  const monitorAttestationPresent = monitorAttestationBlock != null;
  const monitorAttestationVerify = monitorAttestationPresent
    ? verifyTransparencyLogMonitorAttestation(monitorAttestationBlock, {
        entryDigests: options.monitorAttestationEntryDigests,
        requireHealthyState: requireMonitorAttestation,
      })
    : null;
  const monitorAttestationOk =
    (!requireMonitorAttestation && !monitorAttestationPresent)
    || monitorAttestationVerify?.ok === true;

  const profileComplete =
    profileCompleteMembers
    && witnessDiversityOk
    && (!requireWitnessDiversity || witnessDiversityMet)
    && monitorAttestationOk
    && (!requireMonitorAttestation || monitorAttestationPresent);

  let note: string | null = null;
  if (profileComplete) {
    note =
      'Independent Guardian bundle verified — custodian witness + verifiable denial composed offline';
  } else if (!bundleDigestMatches) {
    note = 'bundle_digest does not match bundle preimage';
  } else if (!dualProfileSatisfied && bundleMode === 'dual_profile') {
    note = 'dual_profile requires at least one valid PERMITTED custodian and one valid DENIED member';
  } else if (!memberEntryHashesValid) {
    note = 'each member requires member_id and 64-char entry_hash';
  } else if (memberResults.some((m) => !m.ok)) {
    note = memberResults.find((m) => !m.ok)?.note || 'one or more members failed verification';
  } else if (!witnessDiversityOk) {
    note = witnessDiversityVerify?.note || 'witness_diversity verification failed';
  } else if (!monitorAttestationOk) {
    note = monitorAttestationVerify?.note || 'transparency_log_monitor_attestation verification failed';
  } else {
    note = 'Independent Guardian bundle verification failed';
  }

  return {
    schema: INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA,
    sku: INDEPENDENT_GUARDIAN_BUNDLE_SKU,
    ok: profileComplete,
    bundle_mode: bundleModeValid ? bundleMode! : null,
    checks: {
      schemaValid,
      bundleModeValid,
      organizationIdPresent,
      membersPresent,
      bundleDigestMatches,
      memberEntryHashesValid,
      deniedMemberValid,
      custodianMemberValid,
      dualProfileSatisfied,
      witnessDiversityPresent,
      witnessDiversityOk,
      witnessDiversityMet,
      monitorAttestationPresent,
      monitorAttestationOk,
      profileComplete,
    },
    members: memberResults,
    gtmLine:
      'Platforms log decisions. Aevesa cosigns permits and refusals — auditors verify without the guardian admin plane.',
    note,
  };
}
