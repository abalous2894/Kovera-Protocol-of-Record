import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  buildAddonVettingProvenancePreimage,
  ADDON_VETTING_PROVENANCE_SCHEMA,
  recomputeVettingAttestationDigestFromDocument,
  evaluateVettingCoverage,
  type ProvenanceReadiness,
} from '../core/addonVettingProvenance.js';
import {
  ADDON_VETTING_VENDOR_IDS,
  ADDON_VETTING_VERDICTS,
} from '../core/addonVettingAdapter.js';
import { verifyToolManifestFingerprint } from './toolManifestFingerprintVerify.js';

export const ADDON_VETTING_PROVENANCE_SKU = 'aevesa-addon-vetting-provenance-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

export interface AddonVettingProvenanceVerifyOptions {
  requireProvenanceReady?: boolean;
}

export interface AddonVettingProvenanceVerifyResult {
  schema: typeof ADDON_VETTING_PROVENANCE_SCHEMA;
  sku: typeof ADDON_VETTING_PROVENANCE_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  provenance_readiness: ProvenanceReadiness | null;
  profileComplete: boolean;
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

export function verifyAddonVettingProvenance(
  docInput: unknown,
  options: AddonVettingProvenanceVerifyOptions = {},
): AddonVettingProvenanceVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === ADDON_VETTING_PROVENANCE_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const sessionIdPresent = String(doc?.session_id || '').trim().length > 0;
  const vendorValid = ADDON_VETTING_VENDOR_IDS.includes(
    String(doc?.vetting_vendor_id || '') as (typeof ADDON_VETTING_VENDOR_IDS)[number],
  );
  const verdictValid = ADDON_VETTING_VERDICTS.includes(
    String(doc?.vetting_verdict || '') as (typeof ADDON_VETTING_VERDICTS)[number],
  );
  const vendorVettingIdPresent = String(doc?.vendor_vetting_id || '').trim().length > 0;
  const manifestVersionPresent = String(doc?.manifest_version_id || '').trim().length > 0;
  const vettingEvaluatedAtPresent = String(doc?.vetting_evaluated_at || '').trim().length > 0;
  const actionExecutedAtPresent = String(doc?.action_executed_at || '').trim().length > 0;
  const generatedAtPresent = String(doc?.generated_at || '').trim().length > 0;

  const vettingAttestationDigestValid = HEX64.test(
    String(doc?.vetting_attestation_digest || '').toLowerCase(),
  );
  const manifestFingerprintDigestValid = HEX64.test(
    String(doc?.manifest_fingerprint_digest || '').toLowerCase(),
  );
  const addonIdDigestValid = HEX64.test(String(doc?.addon_id_digest || '').toLowerCase());
  const bindDigestValid = HEX64.test(String(doc?.bind_digest || '').toLowerCase());

  const liabilityReceiptDigestRaw = doc?.liability_receipt_digest;
  const liabilityReceiptDigestValid =
    liabilityReceiptDigestRaw == null
    || HEX64.test(String(liabilityReceiptDigestRaw).toLowerCase());

  const hashOnlySurface = doc != null && !hasForbiddenKeys(doc);

  const recomputedAttestationDigest = doc
    ? recomputeVettingAttestationDigestFromDocument({
        vetting_vendor_id: String(doc.vetting_vendor_id) as never,
        vendor_vetting_id: String(doc.vendor_vetting_id),
        vetting_verdict: String(doc.vetting_verdict) as never,
        vetting_evaluated_at: String(doc.vetting_evaluated_at),
        manifest_fingerprint_digest: String(doc.manifest_fingerprint_digest),
        manifest_version_id: String(doc.manifest_version_id),
        addon_id_digest: String(doc.addon_id_digest),
        policy_digest:
          doc.policy_digest != null ? String(doc.policy_digest) : null,
        re_vet_cadence_days:
          doc.re_vet_cadence_days != null ? Number(doc.re_vet_cadence_days) : null,
      })
    : '';

  const vettingAttestationDigestMatches =
    vettingAttestationDigestValid
    && recomputedAttestationDigest === String(doc?.vetting_attestation_digest || '').toLowerCase();

  const manifestMember = asRecord(doc?.tool_manifest_fingerprint);
  let manifestMemberVerifyOk = true;
  let manifestMemberMatches = true;
  if (manifestMember != null) {
    manifestMemberVerifyOk = verifyToolManifestFingerprint(manifestMember).ok === true;
    const memberDigest = String(manifestMember.manifest_fingerprint || '').toLowerCase();
    manifestMemberMatches =
      !HEX64.test(memberDigest)
      || memberDigest === String(doc?.manifest_fingerprint_digest || '').toLowerCase();
  }

  const binding = asRecord(doc?.provenance_session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingManifestValid = HEX64.test(
    String(binding.manifest_fingerprint_digest || '').toLowerCase(),
  );
  const bindingAttestationValid = HEX64.test(
    String(binding.vetting_attestation_digest || '').toLowerCase(),
  );
  const bindingActionAtPresent = String(binding.action_executed_at || '').trim().length > 0;

  const bindingMatchesFields =
    bindingManifestValid
    && bindingAttestationValid
    && bindingActionAtPresent
    && String(binding.session_id || '').trim() === String(doc?.session_id || '').trim()
    && String(binding.manifest_fingerprint_digest || '').toLowerCase()
      === String(doc?.manifest_fingerprint_digest || '').toLowerCase()
    && String(binding.vetting_attestation_digest || '').toLowerCase()
      === String(doc?.vetting_attestation_digest || '').toLowerCase()
    && String(binding.action_executed_at || '') === String(doc?.action_executed_at || '');

  const assertions = asRecord(doc?.provenance_assertions) || {};
  const derivedReadiness = String(
    assertions.provenance_readiness || '',
  ) as ProvenanceReadiness;

  const cadenceDays =
    doc?.re_vet_cadence_days != null ? Number(doc.re_vet_cadence_days) : 7;
  const computedCoverage = doc
    ? evaluateVettingCoverage(
        String(doc.vetting_verdict) as never,
        String(doc.vetting_evaluated_at),
        String(doc.action_executed_at),
        cadenceDays,
      )
    : { vetting_covers_execution: false, re_vet_cadence_met: false };

  let provenanceAssertionsConsistent =
    assertions.third_party_verifiable === true && sessionIdPresent;

  if (derivedReadiness === 'provenance_ready') {
    provenanceAssertionsConsistent =
      provenanceAssertionsConsistent
      && assertions.vetting_covers_execution === true
      && assertions.re_vet_cadence_met === true
      && computedCoverage.vetting_covers_execution
      && computedCoverage.re_vet_cadence_met
      && String(doc?.vetting_verdict) === 'APPROVED'
      && normalizationBound
      && manifestMemberMatches;
  } else if (derivedReadiness === 'stale') {
    provenanceAssertionsConsistent =
      provenanceAssertionsConsistent
      && (!computedCoverage.re_vet_cadence_met || !computedCoverage.vetting_covers_execution);
  } else if (derivedReadiness === 'partial') {
    provenanceAssertionsConsistent =
      provenanceAssertionsConsistent && normalizationBound;
  }

  const readinessConsistent = assertions.provenance_readiness === derivedReadiness;

  let bindDigestMatches = false;
  if (schemaValid && doc && bindingManifestValid) {
    const preimage = buildAddonVettingProvenancePreimage({
      organization_id: String(doc.organization_id),
      session_id: String(doc.session_id),
      generated_at: String(doc.generated_at || ''),
      vetting_vendor_id: String(doc.vetting_vendor_id) as never,
      vendor_vetting_id: String(doc.vendor_vetting_id),
      vetting_verdict: String(doc.vetting_verdict) as never,
      vetting_attestation_digest: String(doc.vetting_attestation_digest),
      manifest_fingerprint_digest: String(doc.manifest_fingerprint_digest),
      manifest_version_id: String(doc.manifest_version_id),
      addon_id_digest: String(doc.addon_id_digest),
      vetting_evaluated_at: String(doc.vetting_evaluated_at),
      action_executed_at: String(doc.action_executed_at),
      re_vet_cadence_days: cadenceDays,
      policy_digest: doc.policy_digest != null ? String(doc.policy_digest) : null,
      liability_receipt_digest:
        liabilityReceiptDigestRaw != null ? String(liabilityReceiptDigestRaw) : null,
      provenance_session_binding: {
        session_id: String(binding.session_id || ''),
        manifest_fingerprint_digest: String(binding.manifest_fingerprint_digest || ''),
        vetting_attestation_digest: String(binding.vetting_attestation_digest || ''),
        action_executed_at: String(binding.action_executed_at || ''),
        normalization_bound: normalizationBound,
      },
      provenance_assertions: {
        third_party_verifiable: assertions.third_party_verifiable === true,
        vetting_covers_execution: assertions.vetting_covers_execution === true,
        re_vet_cadence_met: assertions.re_vet_cadence_met === true,
        provenance_readiness: derivedReadiness,
      },
    });
    bindDigestMatches =
      sha256HexUtf8(stableStringify(preimage)) === String(doc.bind_digest || '').toLowerCase();
  }

  const requireReady = options.requireProvenanceReady === true;
  const profileComplete =
    schemaValid
    && organizationIdPresent
    && sessionIdPresent
    && vendorValid
    && verdictValid
    && vendorVettingIdPresent
    && manifestVersionPresent
    && vettingEvaluatedAtPresent
    && actionExecutedAtPresent
    && generatedAtPresent
    && vettingAttestationDigestMatches
    && manifestFingerprintDigestValid
    && addonIdDigestValid
    && bindDigestMatches
    && bindingMatchesFields
    && normalizationBound
    && hashOnlySurface
    && liabilityReceiptDigestValid
    && provenanceAssertionsConsistent
    && readinessConsistent
    && manifestMemberMatches
    && (!manifestMember || manifestMemberVerifyOk)
    && derivedReadiness === 'provenance_ready'
    && (!requireReady || derivedReadiness === 'provenance_ready');

  const ok = profileComplete;

  let note: string | null = null;
  if (!vettingAttestationDigestMatches) {
    note = 'vetting_attestation_digest does not match canonical envelope';
  } else if (!bindDigestMatches) {
    note = 'bind_digest does not match preimage';
  } else if (!computedCoverage.re_vet_cadence_met) {
    note = 'action executed outside re-vet cadence window';
  } else if (!computedCoverage.vetting_covers_execution) {
    note = 'vetting verdict does not cover execution window';
  } else if (!bindingMatchesFields) {
    note = 'provenance_session_binding inconsistent with document fields';
  } else if (!manifestMemberMatches) {
    note = 'embedded tool_manifest_fingerprint does not match manifest_fingerprint_digest';
  } else if (!provenanceAssertionsConsistent) {
    note = 'provenance_assertions inconsistent with derived checks';
  }

  return {
    schema: ADDON_VETTING_PROVENANCE_SCHEMA,
    sku: ADDON_VETTING_PROVENANCE_SKU,
    ok,
    checks: {
      schemaValid: schemaValid === true,
      organizationIdPresent: organizationIdPresent === true,
      sessionIdPresent: sessionIdPresent === true,
      vendorValid: vendorValid === true,
      verdictValid: verdictValid === true,
      vettingAttestationDigestMatches: vettingAttestationDigestMatches === true,
      manifestFingerprintDigestValid: manifestFingerprintDigestValid === true,
      bindingMatchesFields: bindingMatchesFields === true,
      normalizationBound: normalizationBound === true,
      bindDigestMatches: bindDigestMatches === true,
      hashOnlySurface: hashOnlySurface === true,
      manifestMemberMatches: manifestMemberMatches === true,
      manifestMemberVerifyOk: !manifestMember || manifestMemberVerifyOk === true,
      provenanceAssertionsConsistent: provenanceAssertionsConsistent === true,
      readinessConsistent: readinessConsistent === true,
      profileComplete: profileComplete === true,
    },
    provenance_readiness: derivedReadiness || null,
    profileComplete,
    gtmLine:
      "Re-verification tells you today's skill is safe. This receipt proves which verification covered the action that went wrong.",
    note,
  };
}

export default { verifyAddonVettingProvenance, ADDON_VETTING_PROVENANCE_SKU };
