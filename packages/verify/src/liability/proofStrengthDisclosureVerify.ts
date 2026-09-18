import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  CAPTURE_TIMINGS,
  ENFORCEMENT_MODES,
  EXTERNAL_TRANSPARENCY_LEVELS,
  PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
  PROOF_STRENGTH_DISCLOSURE_SCHEMA,
  PROOF_STRENGTH_DISCLOSURE_SKU,
  STANDARD_PROOF_LIMITATIONS,
  WITNESS_MODES,
  WITNESS_PERSISTENCE_LEVELS,
  buildProofStrengthDisclosurePreimage,
  type ProofStrengthDisclosureDocument,
} from '../core/proofStrengthDisclosure.js';

export type { ProofStrengthDisclosureDocument };

export interface ProofStrengthDisclosureVerifyResult {
  schema: typeof PROOF_STRENGTH_DISCLOSURE_SCHEMA;
  sku: typeof PROOF_STRENGTH_DISCLOSURE_SKU;
  ok: boolean;
  checks: {
    schemaValid: boolean;
    enforcementModeValid: boolean;
    captureTimingValid: boolean;
    witnessModeValid: boolean;
    witnessPersistenceValid: boolean;
    externalTransparencyValid: boolean;
    limitationsPresent: boolean;
    disclosureDigestMatches: boolean;
    enforcedPepInvariantAligned: boolean;
    auditOnlyPepInvariantAligned: boolean;
    witnessPersistenceAligned: boolean;
    profileComplete: boolean;
  };
  gtmLine: string;
  note: string | null;
}

function includesEnum<T extends readonly string[]>(values: T, value: unknown): value is T[number] {
  return typeof value === 'string' && (values as readonly string[]).includes(value);
}

export function verifyProofStrengthDisclosure(input: unknown): ProofStrengthDisclosureVerifyResult {
  const doc = input != null && typeof input === 'object' && !Array.isArray(input)
    ? (input as ProofStrengthDisclosureDocument)
    : null;

  const schemaValid = doc?.schema === PROOF_STRENGTH_DISCLOSURE_SCHEMA;
  const enforcementModeValid = includesEnum(ENFORCEMENT_MODES, doc?.enforcement_mode);
  const captureTimingValid = includesEnum(CAPTURE_TIMINGS, doc?.capture_timing);
  const witnessModeValid = includesEnum(WITNESS_MODES, doc?.witness_mode);
  const witnessPersistenceValid = includesEnum(WITNESS_PERSISTENCE_LEVELS, doc?.witness_persistence);
  const externalTransparencyValid = includesEnum(EXTERNAL_TRANSPARENCY_LEVELS, doc?.external_transparency);

  const limitationsPresent =
    Array.isArray(doc?.limitations)
    && doc!.limitations.length > 0
    && doc!.limitations.every((item) => typeof item === 'string' && item.trim().length > 0);

  let disclosureDigestMatches = false;
  if (
    schemaValid
    && enforcementModeValid
    && captureTimingValid
    && witnessModeValid
    && witnessPersistenceValid
    && externalTransparencyValid
    && limitationsPresent
    && doc?.generated_at
  ) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildProofStrengthDisclosurePreimage({
          enforcement_mode: doc!.enforcement_mode,
          capture_timing: doc!.capture_timing,
          pep_invariant: doc!.pep_invariant ?? null,
          witness_mode: doc!.witness_mode,
          witness_persistence: doc!.witness_persistence,
          external_transparency: doc!.external_transparency,
          limitations: doc!.limitations,
          generated_at: String(doc!.generated_at),
        }),
      ),
    );
    disclosureDigestMatches = Boolean(doc!.disclosure_digest) && doc!.disclosure_digest === expected;
  }

  const pepInvariant = doc?.pep_invariant ? String(doc.pep_invariant).trim() : null;

  const enforcedPepInvariantAligned =
    doc?.enforcement_mode !== 'enforced'
    || doc?.capture_timing !== 'pre_execution'
    || pepInvariant === PEP_INVARIANT_RECEIPT_BEFORE_ACTION;

  const auditOnlyPepInvariantAligned =
    doc?.enforcement_mode !== 'audit_only'
    || pepInvariant == null;

  const witnessPersistenceAligned =
    doc?.witness_mode !== 'awaited_fail_closed'
    || doc?.witness_persistence === 'postgres'
    || doc?.witness_persistence === 'external_only';

  const profileComplete =
    schemaValid
    && enforcementModeValid
    && captureTimingValid
    && witnessModeValid
    && witnessPersistenceValid
    && externalTransparencyValid
    && limitationsPresent
    && disclosureDigestMatches
    && enforcedPepInvariantAligned
    && auditOnlyPepInvariantAligned
    && witnessPersistenceAligned;

  let note: string | null = null;
  if (!schemaValid) note = `Invalid schema — expected ${PROOF_STRENGTH_DISCLOSURE_SCHEMA}`;
  else if (!disclosureDigestMatches) note = 'disclosure_digest mismatch';
  else if (!enforcedPepInvariantAligned) {
    note = `enforced pre_execution requires pep_invariant ${PEP_INVARIANT_RECEIPT_BEFORE_ACTION}`;
  } else if (!auditOnlyPepInvariantAligned) {
    note = 'audit_only enforcement must not carry pep_invariant';
  } else if (!witnessPersistenceAligned) {
    note = 'awaited_fail_closed witness requires postgres or external_only persistence';
  } else if (!limitationsPresent) note = 'limitations must be a non-empty string array';

  return {
    schema: PROOF_STRENGTH_DISCLOSURE_SCHEMA,
    sku: PROOF_STRENGTH_DISCLOSURE_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      enforcementModeValid,
      captureTimingValid,
      witnessModeValid,
      witnessPersistenceValid,
      externalTransparencyValid,
      limitationsPresent,
      disclosureDigestMatches,
      enforcedPepInvariantAligned,
      auditOnlyPepInvariantAligned,
      witnessPersistenceAligned,
      profileComplete,
    },
    gtmLine:
      'Proof strength is disclosed — buyers see enforced vs audit-only, pre-exec vs observed, and witness scope before trusting a green verify.',
    note: profileComplete
      ? `Proof-strength disclosure verified — ${doc!.enforcement_mode}, ${doc!.capture_timing}, witness ${doc!.witness_mode}`
      : note,
  };
}

export function defaultProofStrengthLimitations(): readonly string[] {
  return STANDARD_PROOF_LIMITATIONS;
}
