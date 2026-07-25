import type { ProveBundleVerifyOptions, ProveBundleVerifyResult } from './proveBundleVerify.js';
import { verifyProveBundle, PROVE_BUNDLE_VERIFY_SCHEMA } from './proveBundleVerify.js';

export const EVIDENCE_CUSTODIAN_VERIFY_SCHEMA = 'aevesa.evidence-custodian-verify/v1' as const;
export const EVIDENCE_CUSTODIAN_SKU = 'aevesa-evidence-custodian-v1' as const;

export interface EvidenceCustodianVerifyChecks {
  /** Inherited prove-bundle checks */
  proveBundle: ProveBundleVerifyResult['checks'];
  /** gateway_attestation.gateway_source is present (guardian/platform origin) */
  guardianSourcePresent: boolean;
  /** Independent witness cosign required and structurally valid (offline) */
  custodianWitnessBound: boolean;
  /** Receipt + gateway + witness profile satisfied */
  custodianProfileComplete: boolean;
}

export interface EvidenceCustodianVerifyOptions extends ProveBundleVerifyOptions {
  /** When true (default), require witness cosign on the custodian profile */
  requireCustodianWitness?: boolean;
}

export interface EvidenceCustodianVerifyResult {
  schema: typeof EVIDENCE_CUSTODIAN_VERIFY_SCHEMA;
  sku: typeof EVIDENCE_CUSTODIAN_SKU;
  ok: boolean;
  checks: EvidenceCustodianVerifyChecks;
  proveBundle: ProveBundleVerifyResult;
  guardianSource: string | null;
  gtmLine: string;
  note: string | null;
}

function readGuardianSource(receipt: Record<string, unknown>): string | null {
  const att = receipt.gateway_attestation;
  if (!att || typeof att !== 'object' || Array.isArray(att)) return null;
  const source = (att as { gateway_source?: unknown }).gateway_source;
  return typeof source === 'string' && source.trim() ? source.trim() : null;
}

/**
 * Evidence Custodian profile — guardian decision cosigned into liability receipt
 * with independent witness binding (metagovernance / Gartner Guardian Agents evidence layer).
 *
 * Offline: receipt crypto + gateway binding + witness fragment structure.
 * Online: use buildProveBundleVerifyResult with requireWitnessCosign for full witness HMAC.
 */
export function verifyEvidenceCustodianBundle(
  receiptData: unknown,
  options: EvidenceCustodianVerifyOptions = {},
): EvidenceCustodianVerifyResult {
  const requireWitness = options.requireCustodianWitness !== false;

  const proveBundle = verifyProveBundle(receiptData, {
    ...options,
    requireWitnessCosign: requireWitness,
  });

  const receipt =
    receiptData != null && typeof receiptData === 'object' && !Array.isArray(receiptData)
      ? (receiptData as Record<string, unknown>)
      : null;

  const guardianSource = receipt ? readGuardianSource(receipt) : null;
  const guardianSourcePresent = guardianSource != null;

  const custodianWitnessBound =
    !requireWitness ||
    (proveBundle.checks.witnessCosignProvided === true &&
      proveBundle.checks.witnessCosignStructureValid === true);

  const custodianProfileComplete =
    proveBundle.checks.receiptValid === true &&
    proveBundle.checks.gatewayAttestationPresent === true &&
    guardianSourcePresent &&
    custodianWitnessBound &&
    proveBundle.checks.entryHashFormat === true &&
    (proveBundle.checks.entryHashMatchesReceipt !== false) &&
    (proveBundle.checks.gatewayEventHashMatch !== false);

  const ok = proveBundle.ok && custodianProfileComplete;

  let note: string | null = proveBundle.note;
  if (ok) {
    note =
      'Evidence custodian profile verified — guardian decision bound to receipt with independent witness cosign metadata';
  } else if (!guardianSourcePresent) {
    note = 'Evidence custodian requires gateway_attestation.gateway_source (guardian/platform origin)';
  } else if (requireWitness && !custodianWitnessBound) {
    note = 'Evidence custodian requires independent witness cosign bound to entry_hash';
  } else if (!proveBundle.ok) {
    note = proveBundle.note;
  } else {
    note = 'Evidence custodian profile verification failed';
  }

  return {
    schema: EVIDENCE_CUSTODIAN_VERIFY_SCHEMA,
    sku: EVIDENCE_CUSTODIAN_SKU,
    ok,
    checks: {
      proveBundle: proveBundle.checks,
      guardianSourcePresent,
      custodianWitnessBound,
      custodianProfileComplete,
    },
    proveBundle,
    guardianSource,
    gtmLine:
      'Your guardian intercepts. Aevesa custodies the proof — cosigned, offline-verifiable, outside your guardian admin plane.',
    note,
  };
}

export { PROVE_BUNDLE_VERIFY_SCHEMA };
