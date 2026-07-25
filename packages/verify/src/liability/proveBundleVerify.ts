import type { VerificationResult } from './types.js';
import { computeGatewayEventHash } from '../core/gatewayDecisionEvent.js';
import {
  isDeniedReceiptProfile,
  validateScittRefusalAlignment,
} from './deniedReceiptProfile.js';
import { verifyReceipt, type VerifyReceiptOptions } from './verifyReceipt.js';

export const PROVE_BUNDLE_VERIFY_SCHEMA = 'aevesa.prove-bundle-verify/v1' as const;
export const COSIGN_FRAGMENT_SCHEMA = 'aevesa.receipt-cosign-fragment/v1' as const;
export const SCITT_REFUSAL_STATEMENT_TYPE = 'https://scitt.io/statement/refusal/v0' as const;

export interface ProveBundleWitnessCosignInput {
  witnessed?: boolean;
  ok?: boolean;
  cosign?: {
    fragment?: {
      schema?: string;
      receipt_digest?: string;
      party?: string;
    } | null;
  } | null;
}

export interface ProveBundleCosignFragment {
  schema?: string;
  receipt_digest?: string;
  party?: string;
  role?: string;
  signed_at?: string;
  signature_alg?: string;
  signature?: string;
}

export interface ProveBundleScittRefusalWitnessInput {
  witnessed?: boolean;
  ok?: boolean;
  receiptDigest?: string | null;
  scrapiStatement?: { statement_type?: string; metadata?: { scitt_profile?: string } } | null;
}

export interface ProveBundleVerifyOptions extends VerifyReceiptOptions {
  /** aevesa.gateway-decision/v1 — recompute gateway_event_hash and compare to receipt */
  gatewayDecision?: unknown;
  /** Expected ledger entry_hash (defaults to receipt.proof.primary_anchor.entry_hash) */
  entryHash?: string;
  /** Optional witness cosign block from public API — structure + digest binding only (offline) */
  witnessCosign?: ProveBundleWitnessCosignInput | null;
  /** When true, witness cosign must be present and structurally valid */
  requireWitnessCosign?: boolean;
  /** Gateway co-sign fragment (structure check offline; HMAC via API) */
  gatewayCosignFragment?: ProveBundleCosignFragment | null;
  /** Receiver co-sign fragment from downstream agent ack */
  receiverCosignFragment?: ProveBundleCosignFragment | null;
  /** When true, receiver co-sign fragment must be present and structurally valid */
  requireReceiverCosign?: boolean;
  /** When true, gateway co-sign fragment must be present and structurally valid */
  requireGatewayCosign?: boolean;
  /** SCITT refusal witness verify block from public API */
  scittRefusalWitness?: ProveBundleScittRefusalWitnessInput | null;
  /** When true, SCITT refusal witness metadata must be present on DENIED receipts */
  requireScittRefusalWitness?: boolean;
}

export interface ProveBundleVerifyChecks {
  receiptValid: boolean;
  gatewayAttestationPresent: boolean;
  gatewayEventHashMatch: boolean | null;
  entryHashFormat: boolean;
  entryHashMatchesReceipt: boolean | null;
  witnessCosignProvided: boolean;
  witnessCosignStructureValid: boolean | null;
  gatewayCosignPresent: boolean;
  gatewayCosignStructureValid: boolean | null;
  receiverCosignPresent: boolean;
  receiverCosignStructureValid: boolean | null;
  multiPartyCosignComplete: boolean | null;
  scittRefusalAlignmentPresent: boolean | null;
  scittRefusalAlignmentValid: boolean | null;
  scittRefusalWitnessProvided: boolean;
  scittRefusalWitnessValid: boolean | null;
}

export interface ProveBundleVerifyResult {
  schema: typeof PROVE_BUNDLE_VERIFY_SCHEMA;
  ok: boolean;
  checks: ProveBundleVerifyChecks;
  receiptVerification?: VerificationResult;
  entryHash: string | null;
  gatewayEventHash: string | null;
  note: string | null;
}

function isHex64(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value.trim().toLowerCase());
}

function readReceiptEntryHash(receipt: Record<string, unknown>): string | null {
  const proof = receipt.proof;
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) return null;
  const anchor = (proof as { primary_anchor?: { entry_hash?: unknown } }).primary_anchor;
  const hash = anchor?.entry_hash;
  return isHex64(hash) ? hash.trim().toLowerCase() : null;
}

function readGatewayAttestation(receipt: Record<string, unknown>): Record<string, unknown> | null {
  const raw = receipt.gateway_attestation;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  return raw as Record<string, unknown>;
}

function verifyCosignFragmentStructure(
  fragment: ProveBundleCosignFragment | null | undefined,
  entryHash: string | null,
  expectedParty: string,
): { provided: boolean; valid: boolean | null } {
  if (!fragment || typeof fragment !== 'object') {
    return { provided: false, valid: null };
  }

  const digestOk = isHex64(fragment.receipt_digest)
    ? fragment.receipt_digest.trim().toLowerCase() === entryHash
    : false;
  const schemaOk = fragment.schema === COSIGN_FRAGMENT_SCHEMA;
  const partyOk = fragment.party === expectedParty;

  return {
    provided: true,
    valid: digestOk && schemaOk && partyOk,
  };
}

/**
 * Stateless prove-bundle verify — liability receipt + gateway binding + optional witness metadata.
 * Full witness cosign HMAC verification requires deployment secrets or the public witness API.
 */
export function verifyProveBundle(
  receiptData: unknown,
  options: ProveBundleVerifyOptions = {},
): ProveBundleVerifyResult {
  const checks: ProveBundleVerifyChecks = {
    receiptValid: false,
    gatewayAttestationPresent: false,
    gatewayEventHashMatch: null,
    entryHashFormat: false,
    entryHashMatchesReceipt: null,
    witnessCosignProvided: false,
    witnessCosignStructureValid: null,
    gatewayCosignPresent: false,
    gatewayCosignStructureValid: null,
    receiverCosignPresent: false,
    receiverCosignStructureValid: null,
    multiPartyCosignComplete: null,
    scittRefusalAlignmentPresent: null,
    scittRefusalAlignmentValid: null,
    scittRefusalWitnessProvided: false,
    scittRefusalWitnessValid: null,
  };

  const base: ProveBundleVerifyResult = {
    schema: PROVE_BUNDLE_VERIFY_SCHEMA,
    ok: false,
    checks,
    entryHash: null,
    gatewayEventHash: null,
    note: null,
  };

  if (receiptData == null || typeof receiptData !== 'object' || Array.isArray(receiptData)) {
    base.note = 'Prove bundle requires a liability-receipt/v1 JSON object';
    return base;
  }

  const receipt = receiptData as Record<string, unknown>;
  const receiptVerification = verifyReceipt(receiptData, options);
  base.receiptVerification = receiptVerification;
  checks.receiptValid = receiptVerification.isValid === true;

  const receiptEntryHash = readReceiptEntryHash(receipt);
  const expectedEntryHash = isHex64(options.entryHash)
    ? options.entryHash.trim().toLowerCase()
    : receiptEntryHash;

  checks.entryHashFormat = expectedEntryHash != null;
  base.entryHash = expectedEntryHash;

  if (expectedEntryHash && receiptEntryHash) {
    checks.entryHashMatchesReceipt = expectedEntryHash === receiptEntryHash;
  }

  const gatewayAttestation = readGatewayAttestation(receipt);
  checks.gatewayAttestationPresent = gatewayAttestation != null;

  if (gatewayAttestation) {
    const stampedHash = gatewayAttestation.gateway_event_hash;
    base.gatewayEventHash = isHex64(stampedHash) ? stampedHash.trim().toLowerCase() : null;

    if (options.gatewayDecision != null) {
      const recomputed = computeGatewayEventHash(options.gatewayDecision);
      checks.gatewayEventHashMatch =
        recomputed != null &&
        base.gatewayEventHash != null &&
        recomputed === base.gatewayEventHash;
    } else if (base.gatewayEventHash) {
      // Fail-closed: stamped hash is not trusted without gatewayDecision recomputation.
      checks.gatewayEventHashMatch = false;
    } else {
      checks.gatewayEventHashMatch = false;
    }
  }

  const witnessFragment =
    options.witnessCosign?.cosign?.fragment && typeof options.witnessCosign.cosign.fragment === 'object'
      ? (options.witnessCosign.cosign.fragment as ProveBundleCosignFragment)
      : null;
  const gatewayFragment = options.gatewayCosignFragment ?? witnessFragment;
  const gatewayCosign = verifyCosignFragmentStructure(gatewayFragment, expectedEntryHash, 'gateway');
  checks.gatewayCosignPresent = gatewayCosign.provided;
  checks.gatewayCosignStructureValid = gatewayCosign.valid;

  const receiverCosign = verifyCosignFragmentStructure(
    options.receiverCosignFragment,
    expectedEntryHash,
    'receiver',
  );
  checks.receiverCosignPresent = receiverCosign.provided;
  checks.receiverCosignStructureValid = receiverCosign.valid;

  checks.witnessCosignProvided = gatewayCosign.provided;
  checks.witnessCosignStructureValid = gatewayCosign.valid;

  if (gatewayCosign.provided || receiverCosign.provided) {
    checks.multiPartyCosignComplete =
      gatewayCosign.valid === true && receiverCosign.valid === true;
  }

  const witnessRequired = options.requireWitnessCosign === true;
  const witnessOk = !witnessRequired || (gatewayCosign.provided && gatewayCosign.valid === true);

  const gatewayCosignRequired = options.requireGatewayCosign === true;
  const gatewayCosignOk =
    !gatewayCosignRequired || (gatewayCosign.provided && gatewayCosign.valid === true);

  const receiverRequired = options.requireReceiverCosign === true;
  const receiverOk =
    !receiverRequired || (receiverCosign.provided && receiverCosign.valid === true);

  const multiPartyRequired = receiverRequired || gatewayCosignRequired;
  const multiPartyOk =
    !multiPartyRequired || checks.multiPartyCosignComplete === true;

  const deniedProfile = isDeniedReceiptProfile(receipt);
  if (deniedProfile) {
    checks.scittRefusalAlignmentPresent = Boolean(receipt.refusal_alignment);
    const alignment = validateScittRefusalAlignment(receipt);
    checks.scittRefusalAlignmentValid = alignment.ok === true;
  }

  const scittWitness = options.scittRefusalWitness;
  if (scittWitness && typeof scittWitness === 'object') {
    checks.scittRefusalWitnessProvided = scittWitness.witnessed === true;
    checks.scittRefusalWitnessValid =
      scittWitness.ok === true &&
      scittWitness.scrapiStatement?.statement_type === SCITT_REFUSAL_STATEMENT_TYPE;
  }

  const scittRequired = options.requireScittRefusalWitness === true && deniedProfile;
  const scittAlignmentOk =
    !deniedProfile ||
    (checks.scittRefusalAlignmentValid !== false && checks.scittRefusalAlignmentPresent !== false);
  const scittWitnessOk =
    !scittRequired || (checks.scittRefusalWitnessProvided && checks.scittRefusalWitnessValid === true);

  const gatewayOk =
    !checks.gatewayAttestationPresent ||
    (checks.gatewayEventHashMatch !== false && checks.entryHashMatchesReceipt !== false);

  base.ok =
    checks.receiptValid &&
    gatewayOk &&
    checks.entryHashFormat === true &&
    witnessOk &&
    gatewayCosignOk &&
    receiverOk &&
    multiPartyOk &&
    scittAlignmentOk &&
    scittWitnessOk;

  if (base.ok) {
    if (checks.scittRefusalWitnessValid === true) {
      base.note =
        'Prove bundle verified — DENIED receipt with SCITT refusal alignment and transparency log registration';
    } else if (checks.multiPartyCosignComplete === true) {
      base.note =
        'Prove bundle verified — receipt, gateway binding, gateway co-sign, and receiver co-sign are consistent';
    } else if (gatewayCosign.provided) {
      base.note =
        'Prove bundle verified — receipt, gateway binding, and witness/gateway co-sign metadata are consistent';
    } else {
      base.note = 'Prove bundle verified — receipt and gateway attestation binding are consistent';
    }
  } else if (!checks.receiptValid) {
    base.note = receiptVerification.error || 'Receipt verification failed';
  } else if (checks.gatewayEventHashMatch === false) {
    base.note = 'gateway_event_hash on receipt does not match recomputed gateway decision event';
  } else if (checks.entryHashMatchesReceipt === false) {
    base.note = 'entry_hash does not match receipt proof.primary_anchor.entry_hash';
  } else if (scittRequired && !scittWitnessOk) {
    base.note = 'SCITT refusal witness required for DENIED receipt but missing or invalid';
  } else if (deniedProfile && checks.scittRefusalAlignmentValid === false) {
    base.note = 'SCITT refusal_alignment metadata invalid on DENIED receipt';
  } else if (receiverRequired && !receiverOk) {
    base.note = 'Receiver co-sign required but missing or structurally invalid for entry_hash';
  } else if (gatewayCosignRequired && !gatewayCosignOk) {
    base.note = 'Gateway co-sign required but missing or structurally invalid for entry_hash';
  } else if (witnessRequired && !witnessOk) {
    base.note = 'Witness cosign required but missing or structurally invalid for entry_hash';
  } else {
    base.note = 'Prove bundle verification failed';
  }

  return base;
}
