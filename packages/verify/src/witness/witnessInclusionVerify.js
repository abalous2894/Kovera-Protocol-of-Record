/**
 * Offline witness inclusion proof verification (aevesa witness log + SCITT export).
 * No Aevesa API — third parties verify exported witness bundles locally.
 */

import { sha256Utf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  REKOR_INCLUSION_DIGEST_MISMATCH,
  REKOR_INCLUSION_PROOF_REQUIRED,
  verifyRekorCryptoInclusionProof,
} from './rekorInclusionVerify.js';

export const WITNESS_INCLUSION_PROOF_SCHEMA = 'aevesa.witness.inclusion-proof/v1';
export const WITNESS_GENESIS_HASH = '0'.repeat(64);
export const SCITT_REFUSAL_WITNESS_VERIFY_SCHEMA = 'aevesa.scitt-refusal-witness-verify/v1';
export const SCITT_REFUSAL_STATEMENT_TYPE = 'https://scitt.io/statement/refusal/v0';
export const REKOR_WITNESS_METADATA_SCHEMA = 'aevesa.witness.rekor-metadata/v1';

/**
 * Mirror private-backend witnessLogService.calculateCanonicalHash (shared kernel).
 * @param {object} ledgerEntry
 * @param {number} sequence
 */
export function calculateWitnessEntryHash(ledgerEntry, sequence) {
  const eventTimestamp =
    ledgerEntry.eventTimestamp instanceof Date
      ? ledgerEntry.eventTimestamp.toISOString()
      : String(ledgerEntry.eventTimestamp || '');
  const preimage = stableStringify({
    orgId: ledgerEntry.orgId,
    sequence,
    prevHash: ledgerEntry.prevHash,
    digest: ledgerEntry.digest,
    eventTimestamp,
    nonce: ledgerEntry.nonce,
    payload: ledgerEntry.payload ?? {},
  });
  return sha256Utf8(preimage);
}

/**
 * @param {unknown} inclusionProof
 * @param {unknown} ledgerAppend
 * @param {unknown} [verificationExport]
 */
export function verifyWitnessInclusionProof(inclusionProof, ledgerAppend, verificationExport) {
  const result = {
    schema: 'aevesa.witness-inclusion-verify/v1',
    ok: false,
    checks: {
      inclusionProofPresent: false,
      ledgerAppendPresent: false,
      rootHashMatchesAppend: false,
      parentHashMatchesAppend: false,
      sequenceMatchesAppend: false,
      canonicalHashRecompute: false,
    },
    errors: [],
  };

  if (!inclusionProof || typeof inclusionProof !== 'object') {
    result.errors.push('inclusion_proof missing');
    return result;
  }
  result.checks.inclusionProofPresent = inclusionProof.schema === WITNESS_INCLUSION_PROOF_SCHEMA;

  if (!ledgerAppend || typeof ledgerAppend !== 'object') {
    result.errors.push('ledger_append missing');
    return result;
  }
  result.checks.ledgerAppendPresent = true;

  const rootHash = String(inclusionProof.root_hash || '').toLowerCase();
  const parentHash = String(inclusionProof.parent_hash || WITNESS_GENESIS_HASH).toLowerCase();
  const entryHash = String(ledgerAppend.entryHash || ledgerAppend.entry_hash || '').toLowerCase();
  const appendParent = String(ledgerAppend.parentHash || ledgerAppend.parent_hash || '').toLowerCase();
  const sequence = Number(inclusionProof.entry_index ?? ledgerAppend.sequence ?? -1);
  const appendSeq = Number(ledgerAppend.sequence ?? -1);

  result.checks.rootHashMatchesAppend = Boolean(rootHash && entryHash && rootHash === entryHash);
  result.checks.parentHashMatchesAppend = parentHash === appendParent;
  result.checks.sequenceMatchesAppend = sequence >= 0 && sequence === appendSeq;

  if (verificationExport && typeof verificationExport === 'object') {
    const recomputed = calculateWitnessEntryHash(
      {
        orgId: verificationExport.orgId ?? verificationExport.org_id,
        prevHash: verificationExport.prevHash ?? verificationExport.prev_hash,
        digest: verificationExport.digest,
        eventTimestamp: verificationExport.eventTimestamp ?? verificationExport.event_timestamp,
        nonce: verificationExport.nonce,
        payload: verificationExport.payload ?? {},
      },
      sequence,
    );
    result.checks.canonicalHashRecompute = recomputed === rootHash;
    if (!result.checks.canonicalHashRecompute) {
      result.errors.push('canonical witness entry hash mismatch');
    }
  }

  result.ok =
    result.checks.inclusionProofPresent &&
    result.checks.ledgerAppendPresent &&
    result.checks.rootHashMatchesAppend &&
    result.checks.parentHashMatchesAppend &&
    result.checks.sequenceMatchesAppend &&
    (verificationExport ? result.checks.canonicalHashRecompute : true);

  if (!result.ok && result.errors.length === 0) {
    result.errors.push('inclusion proof linkage failed');
  }

  return result;
}

/**
 * Offline Rekor metadata check — digest binding + lookup hint (no HTTP to Aevesa).
 * @param {unknown} rekorMeta
 * @param {string} digestHex
 */
export function verifyExternalRekorWitness(rekorMeta, digestHex) {
  const digest = String(digestHex || '').trim().toLowerCase();
  const errors = [];
  if (!rekorMeta || typeof rekorMeta !== 'object') {
    return { ok: false, schema: REKOR_WITNESS_METADATA_SCHEMA, errors: ['rekor metadata missing'] };
  }
  if (rekorMeta.schema !== REKOR_WITNESS_METADATA_SCHEMA) {
    errors.push(`schema must be ${REKOR_WITNESS_METADATA_SCHEMA}`);
  }
  if (rekorMeta.ok !== true) {
    errors.push('rekor submission must report ok: true');
  }
  if (!rekorMeta.uuid) {
    errors.push('uuid required for independent transparency log lookup');
  }
  if (rekorMeta.digest && String(rekorMeta.digest).toLowerCase() !== digest) {
    errors.push('rekor digest does not match statement digest');
  }
  return {
    ok: errors.length === 0,
    schema: REKOR_WITNESS_METADATA_SCHEMA,
    uuid: rekorMeta.uuid ?? null,
    verification_hint: rekorMeta.verification_hint ?? null,
    witnessUrl: rekorMeta.witnessUrl ?? null,
    errors,
    codes: [],
    note:
      errors.length === 0
        ? 'Rekor metadata valid offline — verify independently via GET {witnessUrl}/api/v1/log/entries/{uuid}'
        : null,
  };
}

/**
 * @param {unknown} proof
 */
function bundledRekorInclusionProof(proof) {
  return Boolean(proof && typeof proof === 'object');
}

/**
 * Metadata + optional RFC 6962 inclusion proof (fail-closed when requireInclusionProof).
 * @param {unknown} rekorMeta
 * @param {string} digestHex
 * @param {unknown} [inclusionProof]
 * @param {{ requireInclusionProof?: boolean; expectedLogId?: string | null }} [options]
 */
export function verifyExternalRekorWitnessWithInclusion(rekorMeta, digestHex, inclusionProof, options = {}) {
  const metadata = verifyExternalRekorWitness(rekorMeta, digestHex);
  const requireInclusionProof = options.requireInclusionProof === true;
  const bundledProof =
    inclusionProof ??
    (rekorMeta && typeof rekorMeta === 'object'
      ? rekorMeta.rekor_inclusion_proof ?? rekorMeta.inclusion_proof ?? rekorMeta.inclusionProof ?? null
      : null);

  if (!bundledRekorInclusionProof(bundledProof)) {
    if (requireInclusionProof && metadata.ok) {
      return {
        ...metadata,
        ok: false,
        inclusion_crypto: null,
        codes: [REKOR_INCLUSION_PROOF_REQUIRED],
        errors: [
          ...(metadata.errors || []),
          'Rekor metadata present but cryptographic inclusion proof is required',
        ],
        note: 'Rekor witness incomplete — bundle inclusion proof artifacts for offline crypto verify',
      };
    }
    return {
      ...metadata,
      inclusion_crypto: null,
      codes: [],
      note:
        metadata.note ??
        (metadata.ok
          ? 'Rekor metadata valid offline — inclusion crypto not bundled (metadata-only witness)'
          : null),
    };
  }

  const expectedLogIndex =
    rekorMeta && typeof rekorMeta === 'object'
      ? Number(rekorMeta.log_index ?? rekorMeta.logIndex ?? -1)
      : -1;

  const statementDigest = String(digestHex || '').trim().toLowerCase();
  const crypto = verifyRekorCryptoInclusionProof(bundledProof, {
    expectedLogIndex: expectedLogIndex >= 0 ? expectedLogIndex : null,
    expectedLogId: options.expectedLogId ?? null,
    expectedStatementDigest: /^[a-f0-9]{64}$/.test(statementDigest) ? statementDigest : null,
  });

  return {
    ...metadata,
    ok: metadata.ok && crypto.ok,
    inclusion_crypto: crypto,
    codes: crypto.codes?.length ? crypto.codes : metadata.ok ? [] : [],
    errors: [...(metadata.errors || []), ...(crypto.errors || [])],
    note: metadata.ok && crypto.ok ? crypto.note : metadata.note,
  };
}

/**
 * Fail-closed when export claims Rekor inclusion was verified (Wave 15 Track B).
 * @param {Record<string, unknown>} input
 */
export function resolveRequireRekorInclusionProof(input) {
  if (input.requireRekorInclusionProof === true || input.require_rekor_inclusion_proof === true) {
    return true;
  }
  const proofStrength =
    input.proofStrengthDisclosure ??
    input.proof_strength_disclosure ??
    input.proofStrength ??
    input.proof_strength ??
    null;
  if (proofStrength && typeof proofStrength === 'object') {
    const externalTransparency =
      proofStrength.external_transparency ?? proofStrength.externalTransparency ?? null;
    if (externalTransparency === 'rekor_inclusion_verified') return true;
  }
  const externalService =
    input.externalTransparencyService ?? input.external_transparency_service ?? null;
  if (externalService && typeof externalService === 'object') {
    if (externalService.require_inclusion_proof === true) return true;
    if (externalService.external_transparency === 'rekor_inclusion_verified') return true;
  }
  return false;
}

/**
 * Full offline SCITT refusal witness bundle (export from registerScittRefusalWitness or public API).
 * @param {unknown} bundle
 */
export function verifyScittRefusalWitnessBundle(bundle) {
  const input = bundle && typeof bundle === 'object' ? bundle : {};
  const result = {
    schema: SCITT_REFUSAL_WITNESS_VERIFY_SCHEMA,
    ok: false,
    offline: true,
    checks: {
      receiptDigestFormat: false,
      scrapiStatementPresent: false,
      statementTypeRefusal: false,
      inclusionProofValid: false,
      externalRekorValid: null,
      externalRekorInclusionCrypto: null,
      digestMatchesStatement: false,
    },
    receiptDigest: input.receiptDigest ?? input.receipt_digest ?? null,
    inclusionProof: input.inclusionProof ?? input.inclusion_proof ?? null,
    scrapiStatement: input.scrapiStatement ?? input.scrapi_statement ?? null,
    externalTransparencyService: input.externalTransparencyService ?? input.external_transparency_service ?? null,
    note: null,
  };

  const digest = String(result.receiptDigest || '').trim().toLowerCase();
  result.checks.receiptDigestFormat = /^[a-f0-9]{64}$/.test(digest);

  const scrapi = result.scrapiStatement;
  result.checks.scrapiStatementPresent = Boolean(scrapi && typeof scrapi === 'object');
  result.checks.statementTypeRefusal =
    scrapi?.statement_type === SCITT_REFUSAL_STATEMENT_TYPE;
  const statementDigest = String(scrapi?.digest?.value || '').toLowerCase();
  result.checks.digestMatchesStatement =
    !digest || !statementDigest || digest === statementDigest;

  const ledgerAppend =
    input.ledgerAppend ??
    input.ledger_append ??
    input.witnessEntry?.ledger_append ??
    null;
  const verificationExport =
    input.verificationExport ??
    input.verification_export ??
    input.witnessEntry?.verification_export ??
    null;

  const inclusion = verifyWitnessInclusionProof(result.inclusionProof, ledgerAppend, verificationExport);
  result.checks.inclusionProofValid = inclusion.ok;

  const witnesses = input.witnesses ?? input.witnessEntry?.witnesses ?? [];
  const rekorMeta = Array.isArray(witnesses)
    ? witnesses.find((w) => w?.type === 'rekor' || w?.schema === REKOR_WITNESS_METADATA_SCHEMA)
    : result.externalTransparencyService?.rekor ?? null;

  const bundledRekorProof =
    input.rekorInclusionProof ??
    input.rekor_inclusion_proof ??
    input.externalTransparencyService?.rekor_inclusion_proof ??
    null;

  const requireRekorInclusionProof = resolveRequireRekorInclusionProof(input);

  if (rekorMeta) {
    const rekorCheck = verifyExternalRekorWitnessWithInclusion(
      rekorMeta,
      statementDigest || digest,
      bundledRekorProof ?? undefined,
      { requireInclusionProof: requireRekorInclusionProof },
    );
    result.checks.externalRekorValid = rekorCheck.ok;
    result.checks.externalRekorInclusionCrypto = rekorCheck.inclusion_crypto?.ok ?? null;
    result.externalRekorVerification = rekorCheck;
    result.rekorInclusionRequired = requireRekorInclusionProof;
  }

  result.ok =
    result.checks.receiptDigestFormat &&
    result.checks.scrapiStatementPresent &&
    result.checks.statementTypeRefusal &&
    result.checks.inclusionProofValid &&
    result.checks.digestMatchesStatement &&
    (result.checks.externalRekorValid === null || result.checks.externalRekorValid === true);

  if (
    !result.ok &&
    result.externalRekorVerification?.codes?.includes(REKOR_INCLUSION_PROOF_REQUIRED)
  ) {
    result.note =
      'Rekor witness incomplete — export claims rekor_inclusion_verified but cryptographic inclusion proof is not bundled';
  } else {
    result.note = result.ok
      ? requireRekorInclusionProof && result.checks.externalRekorInclusionCrypto === true
        ? 'SCITT refusal witness verified offline — Aevesa inclusion proof + Rekor RFC 6962 inclusion crypto valid without HTTP'
        : 'SCITT refusal witness verified offline — inclusion proof + optional Rekor metadata valid without Aevesa API'
      : 'SCITT refusal witness bundle incomplete or inclusion proof invalid';
  }

  return result;
}

export { REKOR_INCLUSION_PROOF_REQUIRED, REKOR_INCLUSION_DIGEST_MISMATCH } from './rekorInclusionVerify.js';

export default {
  calculateWitnessEntryHash,
  verifyWitnessInclusionProof,
  verifyExternalRekorWitness,
  verifyExternalRekorWitnessWithInclusion,
  resolveRequireRekorInclusionProof,
  verifyScittRefusalWitnessBundle,
  WITNESS_INCLUSION_PROOF_SCHEMA,
  WITNESS_GENESIS_HASH,
  SCITT_REFUSAL_WITNESS_VERIFY_SCHEMA,
  SCITT_REFUSAL_STATEMENT_TYPE,
  REKOR_WITNESS_METADATA_SCHEMA,
};
