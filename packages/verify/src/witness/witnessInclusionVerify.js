/**
 * Offline witness inclusion proof verification (aevesa witness log + SCITT export).
 * No Aevesa API — third parties verify exported witness bundles locally.
 */

import { sha256Utf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';

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
    note:
      errors.length === 0
        ? 'Rekor metadata valid offline — verify independently via GET {witnessUrl}/api/v1/log/entries/{uuid}'
        : null,
  };
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

  if (rekorMeta) {
    const rekorCheck = verifyExternalRekorWitness(rekorMeta, statementDigest || digest);
    result.checks.externalRekorValid = rekorCheck.ok;
    result.externalRekorVerification = rekorCheck;
  }

  result.ok =
    result.checks.receiptDigestFormat &&
    result.checks.scrapiStatementPresent &&
    result.checks.statementTypeRefusal &&
    result.checks.inclusionProofValid &&
    result.checks.digestMatchesStatement &&
    (result.checks.externalRekorValid === null || result.checks.externalRekorValid === true);

  result.note = result.ok
    ? 'SCITT refusal witness verified offline — inclusion proof + optional Rekor metadata valid without Aevesa API'
    : 'SCITT refusal witness bundle incomplete or inclusion proof invalid';

  return result;
}

export default {
  calculateWitnessEntryHash,
  verifyWitnessInclusionProof,
  verifyExternalRekorWitness,
  verifyScittRefusalWitnessBundle,
  WITNESS_INCLUSION_PROOF_SCHEMA,
  WITNESS_GENESIS_HASH,
  SCITT_REFUSAL_WITNESS_VERIFY_SCHEMA,
  SCITT_REFUSAL_STATEMENT_TYPE,
  REKOR_WITNESS_METADATA_SCHEMA,
};
