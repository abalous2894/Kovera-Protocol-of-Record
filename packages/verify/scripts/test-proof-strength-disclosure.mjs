#!/usr/bin/env node
/**
 * Wave 15 Track A — proof-strength disclosure offline verify smoke test.
 */
import assert from 'node:assert/strict';
import {
  buildProofStrengthDisclosureDocument,
  deriveProofStrengthDisclosureFromContext,
  PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
} from '../dist/core/proofStrengthDisclosure.js';
import { verifyProofStrengthDisclosure } from '../dist/liability/proofStrengthDisclosureVerify.js';
import { detectEvidenceType } from '../src/verify/detectEvidenceType.js';
import { runUnifiedVerify } from '../src/verify/runUnifiedVerify.js';

const enforced = buildProofStrengthDisclosureDocument({
  enforcement_mode: 'enforced',
  capture_timing: 'pre_execution',
  pep_invariant: PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
  witness_mode: 'awaited_fail_closed',
  witness_persistence: 'postgres',
  external_transparency: 'rekor_metadata_only',
  generated_at: '2026-09-09T20:00:00.000Z',
});

const enforcedVerify = verifyProofStrengthDisclosure(enforced);
assert.equal(enforcedVerify.ok, true, enforcedVerify.note);

const derived = deriveProofStrengthDisclosureFromContext({
  policy_enforcement_level: 'enforce',
  pep_receipt_before_action_enabled: true,
  witness_cosign_enabled: true,
  witness_awaited: true,
  witness_persistence: 'postgres',
  external_transparency: 'rekor_metadata_only',
  generated_at: '2026-09-09T20:00:00.000Z',
});
assert.equal(derived.enforcement_mode, 'enforced');
assert.equal(derived.pep_invariant, PEP_INVARIANT_RECEIPT_BEFORE_ACTION);
assert.equal(verifyProofStrengthDisclosure(derived).ok, true);

const auditOnly = deriveProofStrengthDisclosureFromContext({
  policy_enforcement_level: 'audit_only',
  pep_receipt_before_action_enabled: true,
  witness_cosign_enabled: false,
  generated_at: '2026-09-09T20:00:00.000Z',
});
assert.equal(auditOnly.enforcement_mode, 'audit_only');
assert.equal(auditOnly.pep_invariant, null);
assert.equal(verifyProofStrengthDisclosure(auditOnly).ok, true);

const tampered = { ...enforced, enforcement_mode: 'audit_only' };
assert.equal(verifyProofStrengthDisclosure(tampered).ok, false);

assert.equal(detectEvidenceType(enforced).kind, 'proof_strength_disclosure');

const unified = await runUnifiedVerify(enforced, { fetch: false });
assert.equal(unified.ok, true, unified.errors?.join('; '));
assert.equal(unified.evidence_kind, 'proof_strength_disclosure');

console.log('proof-strength disclosure offline verify OK');
