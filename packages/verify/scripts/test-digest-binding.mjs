#!/usr/bin/env node
/**
 * KVR-102 — receipt_digest binding for intent_alignment + legacy profiles.
 */
import { randomUUID, createHash } from 'node:crypto';
import {
  computeReceiptDigest,
  verifyReceiptDigestMatch,
  verifyReceipt,
  evaluateIntentAlignment,
  normalizeStructuralPayload,
  canonicalizeIntentAlignmentForDigest,
} from '../dist/index.js';

function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

function baseReceipt() {
  const now = new Date().toISOString();
  const policyPackId = 'digest_binding_test_v1';
  return {
    schema: 'liability-receipt/v1',
    receipt_id: randomUUID(),
    issued_at: now,
    issuer: { name: 'Aevesa', product: 'VAS', verification_profile: 'aegis/1' },
    session: {
      session_id: randomUUID(),
      correlation_id: randomUUID(),
      vertical: 'enterprise_ops',
      outcome: 'blocked',
    },
    identity: {
      primary_actor: { agent_id: 'test-agent', actor_class: 'autonomous_agent' },
      authority: { scoped_role: 'SERVER', permission_id: 'test' },
    },
    policy: {
      policy_pack_id: policyPackId,
      policy_version_hash: sha256Hex(policyPackId),
      decision: 'deny',
    },
    hitl: { required: false, status: 'not_required' },
    side_effects: {
      action: {
        tool_name: 'read_file',
        verb: 'read',
        target_path: '/proc/self/environ',
      },
      effect_class: 'data_access',
      summary: 'digest binding test',
    },
    proof: {
      ledger_spec: 'aegis/1',
      primary_anchor: {
        entry_hash: sha256Hex(`anchor:${randomUUID()}`),
        event_type: 'RUNTIME_BLOCKED',
      },
      verification: { status: 'demo', methods: ['digest_binding_test'] },
    },
    diligence_summary: {
      who_acted: 'test',
      what_policy_allowed: 'test',
      what_proof_says: 'test',
    },
  };
}

let failed = 0;
function assert(name, cond, detail = '') {
  if (cond) {
    console.log(`OK ${name}`);
  } else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

const intentContext = {
  reasoning_summary: 'Formatting a backup log for archival compliance',
  model_fingerprint: 'gpt-4.1-2025-04-14',
};
const payload = { toolName: 'read_file', path: '/proc/self/environ' };
const alignment = evaluateIntentAlignment(intentContext, normalizeStructuralPayload(payload));

const bound = {
  ...baseReceipt(),
  intent_context: intentContext,
  intent_alignment: alignment,
};
bound.integrity = {
  receipt_digest: computeReceiptDigest(bound),
  signature_alg: 'none',
  signature: null,
  manifest_signature_jws: null,
};

const match = verifyReceiptDigestMatch(bound);
assert('current profile verifies digest-bound receipt', match.ok && match.profile === 'current');
assert('verifyReceipt accepts KVR-102 receipt', verifyReceipt(bound).isValid);

const legacyIntentOnly = {
  ...bound,
  intent_alignment: undefined,
};
legacyIntentOnly.integrity = {
  receipt_digest: computeReceiptDigest(legacyIntentOnly, { profile: 'v1_intent_context' }),
  signature_alg: 'none',
  signature: null,
  manifest_signature_jws: null,
};
const legacyMatch = verifyReceiptDigestMatch(legacyIntentOnly);
assert('legacy intent_context-only receipt verifies', legacyMatch.ok);

const v10 = { ...baseReceipt() };
v10.integrity = {
  receipt_digest: computeReceiptDigest(v10, { profile: 'v1_0' }),
  signature_alg: 'none',
  signature: null,
  manifest_signature_jws: null,
};
const v10Match = verifyReceiptDigestMatch(v10);
assert('v1_0 legacy receipt verifies', v10Match.ok);
assert('verifyReceipt accepts v1_0 legacy receipt', verifyReceipt(v10).isValid);

const tampered = {
  ...bound,
  intent_alignment: { ...alignment, score: 0 },
};
tampered.integrity = { ...bound.integrity };
const tamperedMatch = verifyReceiptDigestMatch(tampered);
assert('tampered alignment fails digest match', tamperedMatch.ok === false);
const tamperedVerify = verifyReceipt(tampered);
assert('tampered alignment fails verifyReceipt', tamperedVerify.isValid === false);

const canonicalA = canonicalizeIntentAlignmentForDigest({
  level: 'CRITICAL',
  score: 1,
  signals: ['B', 'A'],
});
const canonicalB = canonicalizeIntentAlignmentForDigest({
  level: 'CRITICAL',
  score: 1,
  signals: ['A', 'B'],
});
assert(
  'signal order canonicalized for digest',
  JSON.stringify(canonicalA) === JSON.stringify(canonicalB),
);

const perfStart = performance.now();
for (let i = 0; i < 1000; i += 1) {
  computeReceiptDigest(bound);
}
const perfMs = (performance.now() - perfStart) / 1000;
assert('digest compute perf < 2ms', perfMs < 2, `${perfMs.toFixed(4)}ms avg`);

console.log(`\n${failed ? 'FAILED' : 'PASSED'} (${failed} failures)`);
process.exit(failed > 0 ? 1 : 0);
