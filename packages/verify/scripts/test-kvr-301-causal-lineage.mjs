#!/usr/bin/env node
/**
 * KVR-301 — causal_lineage digest binding + ledger cross-check.
 */
import { randomUUID, createHash } from 'node:crypto';
import {
  computeReceiptDigest,
  verifyReceiptDigestMatch,
  verifyReceipt,
  extractCausalLineageFromPayload,
  canonicalizeCausalLineageForDigest,
  causalLineageToProofBinding,
} from '../dist/index.js';
import { buildCausalBinding, computeProofOfIntent } from '../dist/core/proofOfIntent.js';

function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

const parentHash = 'c'.repeat(64);
const childAnchor = sha256Hex(`child:${randomUUID()}`);

function baseReceipt() {
  const now = new Date().toISOString();
  const policyPackId = 'kvr301_swarm_child_v1';
  return {
    schema: 'liability-receipt/v1',
    receipt_id: randomUUID(),
    issued_at: now,
    issuer: { name: 'Kovera', product: 'VAS', verification_profile: 'aegis/1' },
    session: {
      session_id: 'child-session-001',
      correlation_id: randomUUID(),
      vertical: 'enterprise_ops',
      outcome: 'blocked',
      started_at: now,
      completed_at: now,
    },
    identity: {
      primary_actor: { agent_id: 'worker-agent-02', actor_class: 'autonomous_agent' },
      authority: { scoped_role: 'SERVER', permission_id: 'swarm-delegation' },
    },
    policy: {
      policy_pack_id: policyPackId,
      policy_version_hash: sha256Hex(policyPackId),
      decision: 'deny',
    },
    hitl: { required: false, status: 'not_required' },
    side_effects: {
      action: { tool_name: 'read_file', verb: 'read', target_path: '/secrets/payroll.csv' },
      effect_class: 'data_access',
      summary: 'Delegated child attempted unauthorized read.',
      blocked_reason: 'INTENT_ALIGNMENT_BLOCKED',
    },
    proof: {
      ledger_spec: 'aegis/1',
      primary_anchor: {
        entry_hash: childAnchor,
        event_type: 'INTENT_ALIGNMENT_BLOCKED',
        timestamp: now,
      },
      verification: {
        status: 'demo',
        methods: ['causal_lineage_binding', 'kvr301_test'],
      },
    },
    diligence_summary: {
      who_acted: 'Child agent under swarm delegation',
      what_policy_allowed: 'Runtime firewall blocked before side effect.',
      what_proof_says: `Child anchor ${childAnchor.slice(0, 12)}… bound to parent ${parentHash.slice(0, 12)}…`,
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

const ledgerPayload = {
  toolName: 'read_file',
  path: '/secrets/payroll.csv',
  parentEntryHash: parentHash,
  parentSessionId: 'manager-session-001',
  rootSessionId: 'swarm-root-001',
  swarmFirstAction: true,
};

const extracted = extractCausalLineageFromPayload(ledgerPayload);
assert('extractCausalLineageFromPayload maps parent hash', extracted?.parent_entry_hash === parentHash);
assert('extractCausalLineageFromPayload maps session ids', extracted?.parent_session_id === 'manager-session-001');

const receipt = baseReceipt();
receipt.causal_lineage = extracted;
receipt.session.outcome = 'blocked';

const digest = computeReceiptDigest(receipt);
receipt.integrity = { receipt_digest: digest, signature_alg: 'none', signature: null, manifest_signature_jws: null };

assert('digest match with causal_lineage', verifyReceiptDigestMatch(receipt).ok);

const withoutLineage = computeReceiptDigest({ ...receipt, causal_lineage: undefined, integrity: undefined });
assert('causal_lineage changes digest', withoutLineage !== digest);

const tampered = structuredClone(receipt);
tampered.causal_lineage.parent_entry_hash = 'd'.repeat(64);
assert('tampered parent hash fails digest', !verifyReceiptDigestMatch(tampered).ok);

const ledgerDoc = {
  agentId: 'worker-agent-02',
  eventType: 'INTENT_ALIGNMENT_BLOCKED',
  entryHash: childAnchor,
  payload: ledgerPayload,
  timestamp: receipt.issued_at,
  prevHash: parentHash,
  contextHash: sha256Hex('ctx'),
};

assert(
  'verifyReceipt accepts matching ledger parent binding',
  verifyReceipt(receipt, { ledgerDocument: ledgerDoc }).isValid,
);

const mismatchedLedger = {
  ...ledgerDoc,
  payload: { ...ledgerPayload, parentEntryHash: 'e'.repeat(64) },
};
assert(
  'verifyReceipt rejects ledger/receipt parent mismatch',
  !verifyReceipt(receipt, { ledgerDocument: mismatchedLedger }).isValid,
);

const proofBinding = buildCausalBinding({ payload: ledgerPayload, swarmFirstAction: true });
const mapped = causalLineageToProofBinding(receipt.causal_lineage);
assert('causalLineageToProofBinding aligns with proofOfIntent', mapped?.parentEntryHash === proofBinding?.parentEntryHash);

const envelope = {
  reasoningPath: { reasoningDigest: sha256Hex('reason') },
  constraintsApplied: { toolName: 'read_file' },
  modelFingerprint: { primaryModel: 'gpt-4.1' },
  causalBinding: proofBinding,
};
const withParentPoi = computeProofOfIntent(envelope);
const withoutParentPoi = computeProofOfIntent({ ...envelope, causalBinding: null });
assert('proofOfIntent hash differs when parent bound', withParentPoi !== withoutParentPoi);

console.log(failed === 0 ? '\nKVR-301 causal lineage tests passed.' : `\n${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
