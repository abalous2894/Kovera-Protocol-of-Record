#!/usr/bin/env node
/**
 * Smoke test: build a minimal liability-receipt/v1 and verify offline.
 */
import { randomUUID, createHash } from 'node:crypto';
import { verifyReceipt, computeReceiptDigest } from '../dist/index.js';

function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

const now = new Date().toISOString();
const correlationId = randomUUID();
const policyPackId = 'fintech_payment_void_v1';

const receipt = {
  schema: 'liability-receipt/v1',
  receipt_id: randomUUID(),
  issued_at: now,
  issuer: {
    name: 'Kovera',
    product: 'Verified Autonomous Sessions',
    verification_profile: 'aegis/1',
  },
  session: {
    session_id: correlationId,
    correlation_id: correlationId,
    vertical: 'fintech_payments',
    outcome: 'released_after_hitl',
    started_at: now,
    completed_at: now,
  },
  identity: {
    primary_actor: { agent_id: 'Kiosk-Agent-01', actor_class: 'delegated_kiosk' },
    authority: { scoped_role: 'SERVER', permission_id: 'demo-passport' },
    human_release_actor: { agent_id: 'Manager-Agent-01', scoped_role: 'MANAGER' },
  },
  policy: {
    policy_pack_id: policyPackId,
    policy_version_hash: sha256Hex(policyPackId),
    decision: 'released',
  },
  hitl: {
    required: true,
    status: 'signed',
    approval_request_id: randomUUID(),
    release_consumed: true,
  },
  side_effects: {
    action: { tool_name: 'void_transaction', verb: 'void' },
    effect_class: 'financial_void',
    summary: 'Demo void after HITL',
  },
  proof: {
    ledger_spec: 'aegis/1',
    primary_anchor: {
      entry_hash: sha256Hex(`primary:${correlationId}`),
      event_type: 'HITL_ACTION_RELEASED',
      timestamp: now,
    },
    secondary_anchors: [
      {
        entry_hash: sha256Hex(`pending:${correlationId}`),
        event_type: 'HITL_APPROVAL_REQUIRED',
        timestamp: now,
      },
    ],
    verification: { status: 'demo', methods: ['offline_smoke'] },
  },
  diligence_summary: {
    who_acted: 'Agent with manager release',
    what_policy_allowed: 'Policy allowed with HITL',
    what_proof_says: 'Anchored on aegis/1',
  },
};

const digest = computeReceiptDigest(receipt);
receipt.integrity = {
  receipt_digest: digest,
  signature_alg: 'none',
  signature: null,
  manifest_signature_jws: null,
};

const result = verifyReceipt(receipt);
console.log(JSON.stringify(result, null, 2));
process.exit(result.isValid ? 0 : 1);
