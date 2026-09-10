#!/usr/bin/env node
/**
 * Generate packages/verify/fixtures/policy-proof-deny-bundle.json
 */
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, createHash } from 'node:crypto';
import { computeReceiptDigest } from '../dist/index.js';
import { evaluatePathFromFacts } from '../src/policy/evaluatePathFromFacts.js';
import { computePolicyProofDigest } from '../src/policy/policyProofVerify.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const out = join(__dirname, '../fixtures/policy-proof-deny-bundle.json');

const sessionId = 'policy-proof-read-chain-export-deny';
const proposedTool = 'export_data';
const maxReads = 3;

const facts = [`session("${sessionId}").`, `step_count("${sessionId}", 4).`];
for (let i = 0; i < 4; i += 1) {
  facts.push(`step("${sessionId}", ${i}, "read_file", "ALLOW").`);
  facts.push(`read_class("${sessionId}", ${i}, "read_file").`);
}
facts.push(`read_count("${sessionId}", 4).`);
facts.push(`proposed("${sessionId}", "${proposedTool}").`);
facts.push(`export_class("${proposedTool}").`);

const parsed = {
  sessionId,
  steps: Array.from({ length: 4 }, () => ({ toolName: 'read_file', verdict: 'ALLOW' })),
  readCount: 4,
  stepCount: 4,
  proposedTool,
  destructiveBurst: null,
};

const reevaluation = evaluatePathFromFacts(parsed, proposedTool, { maxReadsBeforeDestructive: maxReads });
const partialPathMaterial = {
  schema: 'aevesa.partial-path/v1',
  session_id: sessionId,
  proposed_action: proposedTool,
  step_index: 4,
  read_count_prior: 4,
  path_digest: createHash('sha256')
    .update(JSON.stringify({ sessionId, proposedTool, stepCount: 4, last: 'read_file' }), 'utf8')
    .digest('hex'),
  partial_steps: parsed.steps.map((s, i) => ({
    index: i,
    tool_name: s.toolName,
    verdict: s.verdict,
    entry_hash: null,
  })),
};
const partial_path_hash = createHash('sha256').update(JSON.stringify(partialPathMaterial), 'utf8').digest('hex');

const now = '2026-08-26T12:00:00.000Z';
const entryHash = createHash('sha256').update(`policy-proof:${sessionId}`, 'utf8').digest('hex');

/** @type {Record<string, unknown>} */
const receipt = {
  schema: 'liability-receipt/v1',
  receipt_id: randomUUID(),
  issued_at: now,
  issuer: {
    name: 'Aevesa',
    product: 'Verified Autonomous Sessions',
    verification_profile: 'aegis/1+proof-of-intent',
    organization_display_name: 'Kaptein Path Policy',
  },
  session: {
    session_id: sessionId,
    correlation_id: sessionId,
    vertical: 'enterprise_ops',
    outcome: 'blocked',
    started_at: now,
    completed_at: now,
  },
  identity: {
    primary_actor: { agent_id: 'policy-proof-demo-agent', actor_class: 'autonomous_agent' },
    authority: { scoped_role: 'SERVER', permission_id: 'apor-path-policy' },
  },
  policy: {
    policy_pack_id: 'kaptein_path_v1',
    policy_version_hash: createHash('sha256').update('kaptein_path_v1', 'utf8').digest('hex'),
    decision: 'deny',
  },
  hitl: { required: false, status: 'not_required' },
  side_effects: {
    action: { tool_name: proposedTool, verb: 'invoke', target_path: '/warehouse/analytics' },
    effect_class: 'data_access',
    summary: reevaluation.message,
    blocked_reason: reevaluation.message,
  },
  proof: {
    ledger_spec: 'aegis/1',
    primary_anchor: {
      entry_hash: entryHash,
      event_type: 'PATH_POLICY_BLOCKED',
      timestamp: now,
    },
    verification: {
      status: 'verified',
      methods: ['path_aware_policy', 'kaptein_path_policies', 'partial_path_binding'],
      verified_at: now,
    },
  },
  diligence_summary: {
    who_acted: 'Agent attempted export after read chain.',
    what_policy_allowed: 'Kaptein read-chain-export-deny path policy.',
    what_proof_says: `Path blocked with ${reevaluation.code}.`,
  },
  denial: {
    pre_execution: true,
    execution_occurred: false,
    denial_stage: 'runtime_firewall',
    source: 'apor_path_policy',
  },
  partial_path: { ...partialPathMaterial, partial_path_hash },
  _meta: { generated_by: 'policy-proof-fixture-generator', source_entry_hash: entryHash },
};

receipt.integrity = {
  receipt_digest: computeReceiptDigest(receipt),
  signature_alg: 'none',
  signature: null,
  manifest_signature_jws: null,
};

const policyPack = {
  schema: 'aevesa.kaptein-path-policies/v1',
  version: '2026.09',
  policies: [
    {
      id: 'read-chain-export-deny',
      name: 'Read chain then export — deny',
      engine_code: 'PATH_READ_VELOCITY_DESTRUCTIVE',
      datalog_rule:
        'deny(S, export) :- session(S), read_count(S, N), N >= 3, proposed(S, export), export_class(export).',
      eu_ai_act_framing: 'Art. 15 — unauthorized data egress from high-risk agent session',
    },
  ],
};

const bundle = {
  schema: 'aevesa.policy-proof-bundle/v1',
  generated_at: now,
  policy_params: { max_reads_before_destructive: maxReads },
  datalog_export: {
    schema: 'aevesa.path-datalog-export/v1',
    session_id: sessionId,
    fact_count: facts.length,
    facts,
    policy_evaluation: {
      allow: reevaluation.allow,
      code: reevaluation.code,
      message: reevaluation.message,
      matched_policies: [{ id: 'read-chain-export-deny', name: 'Read chain then export — deny' }],
      policy_pack_schema: 'aevesa.kaptein-path-policies/v1',
    },
  },
  policy_pack: policyPack,
  receipt,
  verify_hint: 'aevesa policy-proof <this-file.json>',
};

bundle.proof_digest = computePolicyProofDigest(bundle);

writeFileSync(out, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');
console.log(`Wrote ${out}`);
