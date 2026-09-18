#!/usr/bin/env node
/**
 * CAP export gate policy envelope — James cached-response staleness stamp.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const verifyPkg = join(__dirname, '..');

let passed = 0;
function ok(label, cond) {
  assert.equal(cond, true, label);
  passed += 1;
  console.log(`  ✓ ${label}`);
}

console.log('\nCAP export gate policy envelope\n');

const buildVerify = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', buildVerify.status === 0);

const {
  buildCapExportGatePolicy,
  evaluateCapExportCarrierHandoff,
  evaluateClosureShipGate,
  isCapExportEnvelopeStale,
  isCapExportGatePolicySupported,
  parseCapExportGatePolicyRevision,
  CAP_EXPORT_GATE_POLICY_SCHEMA,
  CAP_EXPORT_GATE_POLICY_VERSION,
  CAP_EXPORT_GATE_POLICY_MIN_SUPPORTED_VERSION,
} = await import('@aevesa/verify');

const defaultPolicy = buildCapExportGatePolicy();
ok('schema', defaultPolicy.schema === CAP_EXPORT_GATE_POLICY_SCHEMA);
ok('version carrier_default_v1', defaultPolicy.version === CAP_EXPORT_GATE_POLICY_VERSION);
ok('min_supported_version set', defaultPolicy.min_supported_version === CAP_EXPORT_GATE_POLICY_MIN_SUPPORTED_VERSION);
ok('default require applied', defaultPolicy.require_carrier_ready_applied === true);
ok('default require default true', defaultPolicy.require_carrier_ready_default === true);
ok('effective_from set', typeof defaultPolicy.effective_from === 'string' && defaultPolicy.effective_from.length >= 10);
ok('stale_body_note mentions min_supported', defaultPolicy.stale_body_note.includes('min_supported_version'));

const optOut = buildCapExportGatePolicy({ require_carrier_ready_applied: false });
ok('opt-out applied false', optOut.require_carrier_ready_applied === false);
ok('opt-out note mentions diagnostic', optOut.stale_body_note.toLowerCase().includes('diagnostic'));

ok('parse v1 revision', parseCapExportGatePolicyRevision('carrier_default_v1') === 1);
ok('parse v2 revision', parseCapExportGatePolicyRevision('carrier_default_v2') === 2);
ok('legacy revision null', parseCapExportGatePolicyRevision('legacy_opt_in_v0') === null);

ok('v1 supported at min v1', isCapExportGatePolicySupported('carrier_default_v1', 'carrier_default_v1') === true);
ok('v2 supported at min v1', isCapExportGatePolicySupported('carrier_default_v2', 'carrier_default_v1') === true);
ok('legacy not supported at min v1', isCapExportGatePolicySupported('legacy_opt_in_v0', 'carrier_default_v1') === false);

const freshEnvelope = {
  generated_at: new Date().toISOString(),
  export_gate_policy: defaultPolicy,
  ok: true,
};
ok('current envelope not stale', isCapExportEnvelopeStale(freshEnvelope) === false);

const futureEnvelope = {
  export_gate_policy: {
    schema: CAP_EXPORT_GATE_POLICY_SCHEMA,
    version: 'carrier_default_v2',
    min_supported_version: CAP_EXPORT_GATE_POLICY_MIN_SUPPORTED_VERSION,
  },
};
ok('future supported version not stale', isCapExportEnvelopeStale(futureEnvelope) === false);

ok('missing policy is stale', isCapExportEnvelopeStale({ ok: true }) === true);
ok('legacy version is stale', isCapExportEnvelopeStale({
  export_gate_policy: { schema: CAP_EXPORT_GATE_POLICY_SCHEMA, version: 'legacy_opt_in_v0' },
}) === true);
ok(
  'self-declared v0 floor is stale (Terra FP-3)',
  isCapExportEnvelopeStale({
    export_gate_policy: {
      schema: CAP_EXPORT_GATE_POLICY_SCHEMA,
      version: 'carrier_default_v0',
      min_supported_version: 'carrier_default_v0',
    },
  }) === true,
);
ok(
  'tampered min below local floor is stale',
  isCapExportEnvelopeStale({
    export_gate_policy: {
      schema: CAP_EXPORT_GATE_POLICY_SCHEMA,
      version: 'carrier_default_v1',
      min_supported_version: 'carrier_default_v0',
    },
  }) === true,
);

console.log('\nCAP export carrier handoff (James bundled fail-closed gate)\n');

const staleBody = { ok: true, session_proof_complete: true };
const staleHandoff = evaluateCapExportCarrierHandoff(staleBody);
ok('stale body refused', staleHandoff.refused === true);
ok('stale body not allowed', staleHandoff.carrier_handoff_allowed === false);
ok('stale reason', staleHandoff.reason === 'stale_export_gate_policy');

ok(
  'forged clear gate without composition_closure refused (Terra FP-1)',
  evaluateCapExportCarrierHandoff({
    ok: true,
    export_gate_policy: defaultPolicy,
    closure_ship_gate: {
      schema: 'aevesa.closure-ship-gate/v1',
      blocked: false,
      carrier_submission_ready: true,
    },
  }).reason === 'missing_composition_closure',
);

const missingClosureHandoff = evaluateCapExportCarrierHandoff({
  ok: true,
  export_gate_policy: defaultPolicy,
});
ok('missing composition_closure refused', missingClosureHandoff.refused === true);
ok('missing composition reason', missingClosureHandoff.reason === 'missing_composition_closure');

/** Incomplete closure (no advisory) must not hand off — derived gate blocks (Terra FP-2). */
const incompleteClosure = {
  schema: 'aevesa.session-composition-closure/v1',
  carrier_review_ready: true,
  closure_verdict: 'carrier_review_ready',
  chain_enforcement: { chain_enforcement_mode: 'enforced' },
};
const incompleteHandoff = evaluateCapExportCarrierHandoff({
  ok: true,
  export_gate_policy: defaultPolicy,
  composition_closure: incompleteClosure,
});
ok('incomplete closure refused', incompleteHandoff.refused === true);
ok('incomplete closure ship_gate_blocked', incompleteHandoff.reason === 'ship_gate_blocked');
ok(
  'incomplete closure refuses as hard as stale',
  incompleteHandoff.refused === staleHandoff.refused &&
    incompleteHandoff.carrier_handoff_allowed === staleHandoff.carrier_handoff_allowed,
);

const blockedGate = evaluateClosureShipGate({
  schema: 'aevesa.session-composition-closure/v1',
  closure_verdict: 'digest_only_submission',
  carrier_review_ready: false,
  receipt_presence: [],
  chain_enforcement: { chain_enforcement_mode: 'enforced' },
  chain_enforcement_advisory: { chain_enforcement_qualified: false },
  channel_provenance_advisory: null,
  composition_guidance: { schema: 'aevesa.session-composition-guidance/v1', headline: 'x' },
  export_hints: null,
  set_completeness_ok: true,
  closure_digest: 'a'.repeat(64),
  note: 'digest only',
});
const blockedClosure = {
  schema: 'aevesa.session-composition-closure/v1',
  closure_verdict: 'digest_only_submission',
  carrier_review_ready: false,
  receipt_presence: [],
  chain_enforcement: { chain_enforcement_mode: 'enforced' },
  chain_enforcement_advisory: { chain_enforcement_qualified: false },
  channel_provenance_advisory: null,
  composition_guidance: { schema: 'aevesa.session-composition-guidance/v1', headline: 'x' },
  export_hints: null,
  set_completeness_ok: true,
  closure_digest: 'a'.repeat(64),
  note: 'digest only',
};
const blockedHandoff = evaluateCapExportCarrierHandoff({
  ok: true,
  export_gate_policy: defaultPolicy,
  composition_closure: blockedClosure,
  closure_ship_gate: blockedGate,
});
ok('blocked ship gate refused', blockedHandoff.refused === true);
ok('blocked ship gate reason', blockedHandoff.reason === 'ship_gate_blocked');

const mismatchHandoff = evaluateCapExportCarrierHandoff({
  ok: true,
  export_gate_policy: defaultPolicy,
  composition_closure: blockedClosure,
  closure_ship_gate: {
    schema: 'aevesa.closure-ship-gate/v1',
    blocked: false,
    carrier_submission_ready: true,
  },
});
ok('gate mismatch refused (Terra FP-1b)', mismatchHandoff.refused === true);
ok('gate mismatch reason', mismatchHandoff.reason === 'closure_ship_gate_mismatch');

const readyClosure = {
  schema: 'aevesa.session-composition-closure/v1',
  closure_verdict: 'carrier_review_ready',
  carrier_review_ready: true,
  receipt_presence: [],
  chain_enforcement: { chain_enforcement_mode: 'enforced' },
  chain_enforcement_advisory: { chain_enforcement_qualified: true },
  channel_provenance_advisory: null,
  composition_guidance: { schema: 'aevesa.session-composition-guidance/v1', headline: 'x' },
  export_hints: null,
  set_completeness_ok: true,
  closure_digest: 'b'.repeat(64),
  note: 'ready',
};
const derivedReadyGate = evaluateClosureShipGate(readyClosure);
const clearHandoff = evaluateCapExportCarrierHandoff({
  ok: true,
  export_gate_policy: defaultPolicy,
  composition_closure: readyClosure,
  closure_ship_gate: derivedReadyGate,
});
ok('clear derived ship gate allowed', clearHandoff.carrier_handoff_allowed === true);
ok('clear handoff not refused', clearHandoff.refused === false);
ok(
  'closure-only body allowed when derived gate clear',
  evaluateCapExportCarrierHandoff({
    ok: true,
    export_gate_policy: defaultPolicy,
    composition_closure: readyClosure,
  }).carrier_handoff_allowed === true,
);

console.log(`\n${passed} checks passed.\n`);
