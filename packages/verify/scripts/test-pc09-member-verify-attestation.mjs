#!/usr/bin/env node
/**
 * James PC-09 — member verify attestation + composed pack witness path.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const verifyPkg = join(__dirname, '..');
const repoRoot = join(verifyPkg, '../..');

let passed = 0;
function ok(label, cond) {
  assert.equal(cond, true, label);
  passed += 1;
  console.log(`  ✓ ${label}`);
}

console.log('\nJames PC-09 — member verify attestation conformance\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const {
  buildMemberVerifyAttestationDocument,
  verifyMemberVerifyAttestation,
  resolveComposedMemberVerifyState,
  verifyCarrierUnderwritingEvidencePack,
  verifyShutdownDrillBundle,
  CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA,
} = await import('@aevesa/verify');

const SHUTDOWN_DRILL_SCHEMA = 'aevesa.shutdown-drill-bundle/v1';

function witnessCosignForDigest(attestationDigest) {
  return {
    witnessed: true,
    ok: true,
    cosign: {
      fragment: {
        schema: 'aevesa.receipt-cosign-fragment/v1',
        receipt_digest: attestationDigest,
        party: 'witness',
        role: 'member_verify_attestation',
        signed_at: '2026-09-12T18:00:00.000Z',
        signature_alg: 'hmac-sha256',
        signature: 'demo-signature-not-checked-offline',
      },
    },
  };
}

const memberDigest = 'a'.repeat(64);
const attestationBody = buildMemberVerifyAttestationDocument(
  {
    member_schema: CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA,
    member_digest: memberDigest,
    verify_ok: true,
    verify_result_schema: 'aevesa-carrier-underwriting-evidence-pack-v1',
    verified_at: '2026-09-12T18:00:00.000Z',
  },
  witnessCosignForDigest(
    buildMemberVerifyAttestationDocument({
      member_schema: CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA,
      member_digest: memberDigest,
      verify_ok: true,
      verify_result_schema: 'aevesa-carrier-underwriting-evidence-pack-v1',
      verified_at: '2026-09-12T18:00:00.000Z',
    }).attestation_digest,
  ),
);

const attestation = {
  ...attestationBody,
  witness_cosign: witnessCosignForDigest(attestationBody.attestation_digest),
};

const attVerify = verifyMemberVerifyAttestation(attestation, {
  expected_member_schema: CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA,
  expected_member_digest: memberDigest,
  requireWitnessCosign: true,
});
ok('attestation with witness cosign verifies', attVerify.ok === true);

const tampered = {
  ...attestation,
  verify_ok: false,
};
ok('tampered verify_ok fails digest', verifyMemberVerifyAttestation(tampered).ok === false);

const resolution = resolveComposedMemberVerifyState({
  members: [
    {
      member_schema: CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA,
      member_digest: memberDigest,
      verify_ok: true,
    },
    {
      member_schema: SHUTDOWN_DRILL_SCHEMA,
      member_digest: 'b'.repeat(64),
      verify_ok: true,
    },
  ],
  member_documents: {},
  member_verify_attestations: {
    [CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA]: attestation,
  },
  resolveMemberDocument: () => null,
  recomputeMemberVerifyOk: () => false,
});
ok('attestation path marks carrier member verified', resolution.members[0].verify_ok === true);
ok('attestation source recorded', resolution.members[0].verify_source === 'witness_attestation');
ok('missing attestation member not verified', resolution.members[1].verify_ok === false);
ok('member proof present with partial attestations', resolution.memberAttestationsPresent === true);

const demoPath = join(repoRoot, 'private-backend/scripts/test-carrier-mga-acceptance-conformance.mjs');
if (readFileSync(demoPath, 'utf8').includes('member_documents')) {
  ok('carrier MGA conformance script exists', true);
}

const carrierPackVerify = (await import('@aevesa/verify')).verifyCarrierMgaAcceptanceKit;
const hashOnlyKit = {
  schema: 'aevesa.carrier-mga-acceptance-kit/v1',
  organization_id: 'org-pc09',
  generated_at: '2026-09-12T18:00:00.000Z',
  composed_members: [
    {
      member_schema: CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA,
      member_digest: memberDigest,
      verify_ok: true,
      label: 'carrier',
    },
    {
      member_schema: SHUTDOWN_DRILL_SCHEMA,
      member_digest: 'b'.repeat(64),
      verify_ok: true,
      label: 'drill',
    },
  ],
  member_verify_attestations: {
    [CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA]: attestation,
  },
  submission_cadence: {
    cadence: 'quarterly',
    period_label: '2026-Q3',
    next_resubmission_due: '2026-12-01T00:00:00.000Z',
    kill_switch_drill_max_age_days: 90,
    kill_switch_drill_digest: 'b'.repeat(64),
    carrier_pack_digest: memberDigest,
    drill_fresh_for_submission: true,
  },
  mga_acceptance_assertions: {
    six_controls_ready: true,
    kill_switch_drill_fresh: true,
    executive_attestation_bound: true,
    broker_submission_ready: true,
    mga_acceptance_readiness: 'ready',
  },
  pack_digest: 'c'.repeat(64),
};
const partialKitVerify = carrierPackVerify(hashOnlyKit);
ok('hash-only kit without full proof fails closed', partialKitVerify.ok === false);
ok(
  'hash-only kit note mentions PC-09',
  String(partialKitVerify.note || '').includes('member_verify_attestations') ||
    String(partialKitVerify.note || '').includes('member_documents'),
);

console.log(`\n${passed} checks passed.\n`);
