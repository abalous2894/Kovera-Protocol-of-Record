#!/usr/bin/env node
/**
 * James PC-09 — composed pack attestation rollout (cross-platform + attested set).
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const verifyPkg = join(__dirname, '..');

let passed = 0;
function ok(label, cond) {
  assert.equal(cond, true, label);
  passed += 1;
  console.log(`  ✓ ${label}`);
}

console.log('\nJames PC-09 — composed pack attestation rollout\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const {
  buildMemberVerifyAttestationDocument,
  verifyMemberVerifyAttestation,
  verifyCrossPlatformConductPack,
  verifyAttestedEvidenceSet,
  buildAttestedEvidenceSetDocument,
  extractComposedPackProofLayers,
  hashOnlyComposedPackSurface,
  CROSS_PLATFORM_CONDUCT_PACK_SCHEMA,
} = await import('@aevesa/verify');

const AGT_SCHEMA = 'aevesa.agt-conduct-receipt/v1';
const AP2_SCHEMA = 'aevesa.ap2-conduct-receipt/v1';
const MANIFEST_SCHEMA = 'aevesa.traceable-conduct-manifest/v1';

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

function buildWitnessAttestation(memberSchema, memberDigest) {
  const attestationBody = buildMemberVerifyAttestationDocument(
    {
      member_schema: memberSchema,
      member_digest: memberDigest,
      verify_ok: true,
      verify_result_schema: memberSchema,
      verified_at: '2026-09-12T18:00:00.000Z',
    },
    witnessCosignForDigest(
      buildMemberVerifyAttestationDocument({
        member_schema: memberSchema,
        member_digest: memberDigest,
        verify_ok: true,
        verify_result_schema: memberSchema,
        verified_at: '2026-09-12T18:00:00.000Z',
      }).attestation_digest,
    ),
  );
  return {
    ...attestationBody,
    witness_cosign: witnessCosignForDigest(attestationBody.attestation_digest),
  };
}

const agtDigest = 'a'.repeat(64);
const ap2Digest = 'b'.repeat(64);
const manifestDigest = 'c'.repeat(64);

const hashOnlyConductPack = {
  schema: CROSS_PLATFORM_CONDUCT_PACK_SCHEMA,
  organization_id: 'org-pc09-rollout',
  generated_at: '2026-09-12T18:00:00.000Z',
  cross_platform_assertions: {
    agt_normalized_to_ap2: true,
    session_correlation_bound: true,
    multi_vendor_conduct_unified: true,
    third_party_verifiable: true,
    cross_platform_readiness: 'unified',
  },
  composed_members: [
    { member_schema: AGT_SCHEMA, member_digest: agtDigest, verify_ok: true, label: 'agt' },
    { member_schema: AP2_SCHEMA, member_digest: ap2Digest, verify_ok: true, label: 'ap2' },
    {
      member_schema: MANIFEST_SCHEMA,
      member_digest: manifestDigest,
      verify_ok: true,
      label: 'manifest',
    },
  ],
  vendor_session_binding: {
    session_id: 'sess-1',
    correlation_id: 'corr-1',
    vendor_planes: ['agt', 'ap2'],
    agt_receipt_digest: agtDigest,
    ap2_conduct_digest: ap2Digest,
    conduct_manifest_digest: manifestDigest,
    normalization_bound: true,
  },
  pack_digest: 'd'.repeat(64),
};

const noProofResult = verifyCrossPlatformConductPack(hashOnlyConductPack);
ok('cross-platform hash-only without proof fails closed', noProofResult.ok === false);
ok(
  'cross-platform note mentions PC-09 proof path',
  String(noProofResult.note || '').includes('member_verify_attestations') ||
    String(noProofResult.note || '').includes('member_documents'),
);
ok('cross-platform memberProofPresent false without proof', noProofResult.checks.memberProofPresent === false);

const attestedConductPack = {
  ...hashOnlyConductPack,
  member_verify_attestations: {
    [AGT_SCHEMA]: buildWitnessAttestation(AGT_SCHEMA, agtDigest),
    [AP2_SCHEMA]: buildWitnessAttestation(AP2_SCHEMA, ap2Digest),
    [MANIFEST_SCHEMA]: buildWitnessAttestation(MANIFEST_SCHEMA, manifestDigest),
  },
};
const attestedConductResult = verifyCrossPlatformConductPack(attestedConductPack);
ok(
  'cross-platform attestation path sets memberProofPresent',
  attestedConductResult.checks.memberProofPresent === true,
);
ok(
  'cross-platform attestation path sets memberAttestationsPresent',
  attestedConductResult.checks.memberAttestationsPresent === true,
);

const { memberDocs, memberAttestations } = extractComposedPackProofLayers(attestedConductPack);
ok('extractComposedPackProofLayers returns attestations', Object.keys(memberAttestations).length === 3);
ok('extractComposedPackProofLayers omits member docs when absent', Object.keys(memberDocs).length === 0);

const conductMemberDigest = 'e'.repeat(64);
const attestation = buildWitnessAttestation(CROSS_PLATFORM_CONDUCT_PACK_SCHEMA, conductMemberDigest);
ok(
  'witness attestation verifies offline',
  verifyMemberVerifyAttestation(attestation, {
    expected_member_schema: CROSS_PLATFORM_CONDUCT_PACK_SCHEMA,
    expected_member_digest: conductMemberDigest,
    requireWitnessCosign: true,
  }).ok === true,
);

const evidenceSetBody = buildAttestedEvidenceSetDocument({
  organization_id: 'org-pc09',
  period_label: '2026-Q3',
  generated_at: '2026-09-12T18:00:00.000Z',
  members: [
    {
      member_schema: CROSS_PLATFORM_CONDUCT_PACK_SCHEMA,
      member_digest: conductMemberDigest,
      label: 'conduct',
      verify_ok: true,
    },
  ],
});

const noProofSet = verifyAttestedEvidenceSet(evidenceSetBody);
ok('attested evidence set without proof fails closed', noProofSet.ok === false);
ok(
  'attested evidence set PC-09 note',
  String(noProofSet.note || '').includes('member_verify_attestations') ||
    String(noProofSet.note || '').includes('member_documents'),
);

const attestedSet = {
  ...evidenceSetBody,
  member_verify_attestations: {
    [CROSS_PLATFORM_CONDUCT_PACK_SCHEMA]: attestation,
  },
};
const attestedSetResult = verifyAttestedEvidenceSet(attestedSet);
ok(
  'attested evidence set witness attestation sets memberProofPresent',
  attestedSetResult.checks.memberProofPresent === true,
);
ok('attested evidence set memberAttestationsPresent', attestedSetResult.checks.memberAttestationsPresent === true);

ok('hashOnlyComposedPackSurface export callable', typeof hashOnlyComposedPackSurface === 'function');
ok(
  'hashOnlyComposedPackSurface strips proof layers',
  hashOnlyComposedPackSurface(attestedConductPack, () => false) === true,
);

console.log(`\n${passed} checks passed.\n`);
