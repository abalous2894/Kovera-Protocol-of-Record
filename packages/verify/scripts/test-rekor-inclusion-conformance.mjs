#!/usr/bin/env node
/**
 * Wave 15 Track B-PR3 — Rekor RFC 6962 inclusion proof offline verify conformance.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  REKOR_INCLUSION_PROOF_REQUIRED,
  REKOR_INCLUSION_DIGEST_MISMATCH,
  REKOR_INCLUSION_PROOF_SCHEMA,
  computeRfc6962RootFromInclusionProof,
  rfc6962LeafHash,
  rfc6962NodeHash,
  verifyRekorCryptoInclusionProof,
} from '../src/witness/rekorInclusionVerify.js';
import {
  verifyExternalRekorWitness,
  verifyExternalRekorWitnessWithInclusion,
  verifyScittRefusalWitnessBundle,
  resolveRequireRekorInclusionProof,
} from '../src/witness/witnessInclusionVerify.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'fixtures');
const demoFixture = JSON.parse(readFileSync(join(fixturesDir, 'rekor-inclusion-proof-demo.json'), 'utf8'));
const scittExport = JSON.parse(readFileSync(join(fixturesDir, 'scitt-live-witness-export.json'), 'utf8'));

let passed = 0;
function ok(label, cond, detail = '') {
  assert.equal(cond, true, detail || label);
  passed += 1;
}

assert.equal(demoFixture.proof.schema, REKOR_INCLUSION_PROOF_SCHEMA);

const cryptoOk = verifyRekorCryptoInclusionProof(demoFixture.proof);
ok('demo inclusion proof crypto valid', cryptoOk.ok, cryptoOk.errors.join('; '));
ok('demo root matches proof', cryptoOk.checks.rootMatchesProof === true);
ok('demo checkpoint root matches', cryptoOk.checks.checkpointRootMatches === true);

const digestBound = verifyRekorCryptoInclusionProof(demoFixture.proof, {
  expectedStatementDigest: demoFixture.metadata.digest,
});
ok('digest-bound crypto valid', digestBound.ok === true, digestBound.errors.join('; '));
ok('entry body digest binding', digestBound.checks.entryBodyDigestBinding === true);

const digestMismatch = verifyRekorCryptoInclusionProof(demoFixture.proof, {
  expectedStatementDigest: 'f'.repeat(64),
});
ok('digest mismatch fails closed', digestMismatch.ok === false);
ok('digest mismatch code', digestMismatch.codes.includes(REKOR_INCLUSION_DIGEST_MISMATCH));

const metadataOnly = verifyExternalRekorWitnessWithInclusion(
  demoFixture.metadata,
  demoFixture.metadata.digest,
);
ok('metadata-only witness passes without crypto', metadataOnly.ok === true);
ok('metadata-only has no inclusion_crypto', metadataOnly.inclusion_crypto == null);

const requireCrypto = verifyExternalRekorWitnessWithInclusion(
  demoFixture.metadata,
  demoFixture.metadata.digest,
  null,
  { requireInclusionProof: true },
);
ok('requireInclusionProof fails closed', requireCrypto.ok === false);
ok('requireInclusionProof code', requireCrypto.codes.includes(REKOR_INCLUSION_PROOF_REQUIRED));

const full = verifyExternalRekorWitnessWithInclusion(
  demoFixture.metadata,
  demoFixture.metadata.digest,
  demoFixture.proof,
);
ok('metadata + crypto passes', full.ok === true, full.errors.join('; '));
ok('inclusion crypto ok', full.inclusion_crypto?.ok === true);

const tampered = verifyRekorCryptoInclusionProof({
  ...demoFixture.proof,
  root_hash: '0'.repeat(64),
});
ok('tampered root fails', tampered.ok === false);

const bodyBytes = Buffer.from('rekor-test-entry-0', 'utf8');
const leaf0 = rfc6962LeafHash(bodyBytes);
const leaf1 = rfc6962LeafHash(Buffer.from('rekor-test-entry-1', 'utf8'));
const leaf2 = rfc6962LeafHash(Buffer.from('rekor-test-entry-2', 'utf8'));
const leaf3 = rfc6962LeafHash(Buffer.from('rekor-test-entry-3', 'utf8'));
const node01 = rfc6962NodeHash(leaf0, leaf1);
const node23 = rfc6962NodeHash(leaf2, leaf3);
const root = rfc6962NodeHash(node01, node23);
const recompute = computeRfc6962RootFromInclusionProof({
  leafIndex: 0,
  treeSize: 4,
  leafHashHex: leaf0,
  hashesHex: [leaf1, node23],
});
ok('RFC6962 recompute ok', recompute.ok === true);
ok('RFC6962 root matches tree', recompute.rootHex === root);

ok('legacy metadata verify', verifyExternalRekorWitness(demoFixture.metadata, demoFixture.metadata.digest).ok === true);

const scittFull = verifyScittRefusalWitnessBundle(scittExport);
ok('scitt-live export bundle verifies offline', scittFull.ok === true);
ok('scitt-live Rekor metadata valid', scittFull.checks.externalRekorValid === true);
ok('scitt-live Rekor inclusion crypto valid', scittFull.checks.externalRekorInclusionCrypto === true);

const metadataOnlyExport = {
  ...scittExport,
  rekorInclusionProof: undefined,
  witnesses: (scittExport.witnesses ?? []).map((witness) => {
    if (witness?.type !== 'rekor' && witness?.schema !== 'aevesa.witness.rekor-metadata/v1') {
      return witness;
    }
    const { rekor_inclusion_proof: _removed, inclusion_proof: _removed2, ...rest } = witness;
    return rest;
  }),
  externalTransparencyService: {
    ...scittExport.externalTransparencyService,
    rekor: scittExport.externalTransparencyService?.rekor
      ? (({ rekor_inclusion_proof: _r, inclusion_proof: _i, ...rest }) => rest)(
          scittExport.externalTransparencyService.rekor,
        )
      : undefined,
    rekor_inclusion_proof: undefined,
  },
};
const scittMetadataOnly = verifyScittRefusalWitnessBundle(metadataOnlyExport);
ok('metadata-only scitt export still passes (legacy)', scittMetadataOnly.ok === true);
ok('metadata-only no Rekor crypto check', scittMetadataOnly.checks.externalRekorInclusionCrypto == null);

const claimedInclusionWithoutCrypto = {
  ...metadataOnlyExport,
  proof_strength_disclosure: {
    schema: 'aevesa.proof-strength-disclosure/v1',
    external_transparency: 'rekor_inclusion_verified',
  },
};
ok(
  'proof_strength rekor_inclusion_verified requires crypto',
  resolveRequireRekorInclusionProof(claimedInclusionWithoutCrypto) === true,
);
const scittFailClosed = verifyScittRefusalWitnessBundle(claimedInclusionWithoutCrypto);
ok('claimed inclusion without crypto fails closed', scittFailClosed.ok === false);
ok(
  'fail-closed emits REKOR_INCLUSION_PROOF_REQUIRED',
  scittFailClosed.externalRekorVerification?.codes?.includes(REKOR_INCLUSION_PROOF_REQUIRED) === true,
);

const claimedWithCrypto = {
  ...scittExport,
  proof_strength_disclosure: {
    schema: 'aevesa.proof-strength-disclosure/v1',
    external_transparency: 'rekor_inclusion_verified',
  },
};
const scittClaimedPass = verifyScittRefusalWitnessBundle(claimedWithCrypto);
ok('claimed inclusion with bundled crypto passes', scittClaimedPass.ok === true);

console.log(`rekor inclusion conformance OK (${passed} checks)`);
