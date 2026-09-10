#!/usr/bin/env node
/**
 * Generate CAP session proof fixture from bundled portal demo data (no backend DB/signing keys).
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const verifyPkg = join(__dirname, '..');
const repoRoot = join(verifyPkg, '../..');
const fixturePath = join(verifyPkg, 'fixtures/cap-session-proof-demo.json');
const capDemoJsPath = join(repoRoot, 'aevesa-app-site/src/js/capSessionDemoData.js');
const portalDataUrl = pathToFileURL(
  join(repoRoot, 'aevesa-app-site/src/js/setCompletenessDemoData.js'),
).href;

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
if (build.status !== 0) process.exit(build.status ?? 1);

const {
  AEVESA_SET_COMPLETENESS_MANIFEST,
  AEVESA_SET_COMPLETENESS_TERMINAL_RECEIPT,
  AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS,
} = await import(portalDataUrl);

const {
  computeSessionProofDigest,
  verifySessionProof,
  SESSION_PROOF_SCHEMA,
  buildManifestCustodianCommitment,
} = await import('@aevesa/verify');

const witnessEntry = String(
  AEVESA_SET_COMPLETENESS_TERMINAL_RECEIPT?.proof?.primary_anchor?.entry_hash || '',
)
  .trim()
  .toLowerCase();
const manifest_custodian = buildManifestCustodianCommitment({
  session_id: AEVESA_SET_COMPLETENESS_MANIFEST.session_id,
  set_root: AEVESA_SET_COMPLETENESS_MANIFEST.set_root,
  witness_entry_hash: witnessEntry || null,
});

const bundleBody = {
  schema: SESSION_PROOF_SCHEMA,
  session_id: AEVESA_SET_COMPLETENESS_MANIFEST.session_id,
  manifest: AEVESA_SET_COMPLETENESS_MANIFEST,
  terminal_receipt: AEVESA_SET_COMPLETENESS_TERMINAL_RECEIPT,
  member_receipts: AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS,
  manifest_custodian,
};

const bundle = {
  ...bundleBody,
  bundle_digest: computeSessionProofDigest(bundleBody),
};

const verified = verifySessionProof(bundle);
if (!verified.ok) {
  console.error('Fixture failed offline verify:', verified);
  process.exit(1);
}

mkdirSync(dirname(fixturePath), { recursive: true });
writeFileSync(fixturePath, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');
console.log(`Wrote ${fixturePath}`);

const capDemoJs = `/** CAP Phase 3 — compositional accountability session proof (offline portal fallback). */
import {
  AEVESA_SET_COMPLETENESS_MANIFEST,
  AEVESA_SET_COMPLETENESS_TERMINAL_RECEIPT,
  AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS,
} from './setCompletenessDemoData.js';

export const AEVESA_CAP_MANIFEST_CUSTODIAN = ${JSON.stringify(manifest_custodian, null, 2)};

export const AEVESA_CAP_SESSION_PROOF_BUNDLE = ${JSON.stringify(bundle, null, 2)};
`;
writeFileSync(capDemoJsPath, capDemoJs, 'utf8');
console.log(`Wrote ${capDemoJsPath}`);
