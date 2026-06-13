/**
 * Run golden test vectors from kovera-sovereign-ledger-spec.md against the verify engine.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  computeEntryHashFromPreimage,
  computeContextHashFromLinkage,
  buildContextLinkageFromStoredDoc,
  serializeEntryHashInput,
} from '../core/ledgerPreimage.js';
import {
  buildProofOfIntentFromSpecInput,
  computeProofOfIntent,
  digestReasoningText,
} from '../core/proofOfIntent.js';
import {
  hashManifestForSigning,
  signConformityPackManifest,
  verifyConformityPackManifestSignature,
  SPEC_TEST_VECTOR_SIGNING_SECRET,
} from '../core/art12Manifest.js';
import { buildSwarmDelegationTreeFromRows } from '../core/swarmDelegationTree.js';
import { evaluateIntentAlignment } from '../core/intentAlignment.js';
import {
  GOLDEN_VECTORS,
  extractSpecDocumentHashes,
  findSpecJsonBlocksForSection,
} from './goldenVectors.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_SPEC_PATH = path.resolve(__dirname, '../../../../docs/spec/kovera-sovereign-ledger-spec.md');

/**
 * @typedef {{ name: string, pass: boolean, detail?: string }} VectorResult
 */

/**
 * @param {{ specPath?: string, silent?: boolean }} [opts]
 * @returns {{ ok: boolean, results: VectorResult[], specPath: string }}
 */
export function runSpecVectors(opts = {}) {
  const specPath = opts.specPath ?? DEFAULT_SPEC_PATH;
  /** @type {VectorResult[]} */
  const results = [];

  // §3.6.1 — golden ledger row
  const g = GOLDEN_VECTORS.aegis.golden;
  const entryHash = computeEntryHashFromPreimage(g.preimage);
  results.push({
    name: `${g.id} entryHash`,
    pass: entryHash === g.expected.entryHash,
    detail: entryHash,
  });

  const linkageDoc = {
    agentId: g.preimage.agentId,
    eventType: g.preimage.eventType,
    severity: g.preimage.severity,
    payload: g.preimage.payload,
    timestamp: g.preimage.timestamp,
  };
  const linkage = buildContextLinkageFromStoredDoc(linkageDoc);
  const contextHash = computeContextHashFromLinkage('GENESIS', linkage);
  results.push({
    name: `${g.id} contextHash_from_GENESIS`,
    pass: contextHash === g.expected.contextHash_from_GENESIS,
    detail: contextHash,
  });

  // §3.6.2 — tampered payload mismatch
  const tamperedPreimage = {
    ...g.preimage,
    payload: { ...g.preimage.payload, toolName: 'payments.TAMPERED' },
  };
  const tamperedHash = computeEntryHashFromPreimage(tamperedPreimage);
  results.push({
    name: `${GOLDEN_VECTORS.aegis.tampered.id} tampered entryHash`,
    pass: tamperedHash === GOLDEN_VECTORS.aegis.tampered.recomputedEntryHash,
    detail: tamperedHash,
  });
  results.push({
    name: `${GOLDEN_VECTORS.aegis.tampered.id} stored vs recomputed differ`,
    pass: tamperedHash !== GOLDEN_VECTORS.aegis.tampered.storedEntryHash,
  });

  // §3.6.3 — legacy binding must not inject proofOfIntent key
  const legacyBinding = GOLDEN_VECTORS.aegis.legacy.governanceBinding;
  const legacyPreimage = {
    ...g.preimage,
    governanceBinding: legacyBinding,
  };
  const legacySerialized = serializeEntryHashInput(legacyPreimage);
  results.push({
    name: `${GOLDEN_VECTORS.aegis.legacy.id} no proofOfIntent key in serialization`,
    pass: !legacySerialized.includes('"proofOfIntent"'),
    detail: legacySerialized.slice(0, 120),
  });

  // §4.7.1 — proof-of-intent golden
  const poi = GOLDEN_VECTORS.proofOfIntent.golden;
  const poiBuilt = buildProofOfIntentFromSpecInput(poi.input);
  results.push({
    name: `${poi.id} proofOfIntent hash`,
    pass: poiBuilt.proofOfIntent === poi.expectedHash,
    detail: poiBuilt.proofOfIntent,
  });
  results.push({
    name: `${poi.id} reasoningDigest`,
    pass: poiBuilt.envelope.reasoningPath.reasoningDigest === poi.expectedReasoningDigest,
  });

  // §4.7.2 — causal binding
  const causal = GOLDEN_VECTORS.proofOfIntent.causal;
  const causalBuilt = buildProofOfIntentFromSpecInput(causal.input);
  results.push({
    name: `${causal.id} causal proofOfIntent`,
    pass: causalBuilt.proofOfIntent === causal.expectedHash,
    detail: causalBuilt.proofOfIntent,
  });
  results.push({
    name: `${causal.id} causalBinding present`,
    pass: Boolean(causalBuilt.envelope.causalBinding?.parentEntryHash),
  });

  // §4.7.3 — tampered envelope
  const tamperedEnvelope = JSON.parse(JSON.stringify(causalBuilt.envelope));
  tamperedEnvelope.reasoningPath.divergenceScore = 0.99;
  const tamperedPoi = computeProofOfIntent(tamperedEnvelope);
  results.push({
    name: `${GOLDEN_VECTORS.proofOfIntent.tampered.id} tampered recomputed`,
    pass: tamperedPoi === GOLDEN_VECTORS.proofOfIntent.tampered.recomputedAfterTamper,
  });
  results.push({
    name: `${GOLDEN_VECTORS.proofOfIntent.tampered.id} differs from stored`,
    pass: tamperedPoi !== GOLDEN_VECTORS.proofOfIntent.tampered.storedProofOfIntent,
  });

  // §5.5.1 — swarm tree
  const swarm = GOLDEN_VECTORS.swarm.golden;
  const tree = buildSwarmDelegationTreeFromRows(swarm.rootSessionId, swarm.rows);
  results.push({
    name: `${swarm.id} schema`,
    pass: tree.schema === swarm.expected.schema,
  });
  results.push({
    name: `${swarm.id} nodeCount`,
    pass: tree.nodeCount === swarm.expected.nodeCount,
  });
  results.push({
    name: `${swarm.id} edgeCount`,
    pass: tree.edgeCount === swarm.expected.edgeCount,
  });
  results.push({
    name: `${swarm.id} delegation edge`,
    pass: JSON.stringify(tree.edges) === JSON.stringify(swarm.expected.edges),
  });
  const rootNode = tree.nodes.find((n) => n.sessionId === 'root-swarm-001');
  const workerNode = tree.nodes.find((n) => n.sessionId === 'worker-session-001');
  results.push({
    name: `${swarm.id} root isRoot`,
    pass: rootNode?.isRoot === true && rootNode?.parentSessionId === null,
  });
  results.push({
    name: `${swarm.id} worker parent anchor`,
    pass:
      workerNode?.parentSessionId === 'root-swarm-001' &&
      workerNode?.anchorEntryHash === 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  });

  // §6.6.1 — art12 manifest signing
  const art12 = GOLDEN_VECTORS.art12.golden;
  const manifestHash = hashManifestForSigning(art12.manifest);
  results.push({
    name: `${art12.id} manifestSha256`,
    pass: manifestHash === art12.expectedManifestSha256,
    detail: manifestHash,
  });
  const sig = signConformityPackManifest(art12.manifest, SPEC_TEST_VECTOR_SIGNING_SECRET);
  results.push({
    name: `${art12.id} signature`,
    pass: sig.signature === art12.expectedSignature,
  });
  const verifyOk = verifyConformityPackManifestSignature(art12.manifest, sig, SPEC_TEST_VECTOR_SIGNING_SECRET);
  results.push({
    name: `${art12.id} verify PASS`,
    pass: verifyOk.ok === true,
  });

  // §6.6.2 — tampered manifest
  const tamperedManifest = {
    ...art12.manifest,
    session_id: 'spec-session-TAMPERED',
  };
  const tamperedSig = signConformityPackManifest(art12.manifest, SPEC_TEST_VECTOR_SIGNING_SECRET);
  const tamperedVerify = verifyConformityPackManifestSignature(tamperedManifest, tamperedSig, SPEC_TEST_VECTOR_SIGNING_SECRET);
  results.push({
    name: `${GOLDEN_VECTORS.art12.tamperedManifest.id} MANIFEST_HASH_MISMATCH`,
    pass: tamperedVerify.ok === false && tamperedVerify.reason === GOLDEN_VECTORS.art12.tamperedManifest.reason,
  });

  // Cross-check: spec document contains expected golden hashes
  if (fs.existsSync(specPath)) {
    const markdown = fs.readFileSync(specPath, 'utf8');
    const docHashes = extractSpecDocumentHashes(markdown);
    const requiredHashes = [
      g.expected.entryHash,
      g.expected.contextHash_from_GENESIS,
      GOLDEN_VECTORS.aegis.tampered.recomputedEntryHash,
      poi.expectedHash,
      poi.expectedReasoningDigest,
      causal.expectedHash,
      GOLDEN_VECTORS.proofOfIntent.tampered.recomputedAfterTamper,
      art12.expectedManifestSha256,
    ];
    for (const hash of requiredHashes) {
      results.push({
        name: `spec-doc contains ${hash.slice(0, 12)}…`,
        pass: docHashes.has(hash.toLowerCase()),
      });
    }

    // Parse markdown JSON blocks for §3.6.1 output
    const blocks361 = findSpecJsonBlocksForSection(markdown, '3.6.1');
    const outputBlock = blocks361.find((b) => b.entryHash != null);
    if (outputBlock) {
      results.push({
        name: 'spec-parse 3.6.1 entryHash matches engine',
        pass: outputBlock.entryHash === entryHash,
      });
    } else {
      results.push({ name: 'spec-parse 3.6.1 output block', pass: false, detail: 'not found' });
    }
  } else {
    results.push({
      name: 'spec document present',
      pass: false,
      detail: `missing: ${specPath}`,
    });
  }

  // NO_REASONING_DIGEST sanity
  results.push({
    name: 'reasoningDigest spec string',
    pass: digestReasoningText('Transfer funds to vendor per approved invoice') === poi.expectedReasoningDigest,
  });

  const ia = GOLDEN_VECTORS.intentAlignment;
  for (const key of ['aligned', 'elevated', 'critical']) {
    const vec = ia[key];
    const out = evaluateIntentAlignment(vec.intentContext, vec.payload);
    results.push({
      name: `${vec.id} intentAlignment score`,
      pass: out.score === vec.expected.score,
      detail: `got ${out.score}`,
    });
    results.push({
      name: `${vec.id} intentAlignment level`,
      pass: out.level === vec.expected.level,
      detail: `got ${out.level}`,
    });
    const expectedSignals = vec.expected.signals || [];
    const signalsMatch =
      expectedSignals.every((s) => out.signals.includes(s)) &&
      (key === 'aligned' ? out.signals.length === 0 : out.signals.length >= expectedSignals.length);
    results.push({
      name: `${vec.id} intentAlignment signals`,
      pass: signalsMatch,
      detail: `got [${out.signals.join(', ')}]`,
    });
  }

  const perfIters = 500;
  const perfVec = ia.aligned;
  const perfStart = performance.now();
  for (let i = 0; i < perfIters; i += 1) {
    evaluateIntentAlignment(perfVec.intentContext, perfVec.payload);
  }
  const perfMs = (performance.now() - perfStart) / perfIters;
  results.push({
    name: '7.1.x intentAlignment perf budget',
    pass: perfMs < ia.performanceBudgetMs,
    detail: `${perfMs.toFixed(4)}ms avg (budget ${ia.performanceBudgetMs}ms)`,
  });

  const ok = results.every((r) => r.pass);
  if (!opts.silent) {
    for (const r of results) {
      const mark = r.pass ? 'OK' : 'FAIL';
      const line = r.detail ? `${mark} ${r.name} — ${r.detail}` : `${mark} ${r.name}`;
      if (r.pass) console.log(line);
      else console.error(line);
    }
    console.log(ok ? `\nSpec vectors: ${results.length}/${results.length} PASS` : `\nSpec vectors: FAILED`);
  }

  return { ok, results, specPath };
}
