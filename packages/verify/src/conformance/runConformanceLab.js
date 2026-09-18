/**
 * Aevesa Conformance Lab runner — probe any deployment + local offline interop.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyReceipt, verifyReceiptDigestMatch } from '../../dist/index.js';
import { validateConformanceLabManifest } from '../compliance/conformanceLabVerify.js';
import { buildConformanceAttestation, computeConformanceAttestationDigest } from './conformanceAttestation.js';
import { runChainEnforcementRollupConformanceLab } from './chainEnforcementRollupConformanceLab.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_FIXTURE = join(__dirname, '../../fixtures/conformance-local-interop.json');

/**
 * @param {string} url
 * @param {number} timeoutMs
 */
async function fetchJson(url, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    const text = await res.text();
    let body = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = { raw: text.slice(0, 512) };
    }
    return { ok: res.ok, status: res.status, body, url };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      body: null,
      url,
      error: e instanceof Error ? e.message : String(e),
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * @param {string} apiBase
 */
function normalizeApiBase(apiBase) {
  return String(apiBase || '')
    .trim()
    .replace(/\/+$/, '');
}

/**
 * Local offline interop using bundled golden receipt (no Aevesa API).
 * @param {string} [fixturePath]
 */
export function runLocalConformanceInterop(fixturePath = DEFAULT_FIXTURE) {
  const startedAt = Date.now();
  const steps = [];

  let fixture;
  try {
    fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));
    steps.push({ step: 'load_local_fixture', ok: true, elapsed_ms: Date.now() - startedAt });
  } catch (e) {
    steps.push({
      step: 'load_local_fixture',
      ok: false,
      elapsed_ms: Date.now() - startedAt,
      error: e instanceof Error ? e.message : String(e),
    });
    return { ok: false, steps, code: 'FIXTURE_LOAD_FAILED' };
  }

  const receipt = fixture.receipt;
  if (!receipt || typeof receipt !== 'object') {
    steps.push({ step: 'fixture_receipt_present', ok: false, elapsed_ms: 0 });
    return { ok: false, steps, code: 'FIXTURE_INVALID' };
  }

  const digestStarted = Date.now();
  const digest = verifyReceiptDigestMatch(receipt);
  steps.push({
    step: 'receipt_digest_match',
    ok: digest.ok === true,
    elapsed_ms: Date.now() - digestStarted,
  });

  const verifyStarted = Date.now();
  const verify = verifyReceipt(receipt, { ledgerDocument: null });
  steps.push({
    step: 'verify_receipt_offline',
    ok: verify.isValid === true,
    elapsed_ms: Date.now() - verifyStarted,
  });

  const elapsed_ms = Date.now() - startedAt;
  const entryHash = fixture.entry_hash ?? fixture.entryHash ?? null;

  return {
    ok: digest.ok === true && verify.isValid === true,
    schema: 'aevesa.conformance-lab-interop/v1',
    mode: 'local_fixture',
    entry_hash: entryHash,
    verify_portal_url: fixture.verify_portal_url ?? null,
    receipt_schema: receipt.schema ?? 'liability-receipt/v1',
    receipt_profile: receipt.receipt_profile ?? null,
    steps,
    elapsed_ms,
    within_target_minutes: 5,
    within_target: elapsed_ms <= 5 * 60 * 1000,
  };
}

/**
 * Probe a deployed Aevesa API (public evidence surfaces, no auth).
 * @param {string} apiBase
 * @param {{ timeoutMs?: number }} [opts]
 */
export async function probeDeploymentConformance(apiBase, opts = {}) {
  const base = normalizeApiBase(apiBase);
  const timeoutMs = opts.timeoutMs ?? 15000;
  const checks = [];

  const health = await fetchJson(`${base}/health`, timeoutMs);
  checks.push({
    id: 'remote-health',
    program: 'aevesa.deployment-health/v1',
    ok: health.ok === true,
    status: health.status,
    detail: health.ok ? 'API process health OK' : health.error || `HTTP ${health.status}`,
  });

  const spec = await fetchJson(`${base}/api/v1/public/evidence/spec`, timeoutMs);
  const specPrograms = spec.body?.conformancePrograms ?? spec.body?.conformance_programs;
  checks.push({
    id: 'remote-evidence-spec',
    program: 'aevesa.public-evidence-spec/v1',
    ok: spec.ok === true && spec.body?.ok !== false,
    status: spec.status,
    detail:
      spec.ok && Array.isArray(specPrograms)
        ? `${specPrograms.length} conformance programs advertised`
        : spec.error || 'spec endpoint unavailable',
  });

  const lab = await fetchJson(`${base}/api/v1/public/evidence/conformance-lab-demo`, timeoutMs);
  let labManifestOk = false;
  if (lab.ok && lab.body && typeof lab.body === 'object') {
    const manifest = {
      schema: 'aevesa.conformance-lab/1',
      sku: 'kovera-conformance-lab-v1',
      conformance_programs: lab.body.conformance_programs ?? [],
      interop: lab.body.interop ?? {
        entry_hash: lab.body.interop?.entry_hash,
        within_target: lab.body.interop?.within_target,
      },
    };
    labManifestOk = validateConformanceLabManifest(manifest).ok && lab.body.ok !== false;
  }

  checks.push({
    id: 'remote-conformance-lab-demo',
    program: 'aevesa.conformance-lab/1',
    ok: lab.ok === true && labManifestOk,
    status: lab.status,
    detail: lab.ok
      ? labManifestOk
        ? 'conformance-lab-demo manifest valid'
        : 'conformance-lab-demo response invalid'
      : lab.error || 'demo endpoint unavailable',
    snapshot: lab.ok ? { interop: lab.body?.interop ?? null, ok: lab.body?.ok ?? null } : null,
  });

  return {
    ok: checks.every((c) => c.ok === true),
    api_base: base,
    checks,
  };
}

/**
 * Full conformance lab run — local interop + optional remote deployment probe.
 * @param {{
 *   apiBase?: string | null;
 *   fixturePath?: string;
 *   timeoutMs?: number;
 *   localOnly?: boolean;
 * }} opts
 */
export async function runConformanceLab(opts = {}) {
  const startedAt = Date.now();
  /** @type {object[]} */
  const programs = [];

  const local = runLocalConformanceInterop(opts.fixturePath);
  programs.push({
    id: 'local-interop/v1',
    program: 'aevesa.conformance-lab-interop/v1',
    test: 'aevesa conformance run (local fixture)',
    ok: local.ok === true,
    steps: local.steps,
    elapsed_ms: local.elapsed_ms,
  });

  const rollupLab = runChainEnforcementRollupConformanceLab();
  programs.push({
    id: rollupLab.id,
    program: rollupLab.program,
    test: rollupLab.test,
    ok: rollupLab.ok === true,
    steps: rollupLab.steps,
    elapsed_ms: rollupLab.elapsed_ms,
    detail: rollupLab.detail,
  });

  /** @type {object | null} */
  let remote = null;
  const apiBase = opts.localOnly ? null : opts.apiBase ?? null;

  if (apiBase) {
    remote = await probeDeploymentConformance(apiBase, { timeoutMs: opts.timeoutMs });
    for (const check of remote.checks) {
      programs.push({
        id: check.id,
        program: check.program,
        test: `GET ${apiBase}`,
        ok: check.ok === true,
        detail: check.detail,
        http_status: check.status,
      });
    }
  }

  const interop = {
    entry_hash: local.entry_hash ?? remote?.checks?.find((c) => c.id === 'remote-conformance-lab-demo')?.snapshot
      ?.interop?.entry_hash ?? null,
    verify_portal_url: local.verify_portal_url,
    within_target: local.within_target,
    elapsed_ms: local.elapsed_ms,
    local,
    remote_snapshot: remote?.checks?.find((c) => c.id === 'remote-conformance-lab-demo')?.snapshot ?? null,
  };

  const attestation = buildConformanceAttestation({
    apiBase: apiBase ?? null,
    programs,
    interop,
    remote,
    generatedAt: new Date().toISOString(),
  });

  attestation.elapsed_ms = Date.now() - startedAt;
  attestation.attestation_digest = computeConformanceAttestationDigest(attestation);

  return attestation;
}

export default {
  runLocalConformanceInterop,
  probeDeploymentConformance,
  runConformanceLab,
};
