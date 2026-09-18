/**
 * SCITT-aligned composite evidence graph evaluation (Gate 4 / Wave 17-C F).
 * Profiles: carrier_handoff_closed_world | portal_open_world | mga_handoff_closed_world
 */

import { verifySessionProof } from './sessionProofVerify.js';
import { evaluateClosureShipGate } from './sessionCompositionClosure.js';
import { verifyCarrierMgaAcceptanceKit } from './carrierMgaAcceptanceKitVerify.js';
import {
  evaluateEgressProxyProvenanceDisclosure,
  extractProxyAttributionProvenance,
} from './egressProxyProvenanceDisclosure.js';

export const COMPOSITE_EVIDENCE_GRAPH_SCHEMA = 'aevesa.composite-evidence-graph/v1' as const;

export type CompositeEvidenceProfile =
  | 'carrier_handoff_closed_world'
  | 'portal_open_world'
  | 'mga_handoff_closed_world';

export type CompositeEvidenceVerdict = 'pass' | 'unknown' | 'warn' | 'fail';

export interface CompositeEvidenceGraphResult {
  schema: typeof COMPOSITE_EVIDENCE_GRAPH_SCHEMA;
  profile: CompositeEvidenceProfile | string;
  verdict: CompositeEvidenceVerdict;
  graph_kind: 'session_proof' | 'mga_kit' | 'unrecognized';
  graph_nodes?: string[];
  missing_statements?: string[];
  statement_checks?: Record<string, boolean>;
  policy_checks?: Record<string, unknown>;
  note: string;
}

function applyProxyProvenanceCompositePolicy(
  result: CompositeEvidenceGraphResult,
  doc: unknown,
  profile: CompositeEvidenceProfile | string,
): CompositeEvidenceGraphResult {
  const provenance = extractProxyAttributionProvenance(doc);
  if (!provenance) return result;

  const disclosure = evaluateEgressProxyProvenanceDisclosure(provenance);
  const policyChecks = {
    ...result.policy_checks,
    proxy_assurance_tier: disclosure.assurance_tier,
    proxy_independently_observed_claim_allowed: disclosure.independently_observed_claim_allowed,
    proxy_broker_downgrade_required: disclosure.broker_downgrade_required,
  };

  if (!disclosure.broker_downgrade_required) {
    return { ...result, policy_checks: policyChecks };
  }

  let verdict = result.verdict;
  if (profile === 'carrier_handoff_closed_world' || profile === 'mga_handoff_closed_world') {
    if (verdict === 'pass') verdict = 'warn';
  }

  const note = disclosure.note ? `${result.note} | ${disclosure.note}` : result.note;

  return {
    ...result,
    verdict,
    policy_checks: policyChecks,
    note,
  };
}

function normalizeSessionBundle(doc: unknown): Record<string, unknown> | null {
  if (!doc || typeof doc !== 'object') return null;
  const d = doc as Record<string, unknown>;
  if (d.schema === 'aevesa.compositional-accountability/v1') return d;
  const bundle = d.bundle;
  if (
    bundle &&
    typeof bundle === 'object' &&
    (bundle as Record<string, unknown>).schema === 'aevesa.compositional-accountability/v1'
  ) {
    return bundle as Record<string, unknown>;
  }
  if (d.manifest && d.terminal_receipt) {
    return {
      schema: 'aevesa.compositional-accountability/v1',
      session_id: d.session_id ?? (d.manifest as Record<string, unknown>)?.session_id ?? 'unknown',
      ...d,
    };
  }
  return null;
}

function graphNodes(bundle: Record<string, unknown>): string[] {
  const nodes: string[] = [];
  if (bundle.manifest) nodes.push('manifest');
  if (bundle.terminal_receipt) nodes.push('terminal_receipt');
  if (Array.isArray(bundle.member_receipts) && bundle.member_receipts.length > 0) {
    nodes.push('member_receipts');
  }
  if (bundle.manifest_custodian) nodes.push('manifest_custodian');
  return nodes;
}

function evaluateSessionGraph(
  bundle: Record<string, unknown>,
  profile: CompositeEvidenceProfile | string,
): CompositeEvidenceGraphResult {
  const nodes = graphNodes(bundle);
  const missing: string[] = [];
  const required =
    profile === 'portal_open_world'
      ? ['terminal_receipt']
      : ['manifest', 'terminal_receipt', 'member_receipts'];

  for (const req of required) {
    if (!nodes.includes(req)) missing.push(req);
  }

  const offline = verifySessionProof(bundle as Parameters<typeof verifySessionProof>[0], {
    requireMemberReceipts: profile === 'carrier_handoff_closed_world',
  });
  const closure = offline.composition_closure ?? null;
  const shipGate =
    offline.closure_ship_gate ??
    (closure ? evaluateClosureShipGate(closure) : evaluateClosureShipGate(null));

  const statementChecks = {
    verifySessionProof_ok: offline.ok === true,
    session_proof_complete: offline.session_proof_complete === true,
    setCompleteness: offline.checks?.setCompleteness === true,
    memberReceiptsVerified: offline.checks?.memberReceiptsVerified === true,
  };

  const policyChecks = {
    closure_verdict: closure?.closure_verdict ?? null,
    carrier_review_ready: closure?.carrier_review_ready === true,
    ship_gate_blocked: shipGate?.blocked === true,
    rollup_carrier_inference_allowed: shipGate?.rollup_carrier_inference_allowed === true,
    rollup_alone_ship_risk: shipGate?.rollup_alone_ship_risk === true,
    chain_enforcement_qualified:
      closure?.chain_enforcement_advisory?.chain_enforcement_qualified === true,
  };

  const base = {
    schema: COMPOSITE_EVIDENCE_GRAPH_SCHEMA,
    profile,
    graph_kind: 'session_proof' as const,
    graph_nodes: nodes,
    statement_checks: statementChecks,
    policy_checks: policyChecks,
  };

  if (!offline.ok && profile !== 'portal_open_world') {
    return {
      ...base,
      verdict: missing.length > 0 ? 'unknown' : 'fail',
      missing_statements: missing,
      note: offline.errors?.[0] || 'verifySessionProof failed',
    };
  }

  if (profile === 'portal_open_world') {
    const terminalOk = Boolean(bundle.terminal_receipt);
    const compositionIncomplete =
      !bundle.manifest ||
      !Array.isArray(bundle.member_receipts) ||
      bundle.member_receipts.length === 0;
    let verdict: CompositeEvidenceVerdict = 'fail';
    if (!terminalOk) verdict = 'fail';
    else if (compositionIncomplete || !offline.ok) verdict = 'unknown';
    else if (policyChecks.ship_gate_blocked) verdict = 'warn';
    else verdict = 'warn';
    const openMissing: string[] = [];
    if (!bundle.manifest) openMissing.push('manifest');
    if (!Array.isArray(bundle.member_receipts) || bundle.member_receipts.length === 0) {
      openMissing.push('member_receipts');
    }
    return {
      ...base,
      verdict,
      missing_statements: openMissing,
      note: terminalOk
        ? compositionIncomplete
          ? 'Open-world: terminal only — composition graph incomplete (unknown)'
          : 'Open-world: graph present; check closure before carrier handoff'
        : 'Open-world: terminal receipt required',
    };
  }

  if (profile === 'carrier_handoff_closed_world') {
    if (missing.length > 0) {
      return {
        ...base,
        verdict: 'unknown',
        missing_statements: missing,
        note: `Incomplete graph: missing ${missing.join(', ')}`,
      };
    }

    if (policyChecks.ship_gate_blocked || !policyChecks.carrier_review_ready) {
      return {
        ...base,
        verdict: policyChecks.closure_verdict === 'mixed_enforcement_disclosed' ? 'warn' : 'unknown',
        missing_statements: [],
        note: `Not carrier-ready: ${policyChecks.closure_verdict ?? 'no closure'}`,
      };
    }

    if (offline.ok && policyChecks.carrier_review_ready && !policyChecks.ship_gate_blocked) {
      return {
        ...base,
        verdict: 'pass',
        missing_statements: [],
        note: 'Closed-world carrier handoff graph complete',
      };
    }

    return {
      ...base,
      verdict: 'unknown',
      missing_statements: missing,
      note: 'Carrier profile not satisfied',
    };
  }

  return {
    ...base,
    verdict: 'fail',
    missing_statements: missing,
    note: `Unknown profile: ${profile}`,
  };
}

function evaluateMgaKitGraph(
  kit: Record<string, unknown>,
  profile: CompositeEvidenceProfile | string,
): CompositeEvidenceGraphResult {
  if (profile !== 'mga_handoff_closed_world' && profile !== 'carrier_handoff_closed_world') {
    const verify = verifyCarrierMgaAcceptanceKit(
      kit as Parameters<typeof verifyCarrierMgaAcceptanceKit>[0],
    );
    return {
      schema: COMPOSITE_EVIDENCE_GRAPH_SCHEMA,
      profile,
      verdict: verify.ok ? 'warn' : 'unknown',
      graph_kind: 'mga_kit',
      graph_nodes: ['mga_kit', ...(kit.member_documents ? ['member_documents'] : [])],
      missing_statements: kit.member_documents ? [] : ['member_documents'],
      statement_checks: { verify_ok: verify.ok === true },
      policy_checks: {
        broker_submission_ready:
          (kit.mga_acceptance_assertions as Record<string, unknown>)?.broker_submission_ready ===
          true,
      },
      note: 'MGA kit evaluated outside mga_handoff profile',
    };
  }

  const nodes = ['mga_kit'];
  if (kit.member_documents) nodes.push('member_documents');
  if (kit.member_verify_attestations) nodes.push('member_verify_attestations');

  const missing: string[] = [];
  if (!kit.member_documents && !kit.member_verify_attestations) {
    missing.push('member_proof_layer');
  }

  const verify = verifyCarrierMgaAcceptanceKit(kit as Parameters<typeof verifyCarrierMgaAcceptanceKit>[0]);
  const brokerReady =
    (kit.mga_acceptance_assertions as Record<string, unknown>)?.broker_submission_ready === true;

  if (!verify.ok) {
    return {
      schema: COMPOSITE_EVIDENCE_GRAPH_SCHEMA,
      profile,
      verdict: missing.length ? 'unknown' : 'fail',
      graph_kind: 'mga_kit',
      graph_nodes: nodes,
      missing_statements: missing,
      statement_checks: { verify_ok: false },
      policy_checks: { broker_submission_ready: brokerReady },
      note: verify.note || 'verifyCarrierMgaAcceptanceKit failed',
    };
  }

  if (missing.length > 0) {
    return {
      schema: COMPOSITE_EVIDENCE_GRAPH_SCHEMA,
      profile,
      verdict: 'unknown',
      graph_kind: 'mga_kit',
      graph_nodes: nodes,
      missing_statements: missing,
      statement_checks: { verify_ok: true },
      policy_checks: { broker_submission_ready: brokerReady },
      note: 'Hash-only MGA without member_documents or attestations',
    };
  }

  return {
    schema: COMPOSITE_EVIDENCE_GRAPH_SCHEMA,
    profile,
    verdict: brokerReady ? 'pass' : 'warn',
    graph_kind: 'mga_kit',
    graph_nodes: nodes,
    missing_statements: [],
    statement_checks: {
      verify_ok: true,
      memberVerifyRecomputed: verify.checks?.memberVerifyRecomputed === true,
    },
    policy_checks: { broker_submission_ready: brokerReady },
    note: brokerReady ? 'MGA closed-world graph complete' : 'Verify ok but broker_submission_ready false',
  };
}

/** Evaluate a session proof bundle, cap export snapshot, or MGA kit against a SCITT-style profile. */
export function evaluateCompositeEvidenceGraph(
  doc: unknown,
  profile: CompositeEvidenceProfile | string,
): CompositeEvidenceGraphResult {
  const schema = String((doc as Record<string, unknown>)?.schema || '').trim();
  if (schema === 'aevesa.carrier-mga-acceptance-kit/v1') {
    return evaluateMgaKitGraph(doc as Record<string, unknown>, profile);
  }

  const capExport = doc as Record<string, unknown>;
  if (capExport?.bundle && typeof capExport.bundle === 'object') {
    const fromExport = evaluateSessionGraph(
      capExport.bundle as Record<string, unknown>,
      profile,
    );
    return applyProxyProvenanceCompositePolicy(fromExport, capExport, profile);
  }

  const bundle = normalizeSessionBundle(doc);
  if (!bundle) {
    return {
      schema: COMPOSITE_EVIDENCE_GRAPH_SCHEMA,
      profile,
      verdict: 'fail',
      graph_kind: 'unrecognized',
      missing_statements: ['session_proof_bundle'],
      note: 'Document is not a session proof bundle or MGA kit',
    };
  }

  return applyProxyProvenanceCompositePolicy(evaluateSessionGraph(bundle, profile), doc, profile);
}
