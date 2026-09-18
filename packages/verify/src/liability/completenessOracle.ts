import { isRecord } from '../core/isRecord.js';

export const COMPLETENESS_ORACLE_SCHEMA = 'aevesa.completeness-oracle/v1' as const;
export const ORCHESTRATOR_CLAIM_SCHEMA = 'aevesa.orchestrator-claim/v1' as const;

export type CompletenessVerdict =
  | 'COMPLETE'
  | 'UNDER_REPORTED'
  | 'OVER_REPORTED'
  | 'MISMATCH'
  | 'CAP_UNAVAILABLE';

export interface OrchestratorHopClaim {
  index?: number;
  tool_name: string;
  entry_hash?: string | null;
  verdict?: string | null;
}

export interface OrchestratorClaim {
  schema?: typeof ORCHESTRATOR_CLAIM_SCHEMA;
  session_id?: string;
  source?: string;
  hops: OrchestratorHopClaim[];
}

export interface CapWitnessHop {
  index: number;
  tool_name: string;
  entry_hash: string | null;
}

export interface CapWitness {
  session_id: string;
  declared_count: number;
  set_root: string | null;
  hops: CapWitnessHop[];
  session_proof_ok?: boolean;
  closure_verdict?: string | null;
  carrier_review_ready?: boolean;
  carrier_submission_ready?: boolean | null;
  closure_ship_gate_blocked?: boolean | null;
  carrier_handoff_allowed?: boolean | null;
}

export interface CompletenessOracleResult {
  schema: typeof COMPLETENESS_ORACLE_SCHEMA;
  ok: boolean;
  verdict: CompletenessVerdict;
  /** True when orchestrator claim fully matches CAP witness (no laundering gap). */
  non_laundering_ok: boolean;
  /** Incident / ITSM may close when true (future gate). */
  closable: boolean;
  session_id: string | null;
  cap: {
    declared_count: number;
    set_root: string | null;
    hop_count: number;
    hops: CapWitnessHop[];
    session_proof_ok: boolean | null;
  };
  orchestrator: {
    claimed_count: number;
    source: string | null;
    hops: OrchestratorHopClaim[];
  };
  missing_in_orchestrator: CapWitnessHop[];
  missing_in_cap: OrchestratorHopClaim[];
  entry_hash_mismatches: Array<{
    index: number;
    tool_name: string;
    cap_entry_hash: string;
    orchestrator_entry_hash: string;
  }>;
  tool_name_mismatches: Array<{
    index: number;
    cap_tool_name: string;
    orchestrator_tool_name: string;
  }>;
  gtm_line: string;
  note: string | null;
}

const HEX64 = /^[a-f0-9]{64}$/;

function normalizeHex64(v: unknown): string | null {
  const s = String(v ?? '').trim().toLowerCase();
  return HEX64.test(s) ? s : null;
}

function normalizeToolName(v: unknown): string {
  return String(v ?? '').trim().toLowerCase();
}

function hopKey(toolName: string, entryHash: string | null): string {
  return entryHash ? `${normalizeToolName(toolName)}#${entryHash}` : normalizeToolName(toolName);
}

/** Incident may close only when CAP witness is complete and carrier handoff is clear (when fields present). */
function isCapWitnessClosable(cap: CapWitness): boolean {
  if (cap.session_proof_ok !== true) return false;
  if (cap.carrier_handoff_allowed != null) {
    return cap.carrier_handoff_allowed === true;
  }
  if (cap.carrier_submission_ready != null || cap.closure_ship_gate_blocked != null) {
    return cap.carrier_submission_ready === true && cap.closure_ship_gate_blocked !== true;
  }
  return true;
}

/**
 * Parse orchestrator export / AgentiX run manifest into a normalized claim.
 */
export function parseOrchestratorClaim(data: unknown): OrchestratorClaim | null {
  if (!isRecord(data)) return null;
  const hopsRaw = data.hops ?? data.claimed_hops ?? data.tools ?? data.steps;
  if (!Array.isArray(hopsRaw)) return null;

  const hops: OrchestratorHopClaim[] = [];
  for (let i = 0; i < hopsRaw.length; i++) {
    const raw = hopsRaw[i];
    if (!isRecord(raw)) return null;
    const tool_name = String(raw.tool_name ?? raw.toolName ?? raw.tool ?? raw.name ?? '').trim();
    if (!tool_name) return null;
    const index = raw.index != null ? Number(raw.index) : raw.step_index != null ? Number(raw.step_index) : i;
    hops.push({
      index: Number.isInteger(index) ? index : i,
      tool_name,
      entry_hash: normalizeHex64(raw.entry_hash ?? raw.entryHash),
      verdict: raw.verdict != null ? String(raw.verdict) : null,
    });
  }

  return {
    schema: ORCHESTRATOR_CLAIM_SCHEMA,
    session_id: data.session_id != null ? String(data.session_id) : undefined,
    source: data.source != null ? String(data.source) : undefined,
    hops,
  };
}

function indexCapHops(hops: CapWitnessHop[]) {
  return [...hops].sort((a, b) => a.index - b.index);
}

function indexOrchestratorHops(hops: OrchestratorHopClaim[]) {
  return [...hops].map((h, i) => ({
    ...h,
    index: h.index != null && Number.isInteger(h.index) ? h.index : i,
  })).sort((a, b) => (a.index ?? 0) - (b.index ?? 0));
}

/**
 * Compare CAP ground truth vs orchestrator-reported hop set (proof laundering oracle).
 */
export function evaluateCompletenessOracle(
  cap: CapWitness | null | undefined,
  claim: OrchestratorClaim | null | undefined,
): CompletenessOracleResult {
  const emptyOrchestrator = { claimed_count: 0, source: null, hops: [] as OrchestratorHopClaim[] };
  const emptyCap = {
    declared_count: 0,
    set_root: null as string | null,
    hop_count: 0,
    hops: [] as CapWitnessHop[],
    session_proof_ok: null as boolean | null,
  };

  if (!cap || !Array.isArray(cap.hops) || cap.hops.length === 0) {
    return {
      schema: COMPLETENESS_ORACLE_SCHEMA,
      ok: false,
      verdict: 'CAP_UNAVAILABLE',
      non_laundering_ok: false,
      closable: false,
      session_id: cap?.session_id ?? claim?.session_id ?? null,
      cap: cap
        ? {
            declared_count: cap.declared_count ?? 0,
            set_root: cap.set_root ?? null,
            hop_count: cap.hops?.length ?? 0,
            hops: cap.hops ?? [],
            session_proof_ok: cap.session_proof_ok ?? null,
          }
        : emptyCap,
      orchestrator: claim
        ? {
            claimed_count: claim.hops?.length ?? 0,
            source: claim.source ?? null,
            hops: claim.hops ?? [],
          }
        : emptyOrchestrator,
      missing_in_orchestrator: [],
      missing_in_cap: claim?.hops ?? [],
      entry_hash_mismatches: [],
      tool_name_mismatches: [],
      gtm_line:
        'Orchestration logs alone cannot attest set completeness — CAP member receipts required.',
      note: 'CAP witness unavailable (no member receipts or empty hop set).',
    };
  }

  if (!claim || !Array.isArray(claim.hops)) {
    return {
      schema: COMPLETENESS_ORACLE_SCHEMA,
      ok: false,
      verdict: 'MISMATCH',
      non_laundering_ok: false,
      closable: false,
      session_id: cap.session_id ?? null,
      cap: {
        declared_count: cap.declared_count,
        set_root: cap.set_root,
        hop_count: cap.hops.length,
        hops: cap.hops,
        session_proof_ok: cap.session_proof_ok ?? null,
      },
      orchestrator: emptyOrchestrator,
      missing_in_orchestrator: cap.hops,
      missing_in_cap: [],
      entry_hash_mismatches: [],
      tool_name_mismatches: [],
      gtm_line:
        'Receipt protocols truncate tails. Aevesa set-completeness binds every hop — auditors verify the full session set offline.',
      note: 'Orchestrator claim missing or invalid.',
    };
  }

  const capHops = indexCapHops(cap.hops);
  const orchHops = indexOrchestratorHops(claim.hops);

  const capByKey = new Map<string, CapWitnessHop>();
  for (const hop of capHops) {
    capByKey.set(hopKey(hop.tool_name, hop.entry_hash), hop);
  }
  const orchByKey = new Map<string, OrchestratorHopClaim>();
  for (const hop of orchHops) {
    orchByKey.set(hopKey(hop.tool_name, hop.entry_hash ?? null), hop);
  }

  const missing_in_orchestrator: CapWitnessHop[] = [];
  const missing_in_cap: OrchestratorHopClaim[] = [];
  const entry_hash_mismatches: CompletenessOracleResult['entry_hash_mismatches'] = [];
  const tool_name_mismatches: CompletenessOracleResult['tool_name_mismatches'] = [];

  for (const hop of capHops) {
    const withHash = hop.entry_hash ? hopKey(hop.tool_name, hop.entry_hash) : null;
    const toolOnly = hopKey(hop.tool_name, null);
    const matched =
      (withHash && orchByKey.has(withHash)) ||
      orchByKey.has(toolOnly) ||
      orchHops.some(
        (o) =>
          normalizeToolName(o.tool_name) === normalizeToolName(hop.tool_name) &&
          (!o.entry_hash || !hop.entry_hash || o.entry_hash === hop.entry_hash),
      );
    if (!matched) missing_in_orchestrator.push(hop);
  }

  for (const hop of orchHops) {
    const eh = normalizeHex64(hop.entry_hash);
    const withHash = eh ? hopKey(hop.tool_name, eh) : null;
    const toolOnly = hopKey(hop.tool_name, null);
    const matched =
      (withHash && capByKey.has(withHash)) ||
      capByKey.has(toolOnly) ||
      capHops.some(
        (c) =>
          normalizeToolName(c.tool_name) === normalizeToolName(hop.tool_name) &&
          (!eh || !c.entry_hash || eh === c.entry_hash),
      );
    if (!matched) missing_in_cap.push(hop);
  }

  const pairLen = Math.min(capHops.length, orchHops.length);
  for (let i = 0; i < pairLen; i++) {
    const c = capHops[i];
    const o = orchHops[i];
    if (normalizeToolName(c.tool_name) !== normalizeToolName(o.tool_name)) {
      tool_name_mismatches.push({
        index: i,
        cap_tool_name: c.tool_name,
        orchestrator_tool_name: o.tool_name,
      });
    }
    const ce = normalizeHex64(c.entry_hash);
    const oe = normalizeHex64(o.entry_hash);
    if (ce && oe && ce !== oe) {
      entry_hash_mismatches.push({
        index: i,
        tool_name: c.tool_name,
        cap_entry_hash: ce,
        orchestrator_entry_hash: oe,
      });
    }
  }

  let verdict: CompletenessVerdict = 'COMPLETE';
  if (missing_in_orchestrator.length && missing_in_cap.length) {
    verdict = 'MISMATCH';
  } else if (missing_in_orchestrator.length) {
    verdict = 'UNDER_REPORTED';
  } else if (missing_in_cap.length) {
    verdict = 'OVER_REPORTED';
  } else if (entry_hash_mismatches.length || tool_name_mismatches.length) {
    verdict = 'MISMATCH';
  } else if (capHops.length !== orchHops.length) {
    verdict = capHops.length > orchHops.length ? 'UNDER_REPORTED' : 'OVER_REPORTED';
  }

  const non_laundering_ok = verdict === 'COMPLETE';
  const ok = non_laundering_ok;

  let note: string | null = null;
  if (verdict === 'UNDER_REPORTED') {
    note = `Orchestrator under-reports ${missing_in_orchestrator.length} governed hop(s) present in CAP witness — possible proof laundering.`;
  } else if (verdict === 'OVER_REPORTED') {
    note = `Orchestrator claims ${missing_in_cap.length} hop(s) not attested in CAP — possible ungoverned execution.`;
  } else if (verdict === 'MISMATCH') {
    note = 'Hop sets diverge by tool name, entry hash, or ordering.';
  } else {
    note = 'Orchestrator claim matches CAP witness hop set.';
  }

  return {
    schema: COMPLETENESS_ORACLE_SCHEMA,
    ok,
    verdict,
    non_laundering_ok,
    closable: ok && isCapWitnessClosable(cap),
    session_id: cap.session_id ?? claim.session_id ?? null,
    cap: {
      declared_count: cap.declared_count,
      set_root: cap.set_root,
      hop_count: cap.hops.length,
      hops: capHops,
      session_proof_ok: cap.session_proof_ok ?? null,
    },
    orchestrator: {
      claimed_count: orchHops.length,
      source: claim.source ?? null,
      hops: orchHops,
    },
    missing_in_orchestrator,
    missing_in_cap,
    entry_hash_mismatches,
    tool_name_mismatches,
    gtm_line:
      'Orchestration logs ≠ set completeness. Aevesa CAP witness is the independent hop set — offline verifiable via set_root.',
    note,
  };
}

export function capWitnessFromAttachRef(attachRef: Record<string, unknown> | null | undefined): CapWitness | null {
  if (!attachRef || attachRef.ok !== true) return null;
  const session_id = String(attachRef.session_id || '').trim();
  if (!session_id) return null;
  const entry_hashes = Array.isArray(attachRef.entry_hashes) ? attachRef.entry_hashes : [];
  const tool_names = Array.isArray(attachRef.tool_names) ? attachRef.tool_names : [];
  const hops: CapWitnessHop[] = [];
  const count = Math.max(
    Number(attachRef.declared_count) || 0,
    entry_hashes.length,
    tool_names.length,
  );
  for (let i = 0; i < count; i++) {
    hops.push({
      index: i,
      tool_name: tool_names[i] != null ? String(tool_names[i]) : `(hop-${i})`,
      entry_hash: normalizeHex64(entry_hashes[i]),
    });
  }
  const gateSummary = isRecord(attachRef.closure_ship_gate) ? attachRef.closure_ship_gate : null;
  const carrierSubmissionReady =
    gateSummary?.carrier_submission_ready === true
      ? true
      : gateSummary?.carrier_submission_ready === false
        ? false
        : null;
  const closureShipGateBlocked =
    gateSummary?.blocked === true ? true : gateSummary?.blocked === false ? false : null;

  return {
    session_id,
    declared_count: Number(attachRef.declared_count) || hops.length,
    set_root: normalizeHex64(attachRef.set_root),
    hops,
    session_proof_ok: attachRef.session_proof_ok === true,
    closure_verdict:
      attachRef.closure_verdict != null ? String(attachRef.closure_verdict).trim() : null,
    carrier_review_ready: attachRef.carrier_review_ready === true,
    carrier_submission_ready: carrierSubmissionReady,
    closure_ship_gate_blocked: closureShipGateBlocked,
    carrier_handoff_allowed:
      attachRef.carrier_handoff_allowed === true
        ? true
        : attachRef.carrier_handoff_allowed === false
          ? false
          : null,
  };
}
