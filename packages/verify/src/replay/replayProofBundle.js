/**
 * Offline forensic replay from a Proof-of-Action bundle export (no API / DB).
 */

/**
 * @param {unknown} bundle
 * @returns {object}
 */
export function normalizeProofBundleInput(bundle) {
  if (!bundle || typeof bundle !== 'object') {
    throw new Error('Bundle must be a JSON object');
  }
  return /** @type {object} */ (bundle);
}

/**
 * @param {object} bundle
 */
function getArtifacts(bundle) {
  if (bundle.artifacts && typeof bundle.artifacts === 'object') {
    return bundle.artifacts;
  }
  return {};
}

/**
 * @param {object} bundle
 * @param {string} key
 */
function getArtifact(bundle, key) {
  const artifacts = getArtifacts(bundle);
  if (artifacts[key] != null) return artifacts[key];
  const bodies = bundle.artifact_bodies;
  if (bodies && typeof bodies[`${key}.json`] === 'string') {
    try {
      return JSON.parse(bodies[`${key}.json`]);
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * @param {string | Date | null | undefined} ts
 * @returns {number}
 */
function tsSortKey(ts) {
  if (!ts) return 0;
  const n = Date.parse(String(ts));
  return Number.isFinite(n) ? n : 0;
}

/**
 * @param {object} bundle
 * @returns {Array<{
 *   sequence: number;
 *   timestamp: string | null;
 *   kind: string;
 *   summary: string;
 *   entry_hash?: string | null;
 *   tool_name?: string | null;
 *   verdict?: string | null;
 *   detail?: string | null;
 * }>}
 */
export function buildSessionTimelineEvents(bundle) {
  const normalized = normalizeProofBundleInput(bundle);
  /** @type {Array<{ sequence: number; timestamp: string | null; kind: string; summary: string; entry_hash?: string | null; tool_name?: string | null; verdict?: string | null; detail?: string | null; sortKey: number }>} */
  const events = [];

  const manifest = normalized.manifest && typeof normalized.manifest === 'object' ? normalized.manifest : {};
  const anchor = getArtifact(normalized, 'ledger/anchor');
  const forensic = getArtifact(normalized, 'forensic/session_chain');
  const hitl = getArtifact(normalized, 'hitl/dual_signature');
  const mcpIntent = getArtifact(normalized, 'mcp/intent_receipt');
  const mcpWitness = getArtifact(normalized, 'mcp/approval_witness');

  const anchorEntry =
    anchor?.mongo_public_shape?.entry ??
    anchor?.raw_document ??
    null;
  const anchorTs =
    anchorEntry?.timestamp ??
    anchorEntry?.createdAt ??
    manifest.generated_at ??
    manifest.issued_at ??
    null;
  const anchorHash =
    manifest.entry_hash ??
    anchorEntry?.entryHash ??
    anchor?.entry_hash_verification?.entryHash ??
    null;

  if (anchorEntry || anchorHash) {
    events.push({
      sequence: 0,
      timestamp: anchorTs ? String(anchorTs) : null,
      kind: 'ledger_anchor',
      summary: `Primary anchor ${String(anchorEntry?.eventType || 'LEDGER_EVENT')} · ${String(anchorHash || '').slice(0, 16)}…`,
      entry_hash: anchorHash ? String(anchorHash) : null,
      tool_name: anchorEntry?.payload?.toolName ?? anchorEntry?.payload?.tool_name ?? null,
      verdict: anchorEntry?.payload?.verdict ?? null,
      detail: anchor?.entry_hash_verification?.entryHashMatch === true ? 'entryHash verified offline' : null,
      sortKey: tsSortKey(anchorTs),
    });
  }

  if (mcpIntent?.intent_receipt) {
    const ir = mcpIntent.intent_receipt;
    events.push({
      sequence: 0,
      timestamp: ir.minted_at ?? ir.created_at ?? anchorTs ? String(anchorTs) : null,
      kind: 'mcp_intent_receipt',
      summary: `MCP intent · ${String(ir.tool_name || ir.toolName || 'tool')} · args_digest ${String(ir.args_digest || '').slice(0, 12)}…`,
      entry_hash: ir.entry_hash ?? null,
      tool_name: ir.tool_name ?? ir.toolName ?? null,
      verdict: 'INTENT_MINTED',
      detail: mcpIntent.intent_id ? `intent_id ${mcpIntent.intent_id}` : null,
      sortKey: tsSortKey(ir.minted_at ?? ir.created_at ?? anchorTs),
    });
  }

  if (mcpWitness?.witness_verification) {
    const wv = mcpWitness.witness_verification;
    events.push({
      sequence: 0,
      timestamp: anchorTs ? String(anchorTs) : null,
      kind: 'mcp_approval_witness',
      summary: `MCP witness ${wv.pass === true ? 'verified' : 'failed'}`,
      entry_hash: anchorHash ? String(anchorHash) : null,
      tool_name: null,
      verdict: wv.pass === true ? 'WITNESS_OK' : 'WITNESS_FAIL',
      detail: wv.detail ?? wv.reason ?? null,
      sortKey: tsSortKey(anchorTs) + 1,
    });
  }

  if (hitl?.applicable && Array.isArray(hitl.dual_signature_events)) {
    for (const ev of hitl.dual_signature_events) {
      events.push({
        sequence: 0,
        timestamp: ev.timestamp ? String(ev.timestamp) : null,
        kind: 'hitl_dual_signature',
        summary: `HITL ${String(ev.event_type || ev.kind || 'SIGNATURE')} · ${String(ev.approver_id || ev.approverId || 'approver')}`,
        entry_hash: ev.entry_hash ?? ev.entryHash ?? null,
        tool_name: null,
        verdict: ev.verdict ?? ev.status ?? null,
        detail: ev.correlation_id ?? hitl.correlation_id ?? null,
        sortKey: tsSortKey(ev.timestamp),
      });
    }
  }

  if (forensic?.applicable && Array.isArray(forensic.hops)) {
    for (const hop of forensic.hops) {
      events.push({
        sequence: Number(hop.sequence ?? 0),
        timestamp: hop.timestamp ? String(hop.timestamp) : null,
        kind: 'forensic_hop',
        summary: `Forensic hop #${hop.sequence ?? '?'} · ${String(hop.tool_name || 'route')} · ${String(hop.entry_hash || '').slice(0, 12)}…`,
        entry_hash: hop.entry_hash ?? null,
        tool_name: hop.tool_name ?? null,
        verdict: hop.link_ok === true ? 'CHAIN_LINK_OK' : hop.jws_ok === false ? 'JWS_FAIL' : null,
        detail: hop.policy_version_hash ? `policy ${String(hop.policy_version_hash).slice(0, 12)}…` : null,
        sortKey: tsSortKey(hop.timestamp) || Number(hop.sequence ?? 0) * 1000,
      });
    }
  }

  const layers = manifest.proof_chain_summary?.layers;
  if (Array.isArray(layers)) {
    for (const layer of layers) {
      events.push({
        sequence: 0,
        timestamp: manifest.generated_at ? String(manifest.generated_at) : null,
        kind: 'proof_layer',
        summary: `Proof layer ${layer.id} · ${layer.pass === true ? 'pass' : 'fail'}`,
        entry_hash: anchorHash ? String(anchorHash) : null,
        tool_name: null,
        verdict: layer.pass === true ? 'PASS' : 'FAIL',
        detail: layer.detail ?? null,
        sortKey: tsSortKey(manifest.generated_at) + 5000 + events.length,
      });
    }
  }

  events.sort((a, b) => {
    if (a.sortKey !== b.sortKey) return a.sortKey - b.sortKey;
    return String(a.kind).localeCompare(String(b.kind));
  });

  return events.map((ev, idx) => ({
    sequence: idx + 1,
    timestamp: ev.timestamp,
    kind: ev.kind,
    summary: ev.summary,
    entry_hash: ev.entry_hash ?? null,
    tool_name: ev.tool_name ?? null,
    verdict: ev.verdict ?? null,
    detail: ev.detail ?? null,
  }));
}

/**
 * @param {object} bundle
 */
export function replayProofBundle(bundle) {
  const normalized = normalizeProofBundleInput(bundle);
  const manifest = normalized.manifest && typeof normalized.manifest === 'object' ? normalized.manifest : {};
  const timeline = buildSessionTimelineEvents(normalized);

  return {
    schema: 'aevesa.session-replay/v1',
    offline: true,
    bundle_id: manifest.bundle_id ?? manifest.bundleId ?? null,
    entry_hash: manifest.entry_hash ?? null,
    proof_profile: manifest.proof_profile ?? manifest.proofProfile ?? null,
    proof_chain_ok: manifest.proof_chain_summary?.ok ?? null,
    session_id:
      getArtifact(normalized, 'forensic/session_chain')?.session_id ??
      timeline.find((e) => e.kind === 'mcp_intent_receipt')?.detail ??
      null,
    hop_count: timeline.filter((e) => e.kind === 'forensic_hop').length,
    event_count: timeline.length,
    timeline,
    data_gaps: Array.isArray(manifest.data_gaps) ? manifest.data_gaps : [],
  };
}

export default { replayProofBundle, buildSessionTimelineEvents, normalizeProofBundleInput };
