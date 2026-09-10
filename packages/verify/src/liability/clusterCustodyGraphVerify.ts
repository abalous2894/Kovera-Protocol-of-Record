import { sha256HexUtf8 } from '../core/sha256.js';
import { CLUSTER_CUSTODY_GRAPH_SCHEMA, CLUSTER_CUSTODY_GRAPH_SKU, CLUSTER_ASI08_NARRATIVE, buildClusterCustodyGraphPreimage } from '../core/clusterCustodyGraph.js';
import { stableStringify } from '../core/stableStringify.js';

export { CLUSTER_CUSTODY_GRAPH_SKU };

const HEX64 = /^[a-f0-9]{64}$/;

export interface ClusterCustodyGraphVerifyOptions {
  /** When true (default), graph must have freeze anchor or drill_mode */
  requireFreezeOrDrill?: boolean;
}

export interface ClusterCustodyGraphVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  rootSessionIdPresent: boolean;
  graphDigestMatches: boolean;
  multiAgentCluster: boolean;
  edgesPresent: boolean;
  quorumEvidencePresent: boolean;
  freezeOrDrillPresent: boolean;
  freezeAnchorValid: boolean;
  profileComplete: boolean;
}

export interface ClusterCustodyGraphVerifyResult {
  schema: typeof CLUSTER_CUSTODY_GRAPH_SCHEMA;
  sku: typeof CLUSTER_CUSTODY_GRAPH_SKU;
  ok: boolean;
  checks: ClusterCustodyGraphVerifyChecks;
  nodeCount: number;
  edgeCount: number;
  quorumReceiptCount: number;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseIsoMs(value: unknown): number | null {
  const ms = Date.parse(String(value || ''));
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Verify cluster custody graph — multi-agent nodes/edges + quorum receipts; requires freeze or drill mode.
 */
export function verifyClusterCustodyGraph(
  input: unknown,
  options: ClusterCustodyGraphVerifyOptions = {},
): ClusterCustodyGraphVerifyResult {
  const doc = asRecord(input);
  const schemaValid = doc?.schema === CLUSTER_CUSTODY_GRAPH_SCHEMA;

  const organization_id = String(doc?.organization_id || '').trim();
  const organizationIdPresent = organization_id.length > 0;

  const root_session_id = String(doc?.root_session_id || '').trim();
  const rootSessionIdPresent = root_session_id.length > 0;

  const nodes = Array.isArray(doc?.nodes) ? doc.nodes : [];
  const edges = Array.isArray(doc?.edges) ? doc.edges : [];
  const quorum_receipts = Array.isArray(doc?.quorum_receipts) ? doc.quorum_receipts : [];

  const nodeCount = nodes.length;
  const edgeCount = edges.length;
  const quorumReceiptCount = quorum_receipts.length;

  const multiAgentCluster = nodeCount >= 2;
  const edgesPresent = edgeCount >= 1;

  const hasQuorumReceipt = quorum_receipts.some((r) => {
    const row = asRecord(r);
    return HEX64.test(String(row?.entry_hash || '').trim().toLowerCase());
  });
  const hasCollectiveEdge = edges.some((e) => {
    const row = asRecord(e);
    const kind = String(row?.edge_kind || '');
    return kind === 'quorum_vote' || kind === 'collective_action';
  });
  const quorumEvidencePresent = hasQuorumReceipt || hasCollectiveEdge;

  const freezeRaw = asRecord(doc?.freeze_context);
  const drillRaw = asRecord(doc?.drill_context);
  const drillMode = drillRaw?.drill_mode === true;
  const freezeAnchor = String(freezeRaw?.freeze_anchor_entry_hash || '').trim().toLowerCase();
  const freezeAnchorValid =
    freezeRaw?.required === true &&
    HEX64.test(freezeAnchor) &&
    parseIsoMs(freezeRaw?.frozen_at) != null;
  const freezeOrDrillPresent = freezeAnchorValid || drillMode;

  let graphDigestMatches = false;
  if (schemaValid && organizationIdPresent && rootSessionIdPresent) {
    const expected = buildClusterCustodyGraphPreimage({
      graph_id: String(doc?.graph_id || ''),
      organization_id,
      root_session_id,
      exported_at: String(doc?.exported_at || ''),
      asi08_narrative: String(doc?.asi08_narrative || CLUSTER_ASI08_NARRATIVE),
      freeze_context: freezeAnchorValid
        ? {
            required: true,
            freeze_anchor_entry_hash: freezeAnchor,
            incident_ref: freezeRaw?.incident_ref != null ? String(freezeRaw.incident_ref) : null,
            frozen_at: String(freezeRaw?.frozen_at || ''),
          }
        : null,
      drill_context: drillMode
        ? {
            drill_mode: true,
            drill_id: String(drillRaw?.drill_id || ''),
            narrative: String(drillRaw?.narrative || ''),
          }
        : null,
      nodes: nodes as never,
      edges: edges as never,
      quorum_receipts: quorum_receipts as never,
      delegation_chain_digest:
        doc?.delegation_chain_digest != null ? String(doc.delegation_chain_digest) : null,
      verify_manifest: asRecord(doc?.verify_manifest) as never,
      non_goals: Array.isArray(doc?.non_goals) ? doc.non_goals.map(String) : [],
    });
    const digest = String(doc?.graph_digest || '').trim().toLowerCase();
    graphDigestMatches = HEX64.test(digest) && digest === sha256HexUtf8(stableStringify(expected));
  }

  const requireFreezeOrDrill = options.requireFreezeOrDrill !== false;
  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    rootSessionIdPresent &&
    graphDigestMatches &&
    multiAgentCluster &&
    edgesPresent &&
    quorumEvidencePresent &&
    (!requireFreezeOrDrill || freezeOrDrillPresent);

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${CLUSTER_CUSTODY_GRAPH_SCHEMA}`;
  else if (!multiAgentCluster) note = 'cluster graph requires at least two agent nodes';
  else if (!edgesPresent) note = 'cluster graph requires at least one delegation/quorum edge';
  else if (!quorumEvidencePresent) note = 'requires quorum receipt and/or collective_action edge';
  else if (requireFreezeOrDrill && !freezeOrDrillPresent) {
    note = 'requires incident freeze context or explicit drill_mode';
  } else if (!graphDigestMatches) note = 'graph_digest does not match canonical preimage';

  return {
    schema: CLUSTER_CUSTODY_GRAPH_SCHEMA,
    sku: CLUSTER_CUSTODY_GRAPH_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      rootSessionIdPresent,
      graphDigestMatches,
      multiAgentCluster,
      edgesPresent,
      quorumEvidencePresent,
      freezeOrDrillPresent,
      freezeAnchorValid,
      profileComplete,
    },
    nodeCount,
    edgeCount,
    quorumReceiptCount,
    gtmLine:
      'AGT breaks the circuit. Aevesa proves who was in the cluster when it failed — frozen, witnessed, offline.',
    note,
  };
}
