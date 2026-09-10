import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 9 Track P — Multi-agent cluster custody graph (ASI08 Layer 2 evidence). */

export const CLUSTER_CUSTODY_GRAPH_SCHEMA = 'aevesa.cluster-custody-graph/v1' as const;

export const CLUSTER_CUSTODY_GRAPH_SKU = 'aevesa-cluster-custody-graph-v1' as const;

export const CLUSTER_ASI08_NARRATIVE = 'asi08_cluster_custody_artifacts_only' as const;

export const CLUSTER_EDGE_KINDS = ['delegation', 'quorum_vote', 'collective_action'] as const;

export type ClusterEdgeKind = (typeof CLUSTER_EDGE_KINDS)[number];

export const CLUSTER_NODE_ROLES = ['root', 'delegate', 'quorum_member'] as const;

export type ClusterNodeRole = (typeof CLUSTER_NODE_ROLES)[number];

export const CLUSTER_QUORUM_ROLES = ['proposer', 'approver', 'witness'] as const;

export type ClusterQuorumRole = (typeof CLUSTER_QUORUM_ROLES)[number];

export interface ClusterCustodyNode {
  node_id: string;
  session_id: string;
  agent_ids: string[];
  anchor_entry_hash: string | null;
  role: ClusterNodeRole;
}

export interface ClusterCustodyEdge {
  from_session_id: string;
  to_session_id: string;
  edge_kind: ClusterEdgeKind;
  anchor_entry_hash: string | null;
}

export interface ClusterFreezeContext {
  required: true;
  freeze_anchor_entry_hash: string;
  incident_ref?: string | null;
  frozen_at: string;
}

export interface ClusterDrillContext {
  drill_mode: true;
  drill_id: string;
  narrative: string;
}

export interface ClusterQuorumReceipt {
  entry_hash: string;
  quorum_role: ClusterQuorumRole;
  session_id: string;
}

export interface ClusterCustodyVerifyManifest {
  offline_cli: string;
  portal_base: string;
  graph_schema: string;
  swarm_tree_schema: string;
  delegation_chain_schema: string;
}

export interface ClusterCustodyGraphInput {
  graph_id: string;
  organization_id: string;
  root_session_id: string;
  exported_at?: string;
  asi08_narrative?: string;
  freeze_context?: ClusterFreezeContext | null;
  drill_context?: ClusterDrillContext | null;
  nodes: ClusterCustodyNode[];
  edges: ClusterCustodyEdge[];
  quorum_receipts: ClusterQuorumReceipt[];
  delegation_chain_digest?: string | null;
  verify_manifest?: ClusterCustodyVerifyManifest;
  non_goals?: string[];
}



function normalizeHex64(value: unknown): string | null {
  const h = String(value || '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(h) ? h : null;
}

function normalizeNodes(nodes: ClusterCustodyNode[]): ClusterCustodyNode[] {
  return [...nodes]
    .sort((a, b) => a.session_id.localeCompare(b.session_id))
    .map((n) => ({
      node_id: String(n.node_id || n.session_id || '').trim(),
      session_id: String(n.session_id || '').trim(),
      agent_ids: [...(n.agent_ids || [])].map(String).sort(),
      anchor_entry_hash: normalizeHex64(n.anchor_entry_hash),
      role: CLUSTER_NODE_ROLES.includes(n.role) ? n.role : 'delegate',
    }));
}

function normalizeEdges(edges: ClusterCustodyEdge[]): ClusterCustodyEdge[] {
  return [...edges]
    .sort((a, b) =>
      `${a.from_session_id}:${a.to_session_id}:${a.edge_kind}`.localeCompare(
        `${b.from_session_id}:${b.to_session_id}:${b.edge_kind}`,
      ),
    )
    .map((e) => ({
      from_session_id: String(e.from_session_id || '').trim(),
      to_session_id: String(e.to_session_id || '').trim(),
      edge_kind: CLUSTER_EDGE_KINDS.includes(e.edge_kind) ? e.edge_kind : 'delegation',
      anchor_entry_hash: normalizeHex64(e.anchor_entry_hash),
    }));
}

function normalizeQuorumReceipts(receipts: ClusterQuorumReceipt[]): ClusterQuorumReceipt[] {
  return [...receipts]
    .sort((a, b) => a.entry_hash.localeCompare(b.entry_hash))
    .map((r) => ({
      entry_hash: normalizeHex64(r.entry_hash) || '',
      quorum_role: CLUSTER_QUORUM_ROLES.includes(r.quorum_role) ? r.quorum_role : 'witness',
      session_id: String(r.session_id || '').trim(),
    }))
    .filter((r) => /^[a-f0-9]{64}$/.test(r.entry_hash));
}

/**
 * Canonical graph preimage — excludes graph_digest and swarm tree bodies.
 */
export function buildClusterCustodyGraphPreimage(
  input: ClusterCustodyGraphInput,
): Record<string, unknown> {
  const freeze = input.freeze_context;
  const drill = input.drill_context;
  const nodes = normalizeNodes(input.nodes || []);
  const edges = normalizeEdges(input.edges || []);
  const quorum_receipts = normalizeQuorumReceipts(input.quorum_receipts || []);

  return {
    schema: CLUSTER_CUSTODY_GRAPH_SCHEMA,
    graph_id: String(input.graph_id || '').trim(),
    organization_id: String(input.organization_id || '').trim(),
    root_session_id: String(input.root_session_id || '').trim(),
    exported_at: input.exported_at || new Date(0).toISOString(),
    asi08_narrative: input.asi08_narrative || CLUSTER_ASI08_NARRATIVE,
    freeze_context:
      freeze?.required === true
        ? {
            required: true,
            freeze_anchor_entry_hash: normalizeHex64(freeze.freeze_anchor_entry_hash) || '',
            incident_ref: freeze.incident_ref != null ? String(freeze.incident_ref) : null,
            frozen_at: String(freeze.frozen_at || ''),
          }
        : null,
    drill_context:
      drill?.drill_mode === true
        ? {
            drill_mode: true,
            drill_id: String(drill.drill_id || '').trim(),
            narrative: String(drill.narrative || '').trim(),
          }
        : null,
    node_count: nodes.length,
    edge_count: edges.length,
    quorum_receipt_count: quorum_receipts.length,
    nodes: nodes.map((n) => ({
      node_id: n.node_id,
      session_id: n.session_id,
      agent_ids: n.agent_ids,
      anchor_entry_hash: n.anchor_entry_hash,
      role: n.role,
    })),
    edges: edges.map((e) => ({
      from_session_id: e.from_session_id,
      to_session_id: e.to_session_id,
      edge_kind: e.edge_kind,
      anchor_entry_hash: e.anchor_entry_hash,
    })),
    quorum_receipts,
    delegation_chain_digest:
      input.delegation_chain_digest != null
        ? normalizeHex64(input.delegation_chain_digest)
        : null,
    verify_manifest: input.verify_manifest ?? null,
    non_goals: input.non_goals ?? [],
  };
}

/** Summary digest for optional rogue containment pack member. */
export function computeClusterCustodyGraphMemberDigest(graph: Record<string, unknown>): string {
  return sha256HexUtf8(
    stableStringify({
      schema: CLUSTER_CUSTODY_GRAPH_SCHEMA,
      graph_id: String(graph?.graph_id || '').trim(),
      root_session_id: String(graph?.root_session_id || '').trim(),
      node_count: Array.isArray(graph?.nodes) ? graph.nodes.length : 0,
      edge_count: Array.isArray(graph?.edges) ? graph.edges.length : 0,
      quorum_receipt_count: Array.isArray(graph?.quorum_receipts) ? graph.quorum_receipts.length : 0,
      graph_digest: normalizeHex64(graph?.graph_digest),
    }),
  );
}

export function buildClusterCustodyGraphDocument(input: ClusterCustodyGraphInput) {
  const exported_at = input.exported_at || new Date().toISOString();
  const nodes = normalizeNodes(input.nodes || []);
  const edges = normalizeEdges(input.edges || []);
  const quorum_receipts = normalizeQuorumReceipts(input.quorum_receipts || []);

  const preimage = buildClusterCustodyGraphPreimage({
    ...input,
    exported_at,
    nodes,
    edges,
    quorum_receipts,
  });
  const graph_digest = sha256HexUtf8(stableStringify(preimage));

  return {
    ...preimage,
    exported_at,
    nodes,
    edges,
    quorum_receipts,
    graph_digest,
  };
}
