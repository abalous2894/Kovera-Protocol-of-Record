import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import { DELEGATION_CHAIN_SCHEMA } from './delegationChainVerify.js';

/** Wave 9 Track N — Rogue-agent containment evidence pack (composes Wave 8 artifacts). */

export const ROGUE_CONTAINMENT_PACK_SCHEMA = 'aevesa.rogue-containment-pack/v1' as const;

export const ROGUE_CONTAINMENT_PACK_SKU = 'aevesa-rogue-containment-pack-v1' as const;

export const ROGUE_CONTAINMENT_ASI10_NARRATIVE = 'asi10_containment_artifacts_only' as const;

export interface RogueContainmentFreeze {
  required: true;
  frozen_at: string;
  freeze_anchor_entry_hash: string;
  incident_status: 'frozen';
  incident_ref?: string | null;
}

export interface RogueContainmentDelegationChain {
  schema: typeof DELEGATION_CHAIN_SCHEMA;
  chain_digest: string;
  hop_count: number;
  chain: Record<string, unknown>;
}

export interface RogueContainmentGovernance {
  guardian_bundle_digest: string | null;
  independent_guardian_bundle?: Record<string, unknown> | null;
  denied_entry_hashes: string[];
  witness_entry_hash?: string | null;
}

export interface RogueContainmentCustody {
  custody_view_digest: string | null;
  receipt_index_count: number;
  freeze_receipt_schema: 'aevesa.apor.incident-freeze-receipt/v1';
}

export interface RogueContainmentClusterCustody {
  graph_digest: string;
  node_count: number;
  edge_count: number;
  quorum_receipt_count: number;
  cluster_custody_graph?: Record<string, unknown> | null;
}

export interface RogueContainmentVerifyManifest {
  offline_cli: string;
  portal_base: string;
  pack_schema: string;
  delegation_chain_schema: typeof DELEGATION_CHAIN_SCHEMA;
  guardian_bundle_schema: string;
  incident_custody_schema: string;
}

export interface RogueContainmentPackInput {
  pack_id: string;
  organization_id: string;
  incident_id: string;
  session_id: string;
  exported_at?: string;
  asi10_narrative?: string;
  freeze: RogueContainmentFreeze;
  delegation_chain: RogueContainmentDelegationChain;
  governance: RogueContainmentGovernance;
  incident_custody: RogueContainmentCustody;
  cluster_custody?: RogueContainmentClusterCustody | null;
  verify_manifest: RogueContainmentVerifyManifest;
  non_goals?: string[];
}



export function delegationChainMemberHopCount(chain: Record<string, unknown>): number {
  const proof = chain?.proof as { hops?: unknown[] } | undefined;
  const hops = Array.isArray(chain?.hops)
    ? (chain.hops as unknown[])
    : Array.isArray(proof?.hops)
      ? proof.hops
      : [];
  if (hops.length) return hops.length;
  const links = Array.isArray(chain?.links) ? (chain.links as unknown[]) : [];
  return links.length;
}

/**
 * Digest for delegation chain member — chain tip + hop count (not full hop bodies in preimage).
 */
export function computeDelegationChainMemberDigest(chain: Record<string, unknown>): string {
  const proof = chain?.proof as { hops?: Array<{ hop_hash?: unknown }> } | undefined;
  const hops = Array.isArray(chain?.hops)
    ? (chain.hops as Array<{ hop_hash?: unknown }>)
    : Array.isArray(proof?.hops)
      ? proof.hops
      : [];
  const links = Array.isArray(chain?.links)
    ? (chain.links as Array<{ scope_hash?: unknown }>)
    : [];
  const lastHop = hops.length ? hops[hops.length - 1] : null;
  const chainTip =
    lastHop?.hop_hash != null
      ? String(lastHop.hop_hash).trim().toLowerCase()
      : links.length
        ? String(links[links.length - 1]?.scope_hash || '').trim().toLowerCase()
        : null;

  return sha256HexUtf8(
    stableStringify({
      schema: DELEGATION_CHAIN_SCHEMA,
      chain_id: String(chain?.chain_id || '').trim(),
      hop_count: delegationChainMemberHopCount(chain),
      chain_tip_hash: chainTip,
    }),
  );
}

function normalizeDeniedHashes(hashes: string[]): string[] {
  return [...new Set(hashes.map((h) => String(h || '').trim().toLowerCase()))]
    .filter((h) => /^[a-f0-9]{64}$/.test(h))
    .sort();
}

function normalizeFreeze(freeze: RogueContainmentFreeze): RogueContainmentFreeze {
  return {
    required: true,
    frozen_at: String(freeze.frozen_at || ''),
    freeze_anchor_entry_hash: String(freeze.freeze_anchor_entry_hash || '').trim().toLowerCase(),
    incident_status: 'frozen',
    incident_ref: freeze.incident_ref != null ? String(freeze.incident_ref).trim() : null,
  };
}

/**
 * Canonical pack preimage — excludes pack_digest and embedded receipt bodies inside members.
 */
export function buildRogueContainmentPackPreimage(input: RogueContainmentPackInput): Record<string, unknown> {
  const freeze = normalizeFreeze(input.freeze);
  const chainDigest =
    String(input.delegation_chain?.chain_digest || '').trim().toLowerCase() ||
    computeDelegationChainMemberDigest(input.delegation_chain?.chain || {});

  const gov = input.governance || {
    guardian_bundle_digest: null,
    denied_entry_hashes: [],
    witness_entry_hash: null,
  };
  const denied = normalizeDeniedHashes(gov.denied_entry_hashes || []);

  return {
    schema: ROGUE_CONTAINMENT_PACK_SCHEMA,
    pack_id: String(input.pack_id || '').trim(),
    organization_id: String(input.organization_id || '').trim(),
    incident_id: String(input.incident_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    exported_at: input.exported_at || new Date(0).toISOString(),
    asi10_narrative: input.asi10_narrative || ROGUE_CONTAINMENT_ASI10_NARRATIVE,
    freeze: {
      required: true,
      frozen_at: freeze.frozen_at,
      freeze_anchor_entry_hash: freeze.freeze_anchor_entry_hash,
      incident_status: 'frozen',
      incident_ref: freeze.incident_ref,
    },
    delegation_chain: {
      schema: DELEGATION_CHAIN_SCHEMA,
      chain_digest: chainDigest,
      hop_count: Number(input.delegation_chain?.hop_count ?? 0),
    },
    governance: {
      guardian_bundle_digest: gov.guardian_bundle_digest
        ? String(gov.guardian_bundle_digest).trim().toLowerCase()
        : null,
      denied_entry_hashes: denied,
      witness_entry_hash: gov.witness_entry_hash
        ? String(gov.witness_entry_hash).trim().toLowerCase()
        : null,
    },
    incident_custody: {
      custody_view_digest: input.incident_custody?.custody_view_digest
        ? String(input.incident_custody.custody_view_digest).trim().toLowerCase()
        : null,
      receipt_index_count: Number(input.incident_custody?.receipt_index_count ?? 0),
      freeze_receipt_schema: 'aevesa.apor.incident-freeze-receipt/v1',
    },
    cluster_custody: input.cluster_custody?.graph_digest
      ? {
          graph_digest: String(input.cluster_custody.graph_digest).trim().toLowerCase(),
          node_count: Number(input.cluster_custody.node_count ?? 0),
          edge_count: Number(input.cluster_custody.edge_count ?? 0),
          quorum_receipt_count: Number(input.cluster_custody.quorum_receipt_count ?? 0),
        }
      : null,
    verify_manifest: input.verify_manifest,
    non_goals: input.non_goals ?? [],
  };
}

export function buildRogueContainmentPackDocument(input: RogueContainmentPackInput) {
  const exported_at = input.exported_at || new Date().toISOString();
  const chain = input.delegation_chain?.chain || {};
  const chain_digest =
    String(input.delegation_chain?.chain_digest || '').trim().toLowerCase() ||
    computeDelegationChainMemberDigest(chain);
  const hop_count = delegationChainMemberHopCount(chain);

  const preimage = buildRogueContainmentPackPreimage({
    ...input,
    exported_at,
    delegation_chain: {
      schema: DELEGATION_CHAIN_SCHEMA,
      chain_digest,
      hop_count,
      chain,
    },
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));

  return {
    ...preimage,
    exported_at,
    delegation_chain: {
      schema: DELEGATION_CHAIN_SCHEMA,
      chain_digest,
      hop_count,
      chain,
    },
    governance: {
      guardian_bundle_digest: input.governance?.guardian_bundle_digest ?? null,
      independent_guardian_bundle: input.governance?.independent_guardian_bundle ?? null,
      denied_entry_hashes: normalizeDeniedHashes(input.governance?.denied_entry_hashes || []),
      witness_entry_hash: input.governance?.witness_entry_hash ?? null,
    },
    incident_custody: input.incident_custody,
    cluster_custody: input.cluster_custody?.graph_digest
      ? {
          graph_digest: String(input.cluster_custody.graph_digest).trim().toLowerCase(),
          node_count: Number(input.cluster_custody.node_count ?? 0),
          edge_count: Number(input.cluster_custody.edge_count ?? 0),
          quorum_receipt_count: Number(input.cluster_custody.quorum_receipt_count ?? 0),
          cluster_custody_graph: input.cluster_custody.cluster_custody_graph ?? null,
        }
      : null,
    pack_digest,
  };
}
