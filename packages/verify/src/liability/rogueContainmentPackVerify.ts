import { sha256HexUtf8 } from '../core/sha256.js';
import { ROGUE_CONTAINMENT_PACK_SCHEMA, ROGUE_CONTAINMENT_PACK_SKU, ROGUE_CONTAINMENT_ASI10_NARRATIVE, buildRogueContainmentPackPreimage, computeDelegationChainMemberDigest, delegationChainMemberHopCount } from '../core/rogueContainmentPack.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  verifyDelegationChain,
  DELEGATION_CHAIN_SCHEMA,
} from '../core/delegationChainVerify.js';
import {
  verifyIndependentGuardianBundle,
  type IndependentGuardianVerifyOptions,
} from './independentGuardianBundleVerify.js';
import { verifyClusterCustodyGraph } from './clusterCustodyGraphVerify.js';

export { ROGUE_CONTAINMENT_PACK_SKU };

const DEMO_DELEGATION_SIGNING_SECRET = 'kovera-delegation-chain-demo-v1-public';

const HEX64 = /^[a-f0-9]{64}$/;

export interface RogueContainmentPackVerifyOptions extends IndependentGuardianVerifyOptions {
  delegationSigningSecret?: string;
  /** When true (default), pack must include verified delegation chain */
  requireDelegationChain?: boolean;
}

export interface RogueContainmentPackVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  incidentIdPresent: boolean;
  sessionIdPresent: boolean;
  packDigestMatches: boolean;
  freezeRequired: boolean;
  freezeAnchorValid: boolean;
  delegationChainPresent: boolean;
  delegationChainDigestMatches: boolean;
  delegationHopCountMatches: boolean;
  delegationChainVerify: boolean;
  governanceMemberPresent: boolean;
  guardianBundleVerify: boolean;
  deniedAnchorsPresent: boolean;
  custodySummaryPresent: boolean;
  clusterCustodyPresent: boolean;
  clusterCustodyVerify: boolean;
  profileComplete: boolean;
}

export interface RogueContainmentPackVerifyResult {
  schema: typeof ROGUE_CONTAINMENT_PACK_SCHEMA;
  sku: typeof ROGUE_CONTAINMENT_PACK_SKU;
  ok: boolean;
  checks: RogueContainmentPackVerifyChecks;
  delegationVerify: ReturnType<typeof verifyDelegationChain> | null;
  guardianVerify: ReturnType<typeof verifyIndependentGuardianBundle> | null;
  clusterVerify: ReturnType<typeof verifyClusterCustodyGraph> | null;
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
 * Verify rogue containment pack — requires freeze + delegation chain + governance member (denied or guardian).
 */
export function verifyRogueContainmentPack(
  input: unknown,
  options: RogueContainmentPackVerifyOptions = {},
): RogueContainmentPackVerifyResult {
  const doc = asRecord(input);
  const schemaValid = doc?.schema === ROGUE_CONTAINMENT_PACK_SCHEMA;

  const organization_id = String(doc?.organization_id || '').trim();
  const organizationIdPresent = organization_id.length > 0;

  const incident_id = String(doc?.incident_id || '').trim();
  const incidentIdPresent = incident_id.length > 0;

  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const freezeRaw = asRecord(doc?.freeze);
  const freezeRequired = freezeRaw?.required === true;
  const freezeAnchor = String(freezeRaw?.freeze_anchor_entry_hash || '').trim().toLowerCase();
  const freezeAnchorValid =
    freezeRequired &&
    freezeRaw?.incident_status === 'frozen' &&
    HEX64.test(freezeAnchor) &&
    parseIsoMs(freezeRaw?.frozen_at) != null;

  const delegationRaw = asRecord(doc?.delegation_chain);
  const chainDoc = asRecord(delegationRaw?.chain);
  const chainDigestDoc = String(delegationRaw?.chain_digest || '').trim().toLowerCase();
  const hopCountDoc = Number(delegationRaw?.hop_count ?? 0);
  const hopCountActual = chainDoc ? delegationChainMemberHopCount(chainDoc) : 0;
  const delegationChainPresent =
    chainDoc != null && chainDoc.schema === DELEGATION_CHAIN_SCHEMA && hopCountActual > 0;
  const delegationHopCountMatches =
    delegationChainPresent && hopCountDoc === hopCountActual && hopCountActual > 0;
  const expectedChainDigest = chainDoc ? computeDelegationChainMemberDigest(chainDoc) : '';
  const delegationChainDigestMatches =
    delegationChainPresent && HEX64.test(chainDigestDoc) && chainDigestDoc === expectedChainDigest;

  const signingSecret =
    options.delegationSigningSecret ||
    process.env.DELEGATION_CHAIN_DEMO_SIGNING_SECRET ||
    DEMO_DELEGATION_SIGNING_SECRET;
  const delegationVerify =
    delegationChainPresent && options.requireDelegationChain !== false
      ? verifyDelegationChain(chainDoc, { signingSecret })
      : null;
  const delegationChainVerify = delegationVerify?.ok === true;

  const gov = asRecord(doc?.governance);
  const deniedHashes = Array.isArray(gov?.denied_entry_hashes)
    ? gov.denied_entry_hashes.map((h) => String(h).trim().toLowerCase()).filter((h) => HEX64.test(h))
    : [];
  const deniedAnchorsPresent = deniedHashes.length > 0;

  const guardianDoc = asRecord(gov?.independent_guardian_bundle);
  const guardianVerify = guardianDoc
    ? verifyIndependentGuardianBundle(guardianDoc, options)
    : null;
  const guardianBundleVerify = guardianVerify?.ok === true;

  const governanceMemberPresent = deniedAnchorsPresent || guardianBundleVerify;

  const custody = asRecord(doc?.incident_custody);
  const custodySummaryPresent =
    custody != null &&
    custody.freeze_receipt_schema === 'aevesa.apor.incident-freeze-receipt/v1' &&
    Number(custody.receipt_index_count) >= 0;

  const clusterRaw = asRecord(doc?.cluster_custody);
  const clusterGraphDoc = asRecord(clusterRaw?.cluster_custody_graph);
  const clusterDigestDoc = String(clusterRaw?.graph_digest || '').trim().toLowerCase();
  const clusterPresent = clusterRaw != null && HEX64.test(clusterDigestDoc);
  const clusterVerify = clusterGraphDoc ? verifyClusterCustodyGraph(clusterGraphDoc) : null;
  const clusterCustodyVerify =
    !clusterPresent || (clusterVerify?.ok === true && clusterVerify.checks.graphDigestMatches === true);

  let packDigestMatches = false;
  if (schemaValid && organizationIdPresent && incidentIdPresent && sessionIdPresent) {
    const expected = buildRogueContainmentPackPreimage({
      pack_id: String(doc?.pack_id || ''),
      organization_id,
      incident_id,
      session_id,
      exported_at: String(doc?.exported_at || ''),
      asi10_narrative: String(doc?.asi10_narrative || ROGUE_CONTAINMENT_ASI10_NARRATIVE),
      freeze: {
        required: true,
        frozen_at: String(freezeRaw?.frozen_at || ''),
        freeze_anchor_entry_hash: freezeAnchor,
        incident_status: 'frozen',
        incident_ref: freezeRaw?.incident_ref != null ? String(freezeRaw.incident_ref) : null,
      },
      delegation_chain: {
        schema: 'kovera-delegation-chain/1',
        chain_digest: chainDigestDoc,
        hop_count: Number(delegationRaw?.hop_count ?? 0),
        chain: chainDoc || {},
      },
      governance: {
        guardian_bundle_digest:
          gov?.guardian_bundle_digest != null ? String(gov.guardian_bundle_digest) : null,
        denied_entry_hashes: deniedHashes,
        witness_entry_hash:
          gov?.witness_entry_hash != null ? String(gov.witness_entry_hash) : null,
      },
      incident_custody: {
        custody_view_digest:
          custody?.custody_view_digest != null ? String(custody.custody_view_digest) : null,
        receipt_index_count: Number(custody?.receipt_index_count ?? 0),
        freeze_receipt_schema: 'aevesa.apor.incident-freeze-receipt/v1',
      },
      cluster_custody: clusterPresent
        ? {
            graph_digest: clusterDigestDoc,
            node_count: Number(clusterRaw?.node_count ?? 0),
            edge_count: Number(clusterRaw?.edge_count ?? 0),
            quorum_receipt_count: Number(clusterRaw?.quorum_receipt_count ?? 0),
          }
        : null,
      verify_manifest: asRecord(doc?.verify_manifest) as never,
      non_goals: Array.isArray(doc?.non_goals) ? doc.non_goals.map(String) : [],
    });
    const digest = String(doc?.pack_digest || '').trim().toLowerCase();
    packDigestMatches = HEX64.test(digest) && digest === sha256HexUtf8(stableStringify(expected));
  }

  const checks: RogueContainmentPackVerifyChecks = {
    schemaValid,
    organizationIdPresent,
    incidentIdPresent,
    sessionIdPresent,
    packDigestMatches,
    freezeRequired,
    freezeAnchorValid,
    delegationChainPresent,
    delegationChainDigestMatches,
    delegationHopCountMatches,
    delegationChainVerify,
    governanceMemberPresent,
    guardianBundleVerify,
    deniedAnchorsPresent,
    custodySummaryPresent,
    clusterCustodyPresent: clusterPresent,
    clusterCustodyVerify,
    profileComplete:
      schemaValid &&
      organizationIdPresent &&
      incidentIdPresent &&
      sessionIdPresent &&
      packDigestMatches &&
      freezeAnchorValid &&
      delegationChainPresent &&
      delegationChainDigestMatches &&
      delegationHopCountMatches &&
      delegationChainVerify &&
      governanceMemberPresent &&
      custodySummaryPresent &&
      clusterCustodyVerify,
  };

  const ok = checks.profileComplete;
  let note: string | null = null;
  if (!schemaValid) note = 'schema must be aevesa.rogue-containment-pack/v1';
  else if (!freezeAnchorValid) note = 'incident freeze anchor required — pack only valid for frozen incidents';
  else if (!delegationHopCountMatches) note = 'delegation_chain.hop_count must match chain links or proof hops';
  else if (!delegationChainVerify) note = 'delegation chain member failed offline verify';
  else if (!governanceMemberPresent) note = 'requires denied entry hash and/or verified independent guardian bundle';
  else if (!clusterCustodyVerify) note = 'optional cluster_custody member failed offline verify';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';

  return {
    schema: ROGUE_CONTAINMENT_PACK_SCHEMA,
    sku: ROGUE_CONTAINMENT_PACK_SKU,
    ok,
    checks,
    delegationVerify,
    guardianVerify,
    clusterVerify,
    gtmLine:
      'When the agent goes rogue, runtime vendors contain. Aevesa proves what you contained, when, and who witnessed — offline.',
    note,
  };
}
