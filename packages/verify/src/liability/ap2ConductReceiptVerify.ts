import { sha256HexUtf8 } from '../core/sha256.js';
import { AP2_CONDUCT_RECEIPT_SCHEMA, buildAp2ConductPreimage } from '../core/ap2ConductReceipt.js';
import {
  AP2_DISPUTE_THREAT_IDS,
  buildAp2DisputeEvidenceBlock,
} from '../core/ap2DisputeThreatMap.js';
import { stableStringify } from '../core/stableStringify.js';
import type { Ap2ConductCoverage, Ap2ConductSnapshot, Ap2MandateRefs } from '../core/ap2ConductReceipt.js';
import type { Ap2DisputeEvidenceInput } from '../core/ap2DisputeThreatMap.js';

export const AP2_CONDUCT_RECEIPT_SKU = 'aevesa-ap2-conduct-receipt-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS =
  /^(pan|cvv|cvc|card_number|payment_instrument|account_number|routing_number|iban|prompt|raw_payload)$/i;

export interface Ap2ConductReceiptDocument {
  schema?: string;
  session_id?: string;
  organization_id?: string;
  minted_at?: string;
  mandate_refs?: Ap2MandateRefs;
  conduct?: Ap2ConductSnapshot;
  receipt_entry_hashes?: string[];
  liability_receipt_profile?: string | null;
  conduct_digest?: string;
  dispute_evidence?: Ap2DisputeEvidenceInput;
}

export interface Ap2ConductReceiptVerifyChecks {
  schemaValid: boolean;
  correlationIdPresent: boolean;
  sessionIdPresent: boolean;
  organizationIdPresent: boolean;
  conductDigestMatches: boolean;
  paymentSafeSurface: boolean;
  toolHopDigestsValid: boolean;
  fullConductComplete: boolean;
  disputeEvidenceConsistent: boolean;
  profileComplete: boolean;
}

export interface Ap2ConductReceiptVerifyResult {
  schema: typeof AP2_CONDUCT_RECEIPT_SCHEMA;
  sku: typeof AP2_CONDUCT_RECEIPT_SKU;
  ok: boolean;
  checks: Ap2ConductReceiptVerifyChecks;
  gtmLine: string;
  note: string | null;
  dispute_readiness?: string | null;
  highlighted_threats?: Array<{ threat_id: string; status: string; label: string }>;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hasForbiddenKeys(value: unknown, depth = 0): boolean {
  if (depth > 8 || value == null) return false;
  if (Array.isArray(value)) {
    return value.some((v) => hasForbiddenKeys(v, depth + 1));
  }
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

function parseConduct(raw: unknown): Ap2ConductSnapshot | null {
  const c = asRecord(raw);
  if (!c) return null;
  const coverage: Ap2ConductCoverage =
    c.coverage === 'full_conduct' ? 'full_conduct' : 'mandate_correlation_only';
  const hops = Array.isArray(c.tool_hop_digests) ? c.tool_hop_digests.map(String) : [];
  const spendRaw = asRecord(c.spend_cap);
  return {
    coverage,
    tool_hop_digests: hops,
    policy_digest: c.policy_digest != null ? String(c.policy_digest) : null,
    spend_cap: spendRaw
      ? {
          max_amount_minor:
            spendRaw.max_amount_minor != null ? Number(spendRaw.max_amount_minor) : null,
          currency: spendRaw.currency != null ? String(spendRaw.currency) : null,
          cap_digest: spendRaw.cap_digest != null ? String(spendRaw.cap_digest) : null,
        }
      : null,
    model_ref_digest: c.model_ref_digest != null ? String(c.model_ref_digest) : null,
    hitl_approval_digest: c.hitl_approval_digest != null ? String(c.hitl_approval_digest) : null,
  };
}

/**
 * Verify AP2 supplemental conduct receipt — pre-signing context bound to mandate correlation.
 * Does not verify AP2 mandate signatures (external to Aevesa).
 */
export function verifyAp2ConductReceipt(input: unknown): Ap2ConductReceiptVerifyResult {
  const doc = asRecord(input) as Ap2ConductReceiptDocument | null;
  const schemaValid = doc?.schema === AP2_CONDUCT_RECEIPT_SCHEMA;

  const mandateRaw = asRecord(doc?.mandate_refs);
  const correlation_id = String(mandateRaw?.correlation_id || '').trim();
  const correlationIdPresent = correlation_id.length > 0;

  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const organization_id = String(doc?.organization_id || '').trim();
  const organizationIdPresent = organization_id.length > 0;

  const conduct = parseConduct(doc?.conduct);
  const tool_hop_digests = conduct?.tool_hop_digests || [];
  const toolHopDigestsValid =
    tool_hop_digests.length === 0 || tool_hop_digests.every((h) => HEX64.test(h));

  let conductDigestMatches = false;
  const disputeRaw = doc?.dispute_evidence as Ap2DisputeEvidenceInput | undefined;
  if (schemaValid && conduct && doc && mandateRaw) {
    const preimage = buildAp2ConductPreimage({
      session_id,
      organization_id,
      minted_at: String(doc.minted_at || ''),
      mandate_refs: {
        correlation_id,
        intent_mandate_id:
          mandateRaw.intent_mandate_id != null ? String(mandateRaw.intent_mandate_id) : null,
        cart_mandate_id:
          mandateRaw.cart_mandate_id != null ? String(mandateRaw.cart_mandate_id) : null,
        payment_mandate_id:
          mandateRaw.payment_mandate_id != null ? String(mandateRaw.payment_mandate_id) : null,
      },
      conduct,
      receipt_entry_hashes: Array.isArray(doc.receipt_entry_hashes)
        ? doc.receipt_entry_hashes.map(String)
        : [],
      liability_receipt_profile:
        doc.liability_receipt_profile === 'PERMITTED' ||
        doc.liability_receipt_profile === 'DENIED' ||
        doc.liability_receipt_profile === 'HITL_RELEASED'
          ? doc.liability_receipt_profile
          : null,
      dispute_evidence: disputeRaw ?? null,
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    conductDigestMatches = String(doc.conduct_digest || '') === expected;
  }

  let disputeEvidenceConsistent = true;
  if (disputeRaw != null) {
    if (!Array.isArray(disputeRaw.threat_evaluation) || disputeRaw.threat_evaluation.length !== AP2_DISPUTE_THREAT_IDS.length) {
      disputeEvidenceConsistent = false;
    } else {
      const expectedBlock = buildAp2DisputeEvidenceBlock(
        {
          coverage: conduct?.coverage,
          tool_hop_digests: conduct?.tool_hop_digests,
          policy_digest: conduct?.policy_digest ?? null,
          model_ref_digest: conduct?.model_ref_digest ?? null,
          hitl_approval_digest: conduct?.hitl_approval_digest ?? null,
          receipt_entry_hashes: Array.isArray(doc?.receipt_entry_hashes)
            ? doc.receipt_entry_hashes.map(String)
            : [],
          liability_receipt_profile: doc?.liability_receipt_profile ?? null,
          correlation_id,
          intent_mandate_id:
            mandateRaw?.intent_mandate_id != null ? String(mandateRaw.intent_mandate_id) : null,
          cart_mandate_id:
            mandateRaw?.cart_mandate_id != null ? String(mandateRaw.cart_mandate_id) : null,
          payment_mandate_id:
            mandateRaw?.payment_mandate_id != null ? String(mandateRaw.payment_mandate_id) : null,
        },
        {
          analysis_ref: disputeRaw.analysis_ref,
          portal_highlight_threat_ids: disputeRaw.portal_highlight_threat_ids,
        },
      );
      disputeEvidenceConsistent =
        disputeRaw.dispute_readiness === expectedBlock.dispute_readiness &&
        expectedBlock.threat_evaluation.every((expectedRow) => {
          const actual = disputeRaw.threat_evaluation.find((r) => r.threat_id === expectedRow.threat_id);
          return actual?.status === expectedRow.status;
        });
    }
  }

  const paymentSafeSurface =
    !hasForbiddenKeys(doc) &&
    (doc?.receipt_entry_hashes || []).every((h) => HEX64.test(String(h)));

  const fullConductComplete =
    conduct?.coverage !== 'full_conduct' ||
    (tool_hop_digests.length > 0 &&
      (conduct.policy_digest == null || HEX64.test(conduct.policy_digest)));

  const profileComplete =
    schemaValid &&
    correlationIdPresent &&
    sessionIdPresent &&
    organizationIdPresent &&
    conductDigestMatches &&
    paymentSafeSurface &&
    toolHopDigestsValid &&
    fullConductComplete &&
    disputeEvidenceConsistent &&
    conduct != null;

  const ok = profileComplete;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${AP2_CONDUCT_RECEIPT_SCHEMA}`;
  else if (!correlationIdPresent) note = 'mandate_refs.correlation_id is required';
  else if (!conductDigestMatches) note = 'conduct_digest does not match canonical preimage';
  else if (!paymentSafeSurface) note = 'forbidden payment/PII keys or invalid receipt entry hash';
  else if (!fullConductComplete) note = 'full_conduct coverage requires tool_hop_digests and valid policy_digest';
  else if (!disputeEvidenceConsistent) note = 'dispute_evidence threat map inconsistent with conduct snapshot';
  else if (!toolHopDigestsValid) note = 'tool_hop_digests must be SHA-256 hex when present';

  const highlightIds = disputeRaw?.portal_highlight_threat_ids || ['T-39', 'T-40', 'T-41'];
  const highlighted_threats = (disputeRaw?.threat_evaluation || [])
    .filter((row) => highlightIds.includes(row.threat_id as (typeof highlightIds)[number]))
    .map((row) => ({
      threat_id: row.threat_id,
      status: row.status,
      label: row.label,
    }));

  return {
    schema: AP2_CONDUCT_RECEIPT_SCHEMA,
    sku: AP2_CONDUCT_RECEIPT_SKU,
    ok,
    checks: {
      schemaValid,
      correlationIdPresent,
      sessionIdPresent,
      organizationIdPresent,
      conductDigestMatches,
      paymentSafeSurface,
      toolHopDigestsValid,
      fullConductComplete,
      disputeEvidenceConsistent,
      profileComplete,
    },
    gtmLine:
      'AP2 proves the mandate was signed. Aevesa proves what the agent did before settlement — offline, hash-only.',
    note,
    dispute_readiness: disputeRaw?.dispute_readiness ?? null,
    highlighted_threats: highlighted_threats.length ? highlighted_threats : undefined,
  };
}
