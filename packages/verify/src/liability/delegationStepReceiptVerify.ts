import { sha256HexUtf8 } from '../core/sha256.js';
import { buildContextBindingDigest, buildDelegationStepReceiptPreimage, DELEGATION_STEP_RECEIPT_SCHEMA } from '../core/delegationStepReceipt.js';
import { stableStringify } from '../core/stableStringify.js';

export const DELEGATION_STEP_RECEIPT_SKU = 'aevesa-delegation-step-receipt-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

export interface DelegationStepReceiptVerifyResult {
  schema: typeof DELEGATION_STEP_RECEIPT_SCHEMA;
  sku: typeof DELEGATION_STEP_RECEIPT_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hasForbiddenKeys(value: unknown, depth = 0): boolean {
  if (depth > 8 || value == null) return false;
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKeys(v, depth + 1));
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyDelegationStepReceipt(
  docInput: unknown,
): DelegationStepReceiptVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === DELEGATION_STEP_RECEIPT_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const chainIdPresent = String(doc?.chain_id || '').trim().length > 0;
  const hopIndexValid = Number.isInteger(doc?.hop_index) && Number(doc?.hop_index) >= 0;

  const digestsValid =
    HEX64.test(String(doc?.receipt_digest || '').toLowerCase()) &&
    HEX64.test(String(doc?.context_binding_digest || '').toLowerCase()) &&
    HEX64.test(String(doc?.granted_scope_hash || '').toLowerCase()) &&
    HEX64.test(String(doc?.parent_scope_hash || '').toLowerCase()) &&
    HEX64.test(String(doc?.on_behalf_of_principal_digest || '').toLowerCase());

  let contextBindingMatches = false;
  if (doc && organizationIdPresent && chainIdPresent && hopIndexValid) {
    const expected = buildContextBindingDigest({
      organization_id: String(doc.organization_id),
      chain_id: String(doc.chain_id),
      hop_index: Number(doc.hop_index),
      subject_agent_id: String(doc.subject_agent_id || ''),
      actor_agent_id: String(doc.actor_agent_id || ''),
      on_behalf_of_principal_digest: String(doc.on_behalf_of_principal_digest || ''),
      parent_receipt_digest: doc.parent_receipt_digest
        ? String(doc.parent_receipt_digest).toLowerCase()
        : null,
    });
    contextBindingMatches =
      String(doc.context_binding_digest || '').toLowerCase() === expected.toLowerCase();
  }

  let receiptDigestMatches = false;
  if (schemaValid && doc && digestsValid && contextBindingMatches) {
    const preimage = buildDelegationStepReceiptPreimage({
      organization_id: String(doc.organization_id),
      chain_id: String(doc.chain_id),
      hop_index: Number(doc.hop_index),
      issuer_org_id: String(doc.issuer_org_id || ''),
      issuer_sts_id: String(doc.issuer_sts_id || ''),
      subject_agent_id: String(doc.subject_agent_id || ''),
      actor_agent_id: String(doc.actor_agent_id || ''),
      on_behalf_of_principal_digest: String(doc.on_behalf_of_principal_digest || ''),
      effective_scopes: [],
      effective_tools: [],
      parent_scope_hash: String(doc.parent_scope_hash || ''),
      granted_scope_hash: String(doc.granted_scope_hash || ''),
      context_binding_digest: String(doc.context_binding_digest || ''),
      attenuation_valid: doc.attenuation_valid === true,
      parent_receipt_digest: doc.parent_receipt_digest
        ? String(doc.parent_receipt_digest).toLowerCase()
        : null,
      issued_at: String(doc.issued_at || ''),
      expires_at: String(doc.expires_at || ''),
      generated_at: String(doc.generated_at || ''),
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    receiptDigestMatches = String(doc.receipt_digest || '').toLowerCase() === expected;
  }

  const hopZeroParentRule =
    Number(doc?.hop_index) !== 0 ||
    String(doc?.parent_scope_hash || '').toLowerCase() ===
      String(doc?.granted_scope_hash || '').toLowerCase();

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    chainIdPresent &&
    hopIndexValid &&
    digestsValid &&
    contextBindingMatches &&
    receiptDigestMatches &&
    hopZeroParentRule &&
    hashOnlySurface;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${DELEGATION_STEP_RECEIPT_SCHEMA}`;
  else if (!contextBindingMatches) note = 'context_binding_digest does not match anti-splicing preimage';
  else if (!receiptDigestMatches) note = 'receipt_digest does not match canonical preimage';
  else if (!hopZeroParentRule) note = 'hop 0 parent_scope_hash must equal granted_scope_hash';

  return {
    schema: DELEGATION_STEP_RECEIPT_SCHEMA,
    sku: DELEGATION_STEP_RECEIPT_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      chainIdPresent,
      hopIndexValid,
      digestsValid,
      contextBindingMatches,
      receiptDigestMatches,
      hopZeroParentRule,
      hashOnlySurface,
      profileComplete,
    },
    gtmLine: 'Each delegation hop carries a splice-resistant context bind — offline.',
    note,
  };
}
