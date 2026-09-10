import { sha256HexUtf8 } from '../core/sha256.js';
import { AGT_CONDUCT_RECEIPT_SCHEMA, buildAgtConductReceiptPreimage, buildNormalizedAp2ConductDigest } from '../core/agtConductReceipt.js';
import { stableStringify } from '../core/stableStringify.js';
import type { AgtSourceSchema, AgtSourceVendor } from '../core/agtConductReceipt.js';

export const AGT_CONDUCT_RECEIPT_SKU = 'aevesa-agt-conduct-receipt-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|parameters|pan|cvv)$/i;

const SOURCE_SCHEMAS = new Set<AgtSourceSchema>([
  'microsoft.mcp-gateway.audit-entry/v1',
  'microsoft.agent365.audit/v1',
  'microsoft.agt.offline-receipt/v1',
]);

const SOURCE_VENDORS = new Set<AgtSourceVendor>([
  'microsoft_agt',
  'microsoft_agent365',
  'agent_hooks',
]);

export interface AgtConductReceiptVerifyResult {
  schema: typeof AGT_CONDUCT_RECEIPT_SCHEMA;
  sku: typeof AGT_CONDUCT_RECEIPT_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  normalized_ap2_conduct_digest: string | null;
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

export function verifyAgtConductReceipt(docInput: unknown): AgtConductReceiptVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === AGT_CONDUCT_RECEIPT_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const sessionIdPresent = String(doc?.session_id || '').trim().length > 0;
  const sourceSchemaValid = SOURCE_SCHEMAS.has(doc?.source_schema as AgtSourceSchema);
  const sourceVendorValid = SOURCE_VENDORS.has(doc?.source_vendor as AgtSourceVendor);

  const audit = asRecord(doc?.agt_audit);
  const correlationIdPresent = String(audit?.correlation_id || '').trim().length > 0;
  const agentIdPresent = String(audit?.agent_id || '').trim().length > 0;
  const toolNamePresent = String(audit?.tool_name || '').trim().length > 0;

  let normalizedDigestMatches = false;
  let normalized_ap2_conduct_digest: string | null = null;
  if (audit && correlationIdPresent) {
    normalized_ap2_conduct_digest = buildNormalizedAp2ConductDigest({
      agent_id: String(audit.agent_id || ''),
      tool_name: String(audit.tool_name || ''),
      allowed: audit.allowed === true,
      correlation_id: String(audit.correlation_id || ''),
      policy_reference: audit.policy_reference != null ? String(audit.policy_reference) : null,
      entry_hash: audit.entry_hash != null ? String(audit.entry_hash) : null,
      mcp_server: audit.mcp_server != null ? String(audit.mcp_server) : null,
      sensitivity_label: audit.sensitivity_label != null ? String(audit.sensitivity_label) : null,
    });
    normalizedDigestMatches =
      String(doc?.normalized_ap2_conduct_digest || '').toLowerCase() === normalized_ap2_conduct_digest;
  }

  let receiptDigestMatches = false;
  if (schemaValid && doc && normalizedDigestMatches) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildAgtConductReceiptPreimage({
          organization_id: String(doc.organization_id),
          session_id: String(doc.session_id),
          source_schema: doc.source_schema as AgtSourceSchema,
          source_vendor: doc.source_vendor as AgtSourceVendor,
          ingested_at: String(doc.ingested_at || ''),
          agt_audit: {
            agent_id: String(audit?.agent_id || ''),
            tool_name: String(audit?.tool_name || ''),
            allowed: audit?.allowed === true,
            correlation_id: String(audit?.correlation_id || ''),
            policy_reference: audit?.policy_reference != null ? String(audit.policy_reference) : null,
            entry_hash: audit?.entry_hash != null ? String(audit.entry_hash) : null,
            mcp_server: audit?.mcp_server != null ? String(audit.mcp_server) : null,
            sensitivity_label: audit?.sensitivity_label != null ? String(audit.sensitivity_label) : null,
          },
          normalized_ap2_conduct_digest: normalized_ap2_conduct_digest!,
        }),
      ),
    );
    receiptDigestMatches = String(doc.receipt_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    sessionIdPresent &&
    sourceSchemaValid &&
    sourceVendorValid &&
    correlationIdPresent &&
    agentIdPresent &&
    toolNamePresent &&
    normalizedDigestMatches &&
    receiptDigestMatches &&
    hashOnlySurface;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${AGT_CONDUCT_RECEIPT_SCHEMA}`;
  else if (!normalizedDigestMatches) note = 'normalized_ap2_conduct_digest does not match AGT audit';
  else if (!receiptDigestMatches) note = 'receipt_digest does not match canonical preimage';

  return {
    schema: AGT_CONDUCT_RECEIPT_SCHEMA,
    sku: AGT_CONDUCT_RECEIPT_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      sessionIdPresent,
      sourceSchemaValid,
      sourceVendorValid,
      correlationIdPresent,
      normalizedDigestMatches,
      receiptDigestMatches,
      hashOnlySurface,
      profileComplete,
    },
    normalized_ap2_conduct_digest,
    gtmLine:
      'Microsoft AGT proves on-host. Aevesa normalizes AGT audit to AP2 conduct — third-party verify without Entra login.',
    note,
  };
}
