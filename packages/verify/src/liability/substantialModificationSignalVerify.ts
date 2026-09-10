import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  ADAPTATION_OPERATOR_ROLES,
  type AdaptationOperatorRole,
} from '../core/declaredAdaptationEnvelope.js';
import {
  SUBSTANTIAL_MODIFICATION_SIGNAL_SCHEMA,
  SUBSTANTIAL_MODIFICATION_SIGNAL_SKU,
  buildSubstantialModificationSignalPreimage,
  validateSubstantialModificationSignalFraming,
  type SubstantialModificationSignalFraming,
  type SubstantialModificationSignalInput,
} from '../core/substantialModificationSignal.js';

export interface SubstantialModificationSignalDocument {
  schema?: string;
  organization_id?: string;
  system_id?: string;
  operator_role?: AdaptationOperatorRole;
  generated_at?: string;
  envelope_digest?: string;
  envelope_entry_hash?: string | null;
  drift_witness_entry_hash?: string | null;
  drift_status?: string;
  breaches?: SubstantialModificationSignalInput['breaches'];
  runtime_snapshot_digest?: string;
  contributing_entry_hashes?: string[];
  composed_members?: SubstantialModificationSignalInput['composed_members'];
  regulatory_framing?: SubstantialModificationSignalFraming;
  signal_entry_hash?: string | null;
  signal_digest?: string;
  disclaimer?: string;
}

export interface SubstantialModificationSignalVerifyOptions {
  requireSignalEntryHash?: boolean;
  requireContributingEntryHashes?: boolean;
}

export interface SubstantialModificationSignalVerifyResult {
  schema: typeof SUBSTANTIAL_MODIFICATION_SIGNAL_SCHEMA;
  sku: typeof SUBSTANTIAL_MODIFICATION_SIGNAL_SKU;
  ok: boolean;
  checks: {
    schemaValid: boolean;
    organizationIdPresent: boolean;
    systemIdPresent: boolean;
    operatorRoleValid: boolean;
    driftStatusBreach: boolean;
    breachesPresent: boolean;
    regulatoryFramingValid: boolean;
    envelopeDigestPresent: boolean;
    runtimeSnapshotDigestPresent: boolean;
    signalDigestMatches: boolean;
    signalEntryHashPresent: boolean;
    composedMembersPresent: boolean;
    profileComplete: boolean;
  };
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function isHex64(value: unknown): boolean {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

export function verifySubstantialModificationSignalBundle(
  input: unknown,
  options: SubstantialModificationSignalVerifyOptions = {},
): SubstantialModificationSignalVerifyResult {
  const doc = asRecord(input) as SubstantialModificationSignalDocument | null;
  const schemaValid = doc?.schema === SUBSTANTIAL_MODIFICATION_SIGNAL_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const systemIdPresent = String(doc?.system_id || '').trim().length > 0;
  const operatorRoleValid = ADAPTATION_OPERATOR_ROLES.includes(
    doc?.operator_role as AdaptationOperatorRole,
  );
  const driftStatusBreach = doc?.drift_status === 'breach';
  const breaches = Array.isArray(doc?.breaches) ? doc!.breaches : [];
  const breachesPresent = breaches.length > 0;

  const framingEval = validateSubstantialModificationSignalFraming({
    operator_role: doc?.operator_role,
    regulatory_framing: doc?.regulatory_framing ?? null,
  });
  const regulatoryFramingValid = framingEval.valid;

  const envelopeDigestPresent = isHex64(doc?.envelope_digest);
  const runtimeSnapshotDigestPresent = isHex64(doc?.runtime_snapshot_digest);
  const composedMembersPresent = Array.isArray(doc?.composed_members) && doc!.composed_members!.length >= 2;

  let signalDigestMatches = false;
  if (
    organizationIdPresent
    && systemIdPresent
    && operatorRoleValid
    && envelopeDigestPresent
    && runtimeSnapshotDigestPresent
    && doc?.generated_at
    && doc?.regulatory_framing
  ) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildSubstantialModificationSignalPreimage({
          organization_id: String(doc!.organization_id),
          system_id: String(doc!.system_id),
          operator_role: doc!.operator_role as AdaptationOperatorRole,
          generated_at: String(doc!.generated_at),
          envelope_digest: String(doc!.envelope_digest),
          envelope_entry_hash: doc!.envelope_entry_hash ?? null,
          drift_witness_entry_hash: doc!.drift_witness_entry_hash ?? null,
          drift_status: 'breach',
          breaches: breaches as SubstantialModificationSignalInput['breaches'],
          runtime_snapshot_digest: String(doc!.runtime_snapshot_digest),
          contributing_entry_hashes: Array.isArray(doc!.contributing_entry_hashes)
            ? doc!.contributing_entry_hashes.map(String)
            : [],
          composed_members: (doc!.composed_members
            || []) as SubstantialModificationSignalInput['composed_members'],
          regulatory_framing: doc!.regulatory_framing as SubstantialModificationSignalFraming,
          signal_entry_hash: doc!.signal_entry_hash ?? null,
          disclaimer: doc!.disclaimer,
        }),
      ),
    );
    signalDigestMatches = Boolean(doc!.signal_digest) && doc!.signal_digest === expected;
  }

  const signalEntryHashPresent =
    options.requireSignalEntryHash !== true
    || (typeof doc?.signal_entry_hash === 'string' && isHex64(doc.signal_entry_hash));

  const contributingOk =
    options.requireContributingEntryHashes !== true
    || (Array.isArray(doc?.contributing_entry_hashes) && doc!.contributing_entry_hashes!.length > 0);

  const profileComplete =
    schemaValid
    && organizationIdPresent
    && systemIdPresent
    && operatorRoleValid
    && driftStatusBreach
    && breachesPresent
    && regulatoryFramingValid
    && envelopeDigestPresent
    && runtimeSnapshotDigestPresent
    && signalDigestMatches
    && signalEntryHashPresent
    && composedMembersPresent
    && contributingOk;

  const ok = profileComplete;

  let note: string | null = null;
  if (!schemaValid) note = 'Invalid or missing schema.';
  else if (!driftStatusBreach) note = 'drift_status must be breach for substantial modification signal.';
  else if (!breachesPresent) note = 'At least one breach record is required.';
  else if (!regulatoryFramingValid) note = framingEval.code;
  else if (!composedMembersPresent) note = 'composed_members must include envelope and drift witness digests.';
  else if (!signalDigestMatches) note = 'Signal digest mismatch — tamper or serialization drift.';
  else if (!contributingOk) note = 'contributing_entry_hashes required for replayable receipt pack.';

  const gtmLine = ok
    ? 'Substantial modification signal verified offline — envelope breach bound to replayable ledger receipts.'
    : 'Substantial modification signal verification failed — breach pack not independently verifiable.';

  return {
    schema: SUBSTANTIAL_MODIFICATION_SIGNAL_SCHEMA,
    sku: SUBSTANTIAL_MODIFICATION_SIGNAL_SKU,
    ok,
    checks: {
      schemaValid,
      organizationIdPresent,
      systemIdPresent,
      operatorRoleValid,
      driftStatusBreach,
      breachesPresent,
      regulatoryFramingValid,
      envelopeDigestPresent,
      runtimeSnapshotDigestPresent,
      signalDigestMatches,
      signalEntryHashPresent,
      composedMembersPresent,
      profileComplete,
    },
    gtmLine,
    note,
  };
}
