import {
  CHANNEL_PROVENANCE_SCHEMA as CHANNEL_PROVENANCE_SCHEMA_CONST,
  CHANNEL_CONTENT_BINDINGS,
  CHANNEL_SOURCE_CLASSIFICATIONS,
  computeChannelProvenanceDigest,
  computeClassificationDigest,
  isValidContentDigest,
  type ChannelProvenanceSource,
  type ChannelSourceClassification,
} from '../core/channelProvenance.js';
import { buildChannelProvenanceContentBindingReport } from './channelProvenanceContentBinding.js';

export const CHANNEL_PROVENANCE_SCHEMA = CHANNEL_PROVENANCE_SCHEMA_CONST;

export const CHANNEL_PROVENANCE_SKU = 'aevesa-channel-provenance-v1' as const;

export interface ChannelProvenanceDocument {
  schema?: string;
  session_id?: string;
  decision_id?: string;
  sources?: ChannelProvenanceSource[];
  delegated_digest?: string;
  environmental_digest?: string;
  system_digest?: string;
  channel_provenance_digest?: string;
}

export interface ChannelProvenanceVerifyOptions {
  /** Require at least one environmental source (AEG Source B scenarios) */
  requireEnvironmentalSource?: boolean;
}

export interface ChannelProvenanceVerifyChecks {
  schemaValid: boolean;
  sessionIdPresent: boolean;
  sourcesPresent: boolean;
  sourceDigestsValid: boolean;
  classificationsValid: boolean;
  delegatedDigestMatches: boolean;
  environmentalDigestMatches: boolean;
  systemDigestMatches: boolean;
  channelProvenanceDigestMatches: boolean;
  environmentalSourcePresent: boolean;
  digestOnlyDelegatedPresent: boolean;
  profileComplete: boolean;
}

export interface ChannelProvenanceVerifyResult {
  schema: typeof CHANNEL_PROVENANCE_SCHEMA;
  sku: typeof CHANNEL_PROVENANCE_SKU;
  ok: boolean;
  checks: ChannelProvenanceVerifyChecks;
  gtmLine: string;
  note: string | null;
  content_binding_report: ReturnType<typeof buildChannelProvenanceContentBindingReport> | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseSources(raw: unknown): ChannelProvenanceSource[] {
  if (!Array.isArray(raw)) return [];
  const out: ChannelProvenanceSource[] = [];
  for (const item of raw) {
    const rec = asRecord(item);
    if (!rec) continue;
    const classification = String(rec.classification || '').trim() as ChannelSourceClassification;
    if (!CHANNEL_SOURCE_CLASSIFICATIONS.includes(classification)) continue;
    const source_id = String(rec.source_id || '').trim();
    const content_digest = String(rec.content_digest || '').trim().toLowerCase();
    if (!source_id || !isValidContentDigest(content_digest)) continue;
    const bindingRaw = String(rec.content_binding || '').trim();
    const content_binding = (CHANNEL_CONTENT_BINDINGS as readonly string[]).includes(bindingRaw)
      ? (bindingRaw as ChannelProvenanceSource['content_binding'])
      : undefined;
    out.push({
      source_id,
      classification,
      content_digest,
      ...(content_binding ? { content_binding } : {}),
      ...(rec.origin ? { origin: String(rec.origin) } : {}),
      ...(rec.received_at ? { received_at: String(rec.received_at) } : {}),
    });
  }
  return out;
}

/**
 * Verify channel provenance manifest — AEG Source B (channel corruption) forensic binding.
 */
export function verifyChannelProvenanceBundle(
  input: unknown,
  options: ChannelProvenanceVerifyOptions = {},
): ChannelProvenanceVerifyResult {
  const doc = asRecord(input) as ChannelProvenanceDocument | null;
  const schemaValid = doc?.schema === CHANNEL_PROVENANCE_SCHEMA;

  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const sources = parseSources(doc?.sources);
  const sourcesPresent = sources.length > 0;
  const sourceDigestsValid = sources.every((s) => isValidContentDigest(s.content_digest));
  const classificationsValid = sources.every((s) =>
    CHANNEL_SOURCE_CLASSIFICATIONS.includes(s.classification),
  );

  const delegatedDigestMatches =
    Boolean(doc?.delegated_digest) &&
    doc!.delegated_digest === computeClassificationDigest(sources, 'delegated_authority');
  const environmentalDigestMatches =
    Boolean(doc?.environmental_digest) &&
    doc!.environmental_digest === computeClassificationDigest(sources, 'environmental');
  const systemDigestMatches =
    Boolean(doc?.system_digest) &&
    doc!.system_digest === computeClassificationDigest(sources, 'system');

  let channelProvenanceDigestMatches = false;
  if (sessionIdPresent && sourcesPresent) {
    const expected = computeChannelProvenanceDigest({
      session_id,
      decision_id: doc?.decision_id,
      sources,
    });
    channelProvenanceDigestMatches =
      Boolean(doc?.channel_provenance_digest) && doc!.channel_provenance_digest === expected;
  }

  const environmentalSourcePresent = sources.some((s) => s.classification === 'environmental');
  const content_binding_report =
    sources.length > 0 ? buildChannelProvenanceContentBindingReport(sources) : null;
  const digestOnlyDelegatedPresent =
    content_binding_report?.has_digest_only_delegated === true;
  const requireEnvironmental = options.requireEnvironmentalSource === true;

  const profileComplete =
    schemaValid &&
    sessionIdPresent &&
    sourcesPresent &&
    sourceDigestsValid &&
    classificationsValid &&
    delegatedDigestMatches &&
    environmentalDigestMatches &&
    systemDigestMatches &&
    channelProvenanceDigestMatches &&
    (!requireEnvironmental || environmentalSourcePresent);

  const ok = profileComplete;

  let note: string | null = null;
  if (ok) {
    note = digestOnlyDelegatedPresent
      ? 'Channel provenance digest verified — delegated_authority source(s) are digest-only (content not bound at capture); do not treat as carrier-ready mandate proof.'
      : 'Channel provenance verified — instruction sources bound at decision time with classification digests';
  } else if (!schemaValid) {
    note = `Expected schema ${CHANNEL_PROVENANCE_SCHEMA}`;
  } else if (!channelProvenanceDigestMatches) {
    note = 'channel_provenance_digest does not match canonical sources preimage';
  } else if (requireEnvironmental && !environmentalSourcePresent) {
    note = 'Channel provenance requires at least one environmental source for AEG Source B attestation';
  } else {
    note = 'Channel provenance profile verification failed';
  }

  return {
    schema: CHANNEL_PROVENANCE_SCHEMA,
    sku: CHANNEL_PROVENANCE_SKU,
    ok,
    checks: {
      schemaValid,
      sessionIdPresent,
      sourcesPresent,
      sourceDigestsValid,
      classificationsValid,
      delegatedDigestMatches,
      environmentalDigestMatches,
      systemDigestMatches,
      channelProvenanceDigestMatches,
      environmentalSourcePresent,
      digestOnlyDelegatedPresent,
      profileComplete,
    },
    gtmLine:
      'Context7 and CoSnitch poison context — not tools. Aevesa channel provenance binds what was in the decision window, offline-verifiable.',
    note,
    content_binding_report,
  };
}
