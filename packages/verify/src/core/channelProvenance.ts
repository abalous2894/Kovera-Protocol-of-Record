import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const CHANNEL_PROVENANCE_SCHEMA = 'aevesa.channel-provenance/v1' as const;

export const CHANNEL_SOURCE_CLASSIFICATIONS = [
  'delegated_authority',
  'environmental',
  'system',
] as const;

export type ChannelSourceClassification = (typeof CHANNEL_SOURCE_CLASSIFICATIONS)[number];

export interface ChannelProvenanceSource {
  source_id: string;
  classification: ChannelSourceClassification;
  content_digest: string;
  origin?: string;
  received_at?: string;
}

export interface ChannelProvenanceManifestInput {
  session_id: string;
  decision_id?: string;
  sources: ChannelProvenanceSource[];
}

const DIGEST_RE = /^[a-f0-9]{64}$/;

export function isValidContentDigest(value: unknown): boolean {
  return typeof value === 'string' && DIGEST_RE.test(value.trim().toLowerCase());
}



function canonicalSource(source: ChannelProvenanceSource): Record<string, string> {
  const out: Record<string, string> = {
    source_id: String(source.source_id).trim(),
    classification: String(source.classification).trim() as ChannelSourceClassification,
    content_digest: String(source.content_digest).trim().toLowerCase(),
  };
  if (source.origin) out.origin = String(source.origin).trim();
  if (source.received_at) out.received_at = String(source.received_at).trim();
  return out;
}

/**
 * Aggregate digest for one classification bucket (sorted content digests).
 */
export function computeClassificationDigest(
  sources: ChannelProvenanceSource[],
  classification: ChannelSourceClassification,
): string {
  const digests = sources
    .filter((s) => s.classification === classification)
    .map((s) => String(s.content_digest).trim().toLowerCase())
    .filter((d) => DIGEST_RE.test(d))
    .sort();
  const preimage = { classification, digests };
  return sha256HexUtf8(stableStringify(preimage));
}

/**
 * Canonical channel provenance digest — binds instruction sources at decision time.
 */
export function computeChannelProvenanceDigest(input: ChannelProvenanceManifestInput): string {
  const sources = [...input.sources]
    .map(canonicalSource)
    .sort((a, b) => a.source_id.localeCompare(b.source_id));

  const delegated_digest = computeClassificationDigest(input.sources, 'delegated_authority');
  const environmental_digest = computeClassificationDigest(input.sources, 'environmental');
  const system_digest = computeClassificationDigest(input.sources, 'system');

  const preimage: Record<string, unknown> = {
    schema: CHANNEL_PROVENANCE_SCHEMA,
    session_id: String(input.session_id).trim(),
    sources,
    delegated_digest,
    environmental_digest,
    system_digest,
  };
  if (input.decision_id) {
    preimage.decision_id = String(input.decision_id).trim();
  }

  return sha256HexUtf8(stableStringify(preimage));
}
