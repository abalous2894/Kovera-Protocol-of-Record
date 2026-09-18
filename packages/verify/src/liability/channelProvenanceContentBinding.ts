import {
  CHANNEL_CONTENT_BINDINGS,
  type ChannelContentBinding,
  type ChannelProvenanceSource,
  type ChannelSourceClassification,
} from '../core/channelProvenance.js';

export { CHANNEL_CONTENT_BINDINGS };
export type { ChannelContentBinding };

export interface ChannelSourceContentBindingRow {
  source_id: string;
  classification: ChannelSourceClassification;
  content_binding: ChannelContentBinding;
}

export interface ChannelProvenanceContentBindingReport {
  sources: ChannelSourceContentBindingRow[];
  digest_only_delegated_source_ids: string[];
  has_digest_only_delegated: boolean;
  carrier_channel_ready: boolean;
}

/**
 * Resolve per-source content binding (PC-11). Legacy manifests without the field are digest_only.
 */
export function resolveSourceContentBinding(source: ChannelProvenanceSource): ChannelContentBinding {
  if (source.content_binding === 'content_bound' || source.content_binding === 'digest_only') {
    return source.content_binding;
  }
  return 'digest_only';
}

export function buildChannelProvenanceContentBindingReport(
  sources: ChannelProvenanceSource[],
): ChannelProvenanceContentBindingReport {
  const rows = sources.map((source) => ({
    source_id: source.source_id,
    classification: source.classification,
    content_binding: resolveSourceContentBinding(source),
  }));

  const digest_only_delegated_source_ids = rows
    .filter(
      (row) =>
        row.classification === 'delegated_authority' && row.content_binding === 'digest_only',
    )
    .map((row) => row.source_id);

  const has_digest_only_delegated = digest_only_delegated_source_ids.length > 0;

  return {
    sources: rows,
    digest_only_delegated_source_ids,
    has_digest_only_delegated,
    carrier_channel_ready: !has_digest_only_delegated,
  };
}
