import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 10 Track T — EU AI Act deployer log custody composed export. */

export const DEPLOYER_LOG_CUSTODY_PACK_SCHEMA = 'aevesa.deployer-log-custody-pack/v1' as const;

export const DEPLOYER_RETENTION_MONTHS = 6 as const;

export type CustodyReadiness = 'ready' | 'partial' | 'insufficient';

export interface ComposedMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  entry_count?: number | null;
}

export interface WitnessCustodyPathInput {
  witness_cosign_enabled: boolean;
  samples_ok: number;
  independent_verify_base: string;
  sample_entry_hashes: string[];
}

export interface EuAiActMappingInput {
  article_12_logging_capability: boolean;
  article_26_deployer_retention_months: number;
  article_73_incident_preservation: boolean;
  article_19_record_keeping: boolean;
}

export interface CustodyAssertionsInput {
  deployer_controlled: boolean;
  vendor_admin_plane_independent: boolean;
  independent_verify_path: boolean;
  license_survivable: boolean;
}

export interface DeployerLogCustodyPackInput {
  organization_id: string;
  session_id: string;
  generated_at?: string;
  retention_until?: string;
  eu_ai_act_mapping: EuAiActMappingInput;
  custody_assertions: CustodyAssertionsInput;
  composed_members: ComposedMemberRef[];
  traceable_conduct_manifest_digest: string;
  witness_custody_path: WitnessCustodyPathInput;
  license_survivable_bundle_digest?: string | null;
  incident_custody_manifest_digest?: string | null;
  disclaimer?: string;
}



export function computeRetentionUntil(isoGeneratedAt: string, months = DEPLOYER_RETENTION_MONTHS): string {
  const base = Date.parse(isoGeneratedAt);
  const d = new Date(Number.isFinite(base) ? base : Date.now());
  d.setUTCMonth(d.getUTCMonth() + months);
  return d.toISOString();
}

export function deriveCustodyReadiness(members: ComposedMemberRef[]): CustodyReadiness {
  const required = (members || []).filter((m) =>
    ['aevesa.flight-recorder-export/v1', 'aevesa.traceable-conduct-manifest/v1'].includes(
      String(m.member_schema || ''),
    ),
  );
  const okCount = required.filter((m) => m.verify_ok === true).length;
  const witnessOk = (members || []).some(
    (m) => m.member_schema === 'aevesa.witness-custody-path/v1' && m.verify_ok === true,
  );
  if (okCount >= 2 && witnessOk) return 'ready';
  if (okCount >= 1) return 'partial';
  return 'insufficient';
}

export function buildWitnessCustodyPathDigest(input: WitnessCustodyPathInput): string {
  const preimage = {
    schema: 'aevesa.witness-custody-path/v1',
    witness_cosign_enabled: input.witness_cosign_enabled === true,
    samples_ok: Number(input.samples_ok) || 0,
    independent_verify_base: String(input.independent_verify_base || 'https://verify.aevesa.com').trim(),
    sample_entry_hashes: [...(input.sample_entry_hashes || [])]
      .map((h) => String(h).trim().toLowerCase())
      .filter((h) => /^[a-f0-9]{64}$/.test(h))
      .sort(),
  };
  return sha256HexUtf8(stableStringify(preimage));
}

export function buildDeployerLogCustodyPackPreimage(
  input: Omit<DeployerLogCustodyPackInput, 'disclaimer'> & {
    generated_at: string;
    retention_until: string;
    custody_readiness: CustodyReadiness;
    witness_custody_path_digest: string;
  },
): Record<string, unknown> {
  const composed_members = [...(input.composed_members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  return {
    schema: DEPLOYER_LOG_CUSTODY_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    generated_at: input.generated_at,
    retention_until: input.retention_until,
    eu_ai_act_mapping: {
      article_12_logging_capability: input.eu_ai_act_mapping.article_12_logging_capability === true,
      article_26_deployer_retention_months:
        Number(input.eu_ai_act_mapping.article_26_deployer_retention_months) || DEPLOYER_RETENTION_MONTHS,
      article_73_incident_preservation: input.eu_ai_act_mapping.article_73_incident_preservation === true,
      article_19_record_keeping: input.eu_ai_act_mapping.article_19_record_keeping === true,
    },
    custody_assertions: {
      deployer_controlled: input.custody_assertions.deployer_controlled === true,
      vendor_admin_plane_independent: input.custody_assertions.vendor_admin_plane_independent === true,
      independent_verify_path: input.custody_assertions.independent_verify_path === true,
      license_survivable: input.custody_assertions.license_survivable === true,
    },
    composed_members,
    traceable_conduct_manifest_digest: String(input.traceable_conduct_manifest_digest || '')
      .trim()
      .toLowerCase(),
    witness_custody_path: {
      witness_cosign_enabled: input.witness_custody_path.witness_cosign_enabled === true,
      samples_ok: Number(input.witness_custody_path.samples_ok) || 0,
      independent_verify_base: String(input.witness_custody_path.independent_verify_base || '').trim(),
      sample_entry_hashes: [...(input.witness_custody_path.sample_entry_hashes || [])]
        .map((h) => String(h).trim().toLowerCase())
        .filter((h) => /^[a-f0-9]{64}$/.test(h))
        .sort(),
      witness_custody_path_digest: input.witness_custody_path_digest,
    },
    license_survivable_bundle_digest: input.license_survivable_bundle_digest
      ? String(input.license_survivable_bundle_digest).trim().toLowerCase()
      : null,
    incident_custody_manifest_digest: input.incident_custody_manifest_digest
      ? String(input.incident_custody_manifest_digest).trim().toLowerCase()
      : null,
    custody_readiness: input.custody_readiness,
  };
}

export function buildDeployerLogCustodyPackDocument(input: DeployerLogCustodyPackInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const retention_until = input.retention_until || computeRetentionUntil(generated_at);
  const witness_custody_path_digest = buildWitnessCustodyPathDigest(input.witness_custody_path);

  const composed_members = [...input.composed_members];
  if (!composed_members.some((m) => m.member_schema === 'aevesa.witness-custody-path/v1')) {
    composed_members.push({
      member_schema: 'aevesa.witness-custody-path/v1',
      member_digest: witness_custody_path_digest,
      verify_ok: input.witness_custody_path.samples_ok > 0 || input.witness_custody_path.witness_cosign_enabled,
      label: 'Independent witness cosign verify path',
      entry_count: input.witness_custody_path.samples_ok,
    });
  }

  const custody_readiness = deriveCustodyReadiness(composed_members);

  const preimage = buildDeployerLogCustodyPackPreimage({
    ...input,
    composed_members,
    generated_at,
    retention_until,
    custody_readiness,
    witness_custody_path_digest,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));

  return {
    ...preimage,
    disclaimer:
      input.disclaimer ||
      'Deployer log custody alignment for EU AI Act Art. 12/26 — not legal advice or regulatory submission.',
    pack_digest,
  };
}
