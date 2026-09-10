import { sha256HexUtf8 } from '../core/sha256.js';
import { DEPLOYER_LOG_CUSTODY_PACK_SCHEMA, DEPLOYER_RETENTION_MONTHS, buildWitnessCustodyPathDigest } from '../core/deployerLogCustodyPack.js';
import { stableStringify } from '../core/stableStringify.js';
import type { CustodyReadiness } from '../core/deployerLogCustodyPack.js';

export const DEPLOYER_LOG_CUSTODY_PACK_SKU = 'aevesa-deployer-log-custody-pack-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface DeployerLogCustodyPackDocument {
  schema?: string;
  organization_id?: string;
  session_id?: string;
  generated_at?: string;
  retention_until?: string;
  eu_ai_act_mapping?: Record<string, unknown>;
  custody_assertions?: Record<string, unknown>;
  composed_members?: Array<Record<string, unknown>>;
  traceable_conduct_manifest_digest?: string;
  witness_custody_path?: Record<string, unknown>;
  license_survivable_bundle_digest?: string | null;
  incident_custody_manifest_digest?: string | null;
  custody_readiness?: CustodyReadiness;
  pack_digest?: string;
}

export interface DeployerLogCustodyPackVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  sessionIdPresent: boolean;
  retentionUntilValid: boolean;
  euMappingPresent: boolean;
  custodyAssertionsPresent: boolean;
  composedMembersComplete: boolean;
  traceableConductDigestPresent: boolean;
  witnessPathDigestValid: boolean;
  packDigestMatches: boolean;
  hashOnlySurface: boolean;
  readinessConsistent: boolean;
  profileComplete: boolean;
}

export interface DeployerLogCustodyPackVerifyResult {
  schema: typeof DEPLOYER_LOG_CUSTODY_PACK_SCHEMA;
  sku: typeof DEPLOYER_LOG_CUSTODY_PACK_SKU;
  ok: boolean;
  checks: DeployerLogCustodyPackVerifyChecks;
  custody_readiness: CustodyReadiness | null;
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

export function verifyDeployerLogCustodyPack(docInput: unknown): DeployerLogCustodyPackVerifyResult {
  const doc = asRecord(docInput) as Record<string, unknown> | null;
  const schemaValid = doc?.schema === DEPLOYER_LOG_CUSTODY_PACK_SCHEMA;
  const organizationIdPresent = Boolean(String(doc?.organization_id || '').trim());
  const sessionIdPresent = Boolean(String(doc?.session_id || '').trim());
  const retentionUntilValid = Boolean(String(doc?.retention_until || '').trim());

  const eu = asRecord(doc?.eu_ai_act_mapping);
  const euMappingPresent =
    eu != null &&
    typeof eu.article_12_logging_capability === 'boolean' &&
    Number(eu.article_26_deployer_retention_months) === DEPLOYER_RETENTION_MONTHS;

  const assertions = asRecord(doc?.custody_assertions);
  const custodyAssertionsPresent =
    assertions != null &&
    typeof assertions.deployer_controlled === 'boolean' &&
    typeof assertions.independent_verify_path === 'boolean';

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const schemas = new Set(members.map((m) => asRecord(m)?.member_schema).filter(Boolean));
  const composedMembersComplete =
    schemas.has('aevesa.flight-recorder-export/v1') &&
    schemas.has('aevesa.traceable-conduct-manifest/v1') &&
    schemas.has('aevesa.witness-custody-path/v1');

  const traceableConductDigestPresent =
    typeof doc?.traceable_conduct_manifest_digest === 'string' &&
    HEX64.test(String(doc.traceable_conduct_manifest_digest));

  const witnessPath = asRecord(doc?.witness_custody_path);
  let witnessPathDigestValid = false;
  if (witnessPath && typeof witnessPath.witness_custody_path_digest === 'string') {
    const expected = buildWitnessCustodyPathDigest({
      witness_cosign_enabled: witnessPath.witness_cosign_enabled === true,
      samples_ok: Number(witnessPath.samples_ok) || 0,
      independent_verify_base: String(witnessPath.independent_verify_base || ''),
      sample_entry_hashes: Array.isArray(witnessPath.sample_entry_hashes)
        ? (witnessPath.sample_entry_hashes as string[])
        : [],
    });
    witnessPathDigestValid = expected === witnessPath.witness_custody_path_digest;
  }

  let packDigestMatches = false;
  if (doc && typeof doc.pack_digest === 'string' && HEX64.test(doc.pack_digest)) {
    const { pack_digest, disclaimer: _d, ...rest } = doc;
    const recomputed = sha256HexUtf8(stableStringify(rest));
    packDigestMatches = recomputed === pack_digest;
  }

  const hashOnlySurface = !hasForbiddenKeys(docInput);
  const readiness = (doc?.custody_readiness as CustodyReadiness) ?? null;
  const flightOk = members.some(
    (m) =>
      asRecord(m)?.member_schema === 'aevesa.flight-recorder-export/v1' &&
      asRecord(m)?.verify_ok === true,
  );
  const conductOk = members.some(
    (m) =>
      asRecord(m)?.member_schema === 'aevesa.traceable-conduct-manifest/v1' &&
      asRecord(m)?.verify_ok === true,
  );
  const witnessOk = members.some(
    (m) =>
      asRecord(m)?.member_schema === 'aevesa.witness-custody-path/v1' &&
      asRecord(m)?.verify_ok === true,
  );
  const readinessConsistent =
    readiness === 'ready'
      ? flightOk && conductOk && witnessOk
      : readiness === 'partial'
        ? flightOk || conductOk
        : readiness === 'insufficient'
          ? !flightOk && !conductOk
          : false;

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    sessionIdPresent &&
    retentionUntilValid &&
    euMappingPresent &&
    custodyAssertionsPresent &&
    composedMembersComplete &&
    traceableConductDigestPresent &&
    witnessPathDigestValid &&
    packDigestMatches &&
    hashOnlySurface &&
    readinessConsistent;

  return {
    schema: DEPLOYER_LOG_CUSTODY_PACK_SCHEMA,
    sku: DEPLOYER_LOG_CUSTODY_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      sessionIdPresent,
      retentionUntilValid,
      euMappingPresent,
      custodyAssertionsPresent,
      composedMembersComplete,
      traceableConductDigestPresent,
      witnessPathDigestValid,
      packDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      profileComplete,
    },
    custody_readiness: readiness,
    gtmLine:
      'Your AI vendor logs are not under your control. Aevesa gives deployers independent, tamper-evident custody that survives vendor switch.',
    note: profileComplete
      ? 'Deployer log custody pack verified offline.'
      : 'Deployer log custody pack incomplete — see checks.',
  };
}

export default verifyDeployerLogCustodyPack;
