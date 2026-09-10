import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  buildEvidencePortabilityDrillPreimage,
  derivePortabilityReadiness,
  EVIDENCE_PORTABILITY_DRILL_SCHEMA,
  resolvePortabilityMemberDigest,
  type PortabilityReadiness,
} from '../core/evidencePortabilityDrill.js';
import { LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA } from '../core/licenseSurvivableCustodyPack.js';
import { SHUTDOWN_DRILL_BUNDLE_SCHEMA } from '../core/shutdownDrillBundle.js';
import { verifyLicenseSurvivableCustodyPack } from './licenseSurvivableCustodyPackVerify.js';
import { verifyShutdownDrillBundle } from './shutdownDrillBundleVerify.js';

export const EVIDENCE_PORTABILITY_DRILL_SKU = 'aevesa-evidence-portability-drill-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

export interface EvidencePortabilityDrillVerifyOptions {
  requireDrillReady?: boolean;
}

export interface EvidencePortabilityDrillVerifyResult {
  schema: typeof EVIDENCE_PORTABILITY_DRILL_SCHEMA;
  sku: typeof EVIDENCE_PORTABILITY_DRILL_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  portability_readiness: PortabilityReadiness | null;
  profileComplete: boolean;
  member_results: Record<string, boolean>;
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

function memberDocumentForSchema(
  docs: Record<string, unknown>,
  schema: string,
): Record<string, unknown> | null {
  if (schema === LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA) {
    return asRecord(docs.license_survivable_custody_pack);
  }
  if (schema === SHUTDOWN_DRILL_BUNDLE_SCHEMA) {
    return asRecord(docs.shutdown_drill_bundle);
  }
  return null;
}

function verifyEmbeddedMember(schema: string, doc: unknown): boolean {
  if (schema === LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA) {
    return verifyLicenseSurvivableCustodyPack(doc).ok === true;
  }
  if (schema === SHUTDOWN_DRILL_BUNDLE_SCHEMA) {
    return verifyShutdownDrillBundle(doc, { skipSignatureVerification: true }).ok === true;
  }
  return false;
}

export function verifyEvidencePortabilityDrill(
  docInput: unknown,
  options: EvidencePortabilityDrillVerifyOptions = {},
): EvidencePortabilityDrillVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === EVIDENCE_PORTABILITY_DRILL_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const sessionIdPresent = String(doc?.session_id || '').trim().length > 0;
  const drillIdPresent = String(doc?.drill_id || '').trim().length > 0;
  const generatedAtPresent = String(doc?.generated_at || '').trim().length > 0;
  const triggerPresent =
    typeof doc?.trigger === 'string' && String(doc.trigger).trim().length > 0;

  const drillDigestValid = HEX64.test(String(doc?.drill_digest || '').toLowerCase());

  const memberDocs = asRecord(doc?.member_documents) || {};
  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];

  const member_results: Record<string, boolean> = {};
  let custodyPresent = false;
  let custodyVerifyOk = false;
  let shutdownPresent = false;
  let shutdownVerifyOk = false;

  for (const schema of [LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA, SHUTDOWN_DRILL_BUNDLE_SCHEMA]) {
    const embedded = memberDocumentForSchema(memberDocs, schema);
    const present = embedded != null;
    member_results[`${schema}_present`] = present;
    if (schema === LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA) custodyPresent = present;
    if (schema === SHUTDOWN_DRILL_BUNDLE_SCHEMA) shutdownPresent = present;
    if (!present) {
      member_results[`${schema}_verify_ok`] = false;
      continue;
    }
    const verifyOk = verifyEmbeddedMember(schema, embedded);
    member_results[`${schema}_verify_ok`] = verifyOk;
    if (schema === LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA) custodyVerifyOk = verifyOk;
    if (schema === SHUTDOWN_DRILL_BUNDLE_SCHEMA) shutdownVerifyOk = verifyOk;
  }

  let composedMembersMatchDocuments = true;
  for (const ref of members) {
    const schema = String(ref?.member_schema || '');
    const embedded = memberDocumentForSchema(memberDocs, schema);
    const expected = resolvePortabilityMemberDigest(schema, embedded);
    if (
      expected != null
      && String(ref?.member_digest || '').toLowerCase() !== String(expected).toLowerCase()
    ) {
      composedMembersMatchDocuments = false;
    }
    if (
      ref?.verify_ok === true
      && embedded != null
      && !verifyEmbeddedMember(schema, embedded)
    ) {
      composedMembersMatchDocuments = false;
    }
  }

  const assertions = asRecord(doc?.portability_assertions) || {};
  const derivedReadiness = String(
    assertions.portability_readiness || '',
  ) as PortabilityReadiness;

  const manifest = asRecord(doc?.portability_verify_manifest) || {};
  const manifestPresent =
    manifest.no_backend_required === true
    && String(manifest.bundle_schema || '') === EVIDENCE_PORTABILITY_DRILL_SCHEMA
    && Array.isArray(manifest.api_key_env_vars_checked)
    && manifest.api_key_env_vars_checked.length >= 1;

  let portabilityAssertionsConsistent =
    assertions.third_party_verifiable === true
    && assertions.api_credentials_absent === true
    && assertions.offline_verify_complete === true;

  if (derivedReadiness === 'drill_ready') {
    portabilityAssertionsConsistent =
      portabilityAssertionsConsistent
      && assertions.custody_survival_bound === true
      && assertions.shutdown_drill_bound === true
      && custodyPresent
      && custodyVerifyOk
      && shutdownPresent
      && shutdownVerifyOk;
  } else if (derivedReadiness === 'partial') {
    portabilityAssertionsConsistent =
      portabilityAssertionsConsistent && (custodyVerifyOk || shutdownVerifyOk);
  }

  const readinessConsistent = assertions.portability_readiness === derivedReadiness;

  const recomputedReadiness = derivePortabilityReadiness(
    custodyPresent,
    custodyVerifyOk,
    shutdownPresent,
    shutdownVerifyOk,
    assertions.api_credentials_absent === true,
    assertions.offline_verify_complete === true,
    assertions.third_party_verifiable === true,
  );
  const readinessMatchesDerived = derivedReadiness === recomputedReadiness;

  let drillDigestMatches = false;
  if (schemaValid && doc && manifestPresent) {
    const preimage = buildEvidencePortabilityDrillPreimage({
      drill_id: String(doc.drill_id),
      organization_id: String(doc.organization_id),
      session_id: String(doc.session_id),
      generated_at: String(doc.generated_at || ''),
      trigger: String(doc.trigger) as never,
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        sequence_index: Number(m?.sequence_index) || 0,
      })),
      portability_assertions: {
        third_party_verifiable: assertions.third_party_verifiable === true,
        api_credentials_absent: assertions.api_credentials_absent === true,
        offline_verify_complete: assertions.offline_verify_complete === true,
        custody_survival_bound: assertions.custody_survival_bound === true,
        shutdown_drill_bound: assertions.shutdown_drill_bound === true,
        portability_readiness: derivedReadiness,
      },
      portability_verify_manifest: {
        offline_cli: String(manifest.offline_cli || ''),
        portal_base: String(manifest.portal_base || ''),
        no_backend_required: manifest.no_backend_required === true,
        api_key_env_vars_checked: Array.isArray(manifest.api_key_env_vars_checked)
          ? manifest.api_key_env_vars_checked.map((v) => String(v))
          : [],
        custody_pack_schema: String(manifest.custody_pack_schema || ''),
        shutdown_drill_schema: String(manifest.shutdown_drill_schema || ''),
        bundle_schema: String(manifest.bundle_schema || ''),
      },
    });
    drillDigestMatches =
      sha256HexUtf8(stableStringify(preimage)) === String(doc.drill_digest || '').toLowerCase();
  }

  const hashOnlySurface =
    doc != null
    && !hasForbiddenKeys({
      ...doc,
      member_documents: undefined,
    });

  const requireReady = options.requireDrillReady === true;

  const profileComplete =
    schemaValid
    && organizationIdPresent
    && sessionIdPresent
    && drillIdPresent
    && generatedAtPresent
    && triggerPresent
    && drillDigestValid
    && drillDigestMatches
    && custodyPresent
    && custodyVerifyOk
    && shutdownPresent
    && shutdownVerifyOk
    && composedMembersMatchDocuments
    && manifestPresent
    && hashOnlySurface
    && portabilityAssertionsConsistent
    && readinessConsistent
    && readinessMatchesDerived
    && derivedReadiness === 'drill_ready'
    && (!requireReady || derivedReadiness === 'drill_ready');

  const ok = profileComplete;

  let note: string | null = null;
  if (!custodyVerifyOk) note = 'license_survivable_custody_pack verification failed';
  else if (!shutdownVerifyOk) note = 'shutdown_drill_bundle verification failed';
  else if (!drillDigestMatches) note = 'drill_digest mismatch';
  else if (!assertions.api_credentials_absent) note = 'api_credentials_absent must be true';
  else if (derivedReadiness !== 'drill_ready') note = `portability readiness is ${derivedReadiness}`;

  return {
    schema: EVIDENCE_PORTABILITY_DRILL_SCHEMA,
    sku: EVIDENCE_PORTABILITY_DRILL_SKU,
    ok,
    checks: {
      schemaValid: schemaValid === true,
      organizationIdPresent: organizationIdPresent === true,
      sessionIdPresent: sessionIdPresent === true,
      drillDigestMatches: drillDigestMatches === true,
      custodyPresent: custodyPresent === true,
      custodyVerifyOk: custodyVerifyOk === true,
      shutdownPresent: shutdownPresent === true,
      shutdownVerifyOk: shutdownVerifyOk === true,
      composedMembersMatchDocuments: composedMembersMatchDocuments === true,
      manifestPresent: manifestPresent === true,
      hashOnlySurface: hashOnlySurface === true,
      portabilityAssertionsConsistent: portabilityAssertionsConsistent === true,
      readinessConsistent: readinessConsistent === true,
      readinessMatchesDerived: readinessMatchesDerived === true,
      profileComplete: profileComplete === true,
    },
    portability_readiness: derivedReadiness || null,
    profileComplete,
    member_results,
    gtmLine:
      'We delete our API key on stage. Your auditor still verifies 2026 agent conduct offline.',
    note,
  };
}

export default { verifyEvidencePortabilityDrill, EVIDENCE_PORTABILITY_DRILL_SKU };
