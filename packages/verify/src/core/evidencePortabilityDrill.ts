import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import { LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA } from './licenseSurvivableCustodyPack.js';
import { SHUTDOWN_DRILL_BUNDLE_SCHEMA } from './shutdownDrillBundle.js';

/** Wave 14 Track F — evidence portability drill receipt (INT-03). */

export const EVIDENCE_PORTABILITY_DRILL_SCHEMA = 'aevesa.evidence-portability-drill/v1' as const;

export const PORTABILITY_DRILL_TRIGGERS = ['scheduled', 'on_demand', 'demo'] as const;
export type PortabilityDrillTrigger = (typeof PORTABILITY_DRILL_TRIGGERS)[number];

export type PortabilityReadiness = 'drill_ready' | 'partial' | 'unverified';

export interface PortabilityComposedMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  sequence_index: number;
}

export interface PortabilityAssertionsInput {
  third_party_verifiable: boolean;
  api_credentials_absent: boolean;
  offline_verify_complete: boolean;
}

export interface PortabilityVerifyManifest {
  offline_cli: string;
  portal_base: string;
  no_backend_required: boolean;
  api_key_env_vars_checked: string[];
  custody_pack_schema: string;
  shutdown_drill_schema: string;
  bundle_schema: string;
}

export interface PortabilityMemberDocuments {
  license_survivable_custody_pack: Record<string, unknown>;
  shutdown_drill_bundle: Record<string, unknown>;
}

export interface EvidencePortabilityDrillInput {
  drill_id: string;
  organization_id: string;
  session_id: string;
  generated_at?: string;
  trigger: PortabilityDrillTrigger;
  member_documents: PortabilityMemberDocuments;
  composed_members: PortabilityComposedMemberRef[];
  portability_assertions: PortabilityAssertionsInput;
  portability_verify_manifest: PortabilityVerifyManifest;
  disclaimer?: string;
}

export function resolvePortabilityMemberDigest(
  memberSchema: string,
  doc: Record<string, unknown> | null | undefined,
): string | null {
  if (!doc || typeof doc !== 'object') return null;
  if (memberSchema === LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA) {
    return typeof doc.pack_digest === 'string' ? doc.pack_digest : null;
  }
  if (memberSchema === SHUTDOWN_DRILL_BUNDLE_SCHEMA) {
    return typeof doc.bundle_digest === 'string' ? doc.bundle_digest : null;
  }
  return null;
}

export function derivePortabilityReadiness(
  custodyLinked: boolean,
  custodyVerifyOk: boolean,
  shutdownLinked: boolean,
  shutdownVerifyOk: boolean,
  apiCredentialsAbsent: boolean,
  offlineVerifyComplete: boolean,
  thirdPartyVerifiable: boolean,
): PortabilityReadiness {
  if (
    custodyLinked
    && custodyVerifyOk
    && shutdownLinked
    && shutdownVerifyOk
    && apiCredentialsAbsent
    && offlineVerifyComplete
    && thirdPartyVerifiable
  ) {
    return 'drill_ready';
  }
  if ((custodyLinked && custodyVerifyOk) || (shutdownLinked && shutdownVerifyOk)) {
    return 'partial';
  }
  return 'unverified';
}

export function buildPortabilityAssertionsBlock(
  input: PortabilityAssertionsInput,
  custodyLinked: boolean,
  custodyVerifyOk: boolean,
  shutdownLinked: boolean,
  shutdownVerifyOk: boolean,
) {
  const portability_readiness = derivePortabilityReadiness(
    custodyLinked,
    custodyVerifyOk,
    shutdownLinked,
    shutdownVerifyOk,
    input.api_credentials_absent === true,
    input.offline_verify_complete === true,
    input.third_party_verifiable === true,
  );

  return {
    third_party_verifiable: input.third_party_verifiable === true,
    api_credentials_absent: input.api_credentials_absent === true,
    offline_verify_complete: input.offline_verify_complete === true,
    custody_survival_bound: custodyLinked && custodyVerifyOk,
    shutdown_drill_bound: shutdownLinked && shutdownVerifyOk,
    portability_readiness,
  };
}

export function buildEvidencePortabilityDrillPreimage(
  input: Omit<EvidencePortabilityDrillInput, 'disclaimer' | 'member_documents'> & {
    generated_at: string;
    portability_assertions: ReturnType<typeof buildPortabilityAssertionsBlock>;
  },
): Record<string, unknown> {
  const composed_members = [...input.composed_members]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      sequence_index: Number(m.sequence_index) || 0,
    }))
    .sort((a, b) => a.sequence_index - b.sequence_index);

  const manifest = input.portability_verify_manifest;

  return {
    schema: EVIDENCE_PORTABILITY_DRILL_SCHEMA,
    drill_id: String(input.drill_id || '').trim(),
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    generated_at: input.generated_at,
    trigger: input.trigger,
    composed_members,
    portability_assertions: input.portability_assertions,
    portability_verify_manifest: {
      offline_cli: String(manifest.offline_cli || '').trim(),
      portal_base: String(manifest.portal_base || '').trim(),
      no_backend_required: manifest.no_backend_required === true,
      api_key_env_vars_checked: [...(manifest.api_key_env_vars_checked || [])].map((v) =>
        String(v || '').trim(),
      ),
      custody_pack_schema: String(manifest.custody_pack_schema || '').trim(),
      shutdown_drill_schema: String(manifest.shutdown_drill_schema || '').trim(),
      bundle_schema: String(manifest.bundle_schema || '').trim(),
    },
  };
}

export interface EvidencePortabilityDrillDocument {
  schema: typeof EVIDENCE_PORTABILITY_DRILL_SCHEMA;
  drill_id: string;
  organization_id: string;
  session_id: string;
  generated_at: string;
  trigger: PortabilityDrillTrigger;
  member_documents: PortabilityMemberDocuments;
  composed_members: PortabilityComposedMemberRef[];
  portability_assertions: ReturnType<typeof buildPortabilityAssertionsBlock>;
  portability_verify_manifest: PortabilityVerifyManifest;
  drill_digest: string;
  disclaimer: string;
}

export function buildEvidencePortabilityDrillDocument(
  input: EvidencePortabilityDrillInput,
): EvidencePortabilityDrillDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const docs = input.member_documents;

  const custodyDoc = docs.license_survivable_custody_pack;
  const shutdownDoc = docs.shutdown_drill_bundle;

  const custodyDigest = resolvePortabilityMemberDigest(
    LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA,
    custodyDoc,
  );
  const shutdownDigest = resolvePortabilityMemberDigest(SHUTDOWN_DRILL_BUNDLE_SCHEMA, shutdownDoc);

  const custodyMember = input.composed_members.find(
    (m) => m.member_schema === LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA,
  );
  const shutdownMember = input.composed_members.find(
    (m) => m.member_schema === SHUTDOWN_DRILL_BUNDLE_SCHEMA,
  );

  const custodyLinked = custodyDoc != null && custodyDigest != null;
  const custodyVerifyOk = custodyMember?.verify_ok === true;
  const shutdownLinked = shutdownDoc != null && shutdownDigest != null;
  const shutdownVerifyOk = shutdownMember?.verify_ok === true;

  const portability_assertions = buildPortabilityAssertionsBlock(
    input.portability_assertions,
    custodyLinked,
    custodyVerifyOk,
    shutdownLinked,
    shutdownVerifyOk,
  );

  const { member_documents: _docs, disclaimer: _disclaimer, portability_assertions: _a, ...fields } =
    input;

  const preimage = buildEvidencePortabilityDrillPreimage({
    ...fields,
    generated_at,
    portability_assertions,
  });
  const drill_digest = sha256HexUtf8(stableStringify(preimage));

  return {
    ...(preimage as Omit<
      EvidencePortabilityDrillDocument,
      'member_documents' | 'drill_digest' | 'disclaimer'
    >),
    member_documents: input.member_documents,
    drill_digest,
    disclaimer:
      input.disclaimer ??
      'Evidence portability drill — export + offline verify with zero live credentials; not legal advice.',
  };
}

export default {
  EVIDENCE_PORTABILITY_DRILL_SCHEMA,
  PORTABILITY_DRILL_TRIGGERS,
  buildEvidencePortabilityDrillDocument,
  buildEvidencePortabilityDrillPreimage,
  buildPortabilityAssertionsBlock,
  derivePortabilityReadiness,
  resolvePortabilityMemberDigest,
};
