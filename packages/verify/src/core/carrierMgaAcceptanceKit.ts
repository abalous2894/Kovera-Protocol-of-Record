import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 11 Track C — carrier underwriting + kill-switch drill MGA submission compose. */

export const CARRIER_MGA_ACCEPTANCE_KIT_SCHEMA =
  'aevesa.carrier-mga-acceptance-kit/v1' as const;

/** Wave 13 Track D — optional composed member (adversarial test evidence). */
export const CARRIER_MGA_OPTIONAL_MEMBER_SCHEMAS = [
  'aevesa.adversarial-test-evidence-pack/v1',
] as const;

export const CARRIER_MGA_REQUIRED_MEMBER_SCHEMAS = [
  'aevesa.carrier-underwriting-evidence-pack/v1',
  'aevesa.shutdown-drill-bundle/v1',
] as const;

export type MgaAcceptanceReadiness = 'ready' | 'partial' | 'insufficient';

export type SubmissionCadence = 'quarterly' | 'annual';

export interface ComposedMgaMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  entry_count?: number | null;
}

export interface SubmissionCadenceInput {
  cadence: SubmissionCadence;
  period_label: string;
  next_resubmission_due: string;
  kill_switch_drill_max_age_days: number;
  kill_switch_drill_digest: string;
  carrier_pack_digest: string;
  drill_fresh_for_submission: boolean;
}

export interface MgaAcceptanceAssertionsInput {
  six_controls_ready: boolean;
  kill_switch_drill_fresh: boolean;
  executive_attestation_bound: boolean;
  broker_submission_ready: boolean;
}

export interface ChainCompositionDisclosure {
  chain_enforcement_mode: string;
  uniformly_enforced: boolean;
  weakest_link_index: number | null;
  owasp_asi_gl3_hint: string;
  owasp_at7_hint: string;
  carrier_footnote: string;
  egress_attestation_schema: string;
}

export interface CarrierMgaAcceptanceKitInput {
  organization_id: string;
  generated_at?: string;
  mga_partner_ref?: string | null;
  mga_acceptance_assertions: MgaAcceptanceAssertionsInput;
  composed_members: ComposedMgaMemberRef[];
  submission_cadence: SubmissionCadenceInput;
  /** Phase 3 — prominent chain enforcement disclosure for MGA/carrier review */
  chain_composition_disclosure?: ChainCompositionDisclosure | null;
  disclaimer?: string;
}



export function deriveMgaAcceptanceReadiness(
  members: ComposedMgaMemberRef[],
  assertions: MgaAcceptanceAssertionsInput,
  drillFresh: boolean,
): MgaAcceptanceReadiness {
  const carrier = (members || []).find(
    (m) => m.member_schema === 'aevesa.carrier-underwriting-evidence-pack/v1' && m.verify_ok === true,
  );
  const drill = (members || []).find(
    (m) => m.member_schema === 'aevesa.shutdown-drill-bundle/v1' && m.verify_ok === true,
  );
  if (
    carrier &&
    drill &&
    assertions.six_controls_ready === true &&
    assertions.executive_attestation_bound === true &&
    drillFresh &&
    assertions.broker_submission_ready === true
  ) {
    return 'ready';
  }
  if (carrier || drill) return 'partial';
  return 'insufficient';
}

export function buildMgaAcceptanceAssertionsBlock(
  input: MgaAcceptanceAssertionsInput,
  members: ComposedMgaMemberRef[],
  drillFresh: boolean,
) {
  const readiness = deriveMgaAcceptanceReadiness(members, input, drillFresh);
  const hasCarrier = (members || []).some(
    (m) => m.member_schema === 'aevesa.carrier-underwriting-evidence-pack/v1' && m.verify_ok === true,
  );
  const hasDrill = (members || []).some(
    (m) => m.member_schema === 'aevesa.shutdown-drill-bundle/v1' && m.verify_ok === true,
  );
  return {
    six_controls_ready: input.six_controls_ready === true && hasCarrier,
    kill_switch_drill_fresh: drillFresh || (hasDrill && input.kill_switch_drill_fresh === true),
    executive_attestation_bound: input.executive_attestation_bound === true && hasCarrier,
    broker_submission_ready: input.broker_submission_ready === true,
    mga_acceptance_readiness: readiness,
  };
}

export function buildCarrierMgaAcceptanceKitPreimage(
  input: Omit<CarrierMgaAcceptanceKitInput, 'disclaimer'> & {
    generated_at: string;
    mga_acceptance_assertions: ReturnType<typeof buildMgaAcceptanceAssertionsBlock>;
    composed_members: ComposedMgaMemberRef[];
  },
): Record<string, unknown> {
  const members = [...(input.composed_members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  const body: Record<string, unknown> = {
    schema: CARRIER_MGA_ACCEPTANCE_KIT_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    generated_at: input.generated_at,
    mga_partner_ref: input.mga_partner_ref ? String(input.mga_partner_ref).trim() : null,
    mga_acceptance_assertions: input.mga_acceptance_assertions,
    composed_members: members,
    submission_cadence: {
      cadence: input.submission_cadence.cadence,
      period_label: String(input.submission_cadence.period_label || '').trim(),
      next_resubmission_due: String(input.submission_cadence.next_resubmission_due || '').trim(),
      kill_switch_drill_max_age_days: Number(input.submission_cadence.kill_switch_drill_max_age_days) || 90,
      kill_switch_drill_digest: String(input.submission_cadence.kill_switch_drill_digest || '')
        .trim()
        .toLowerCase(),
      carrier_pack_digest: String(input.submission_cadence.carrier_pack_digest || '')
        .trim()
        .toLowerCase(),
      drill_fresh_for_submission: input.submission_cadence.drill_fresh_for_submission === true,
    },
  };

  if (input.chain_composition_disclosure && typeof input.chain_composition_disclosure === 'object') {
    const c = input.chain_composition_disclosure;
    body.chain_composition_disclosure = {
      chain_enforcement_mode: String(c.chain_enforcement_mode || 'unknown').trim(),
      uniformly_enforced: c.uniformly_enforced === true,
      weakest_link_index:
        c.weakest_link_index != null && Number.isInteger(c.weakest_link_index)
          ? c.weakest_link_index
          : null,
      owasp_asi_gl3_hint: String(c.owasp_asi_gl3_hint || '').trim(),
      owasp_at7_hint: String(c.owasp_at7_hint || '').trim(),
      carrier_footnote: String(c.carrier_footnote || '').trim(),
      egress_attestation_schema: String(c.egress_attestation_schema || 'aevesa.egress-attestation/v2').trim(),
    };
  }

  return body;
}

export function buildCarrierMgaAcceptanceKitDocument(input: CarrierMgaAcceptanceKitInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const drillFresh = input.submission_cadence.drill_fresh_for_submission === true;
  const mga_acceptance_assertions = buildMgaAcceptanceAssertionsBlock(
    input.mga_acceptance_assertions,
    input.composed_members,
    drillFresh,
  );
  const preimage = buildCarrierMgaAcceptanceKitPreimage({
    ...input,
    generated_at,
    mga_acceptance_assertions,
    composed_members: input.composed_members,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    pack_digest,
    disclaimer:
      input.disclaimer ||
      'Broker submission aid only — Aevesa does not underwrite, bind coverage, or certify MGA acceptance.',
  };
}

export default {
  CARRIER_MGA_ACCEPTANCE_KIT_SCHEMA,
  deriveMgaAcceptanceReadiness,
  buildMgaAcceptanceAssertionsBlock,
  buildCarrierMgaAcceptanceKitDocument,
  buildCarrierMgaAcceptanceKitPreimage,
};
