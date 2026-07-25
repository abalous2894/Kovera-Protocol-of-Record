import { z } from 'zod';
import { causalLineageSchema } from './causalLineageSchema.js';
import { gatewayAttestationSchema } from './gatewayAttestationSchema.js';
import { partialPathSchema } from './partialPathSchema.js';
import { intentContextSchema } from './intentContext.js';
import { intentAlignmentSchema } from './intentAlignmentSchema.js';

const hex64 = z.string().regex(/^[a-f0-9]{64}$/);

const policyThresholdValueSchema = z.union([z.number(), z.string(), z.boolean(), z.null()]);

const primaryActorSchema = z.object({
  agent_id: z.string().min(1),
  actor_class: z.enum([
    'autonomous_agent',
    'delegated_kiosk',
    'human_operator',
    'system_control_plane',
  ]),
  display_name: z.string().nullable().optional(),
});

const humanReleaseActorSchema = z.object({
  agent_id: z.string().min(1),
  scoped_role: z.string().min(1),
  operator_id: z.string().nullable().optional(),
});

export const liabilityReceiptV1ZodSchema = z
  .object({
    schema: z.literal('liability-receipt/v1'),
    receipt_id: z.string().uuid(),
    issued_at: z.string().datetime(),
    issuer: z.object({
      name: z.string().min(1),
      product: z.string().min(1),
      verification_profile: z.string().min(1),
      organization_id: z.string().nullable().optional(),
      organization_display_name: z.string().nullable().optional(),
    }),
    session: z.object({
      session_id: z.string().min(1),
      correlation_id: z.string().min(1),
      vertical: z.enum(['fintech_payments', 'healthcare', 'retail_pos', 'enterprise_ops', 'generic']),
      outcome: z.enum(['permitted', 'blocked', 'pending_human_release', 'released_after_hitl']),
      started_at: z.string().datetime().optional(),
      completed_at: z.string().datetime().nullable().optional(),
    }),
    identity: z.object({
      primary_actor: primaryActorSchema,
      authority: z.object({
        scoped_role: z.string().min(1),
        permission_id: z.string().min(1),
        location_id: z.string().nullable().optional(),
        constraints_digest: hex64.nullable().optional(),
      }),
      human_release_actor: humanReleaseActorSchema.nullable().optional(),
    }),
    policy: z.object({
      policy_pack_id: z.string().min(1),
      policy_version_hash: hex64,
      treaty_name: z.string().nullable().optional(),
      decision: z.enum(['allow_within_ceiling', 'require_hitl', 'deny', 'released']),
      thresholds: z.record(policyThresholdValueSchema).optional(),
      regulatory_framing: z.array(z.string()).nullable().optional(),
    }),
    hitl: z.object({
      required: z.boolean(),
      status: z.enum(['not_required', 'pending', 'signed', 'expired', 'rejected']),
      approval_request_id: z.string().uuid().nullable().optional(),
      required_role: z.string().nullable().optional(),
      manager_signed_at: z.string().datetime().nullable().optional(),
      dual_signature_kind: z.string().nullable().optional(),
      release_consumed: z.boolean().optional(),
      sla_due_at: z.string().datetime().nullable().optional(),
    }),
    side_effects: z.object({
      action: z.object({
        tool_name: z.string().min(1),
        verb: z.string().min(1),
        metric_name: z.string().nullable().optional(),
        metric_value: z.number().nullable().optional(),
        currency: z
          .string()
          .regex(/^[A-Z]{3}$/)
          .nullable()
          .optional(),
        /** Structural alignment inputs (KVR-102) — bound into intent_alignment evaluation. */
        target_path: z.string().nullable().optional(),
        target_host: z.string().nullable().optional(),
        execution_scopes: z.array(z.string()).max(16).optional(),
      }),
      effect_class: z.enum([
        'financial_void',
        'data_access',
        'configuration_change',
        'communication',
        'none',
      ]),
      summary: z.string().min(1),
      projected_liability_usd: z.number().nullable().optional(),
      blocked_reason: z.string().nullable().optional(),
    }),
    intent_context: intentContextSchema.optional(),
    /** KVR-102 — digest-bound when intent_context is present. */
    intent_alignment: intentAlignmentSchema.optional(),
    /** KVR-301 — parent ledger anchor for delegated / swarm child actions. */
    causal_lineage: causalLineageSchema.optional(),
    /** Proof Moat Phase 1 — external gateway decision bound to Aevesa entryHash. */
    gateway_attestation: gatewayAttestationSchema.optional(),
    /** Proof Moat Phase 3 — Kaptein path binding for multi-hop sessions. */
    partial_path: partialPathSchema.optional(),
    /** Wave 2.2 — explicit refusal profile for pre-execution denials. */
    receipt_profile: z.enum(['PERMITTED', 'DENIED', 'HITL_PENDING', 'HITL_RELEASED']).optional(),
    denial: z
      .object({
        pre_execution: z.literal(true),
        execution_occurred: z.literal(false),
        denial_stage: z.enum(['gateway', 'pep', 'hitl', 'runtime_firewall', 'intent_alignment']),
        source: z.string().max(128).optional(),
      })
      .optional(),
    refusal_alignment: z
      .object({
        profile: z.string().min(1),
        mapping_version: z.string().min(1),
        reference: z.string().min(1),
        scitt_event_type: z.string().optional(),
        mapped_fields: z.array(z.string()).optional(),
        evidence_hash: z.string().nullable().optional(),
        kovera_receipt_profile: z.string().optional(),
      })
      .optional(),
    /** Tier 1 — SCITT Agent Interaction Record draft alignment metadata. */
    air_alignment: z
      .object({
        profile: z.string().min(1),
        agent_interaction_record: z
          .object({
            agent_id: z.string().nullable().optional(),
            session_id: z.string().nullable().optional(),
            correlation_id: z.string().nullable().optional(),
            action_tool: z.string().nullable().optional(),
            entry_hash: z.string().nullable().optional(),
            issued_at: z.string().nullable().optional(),
            policy_decision: z.string().nullable().optional(),
          })
          .optional(),
        evidence_custodian_role: z.string().optional(),
        compliance_mappings: z.array(z.string()).optional(),
      })
      .optional(),
    proof: z.object({
      ledger_spec: z.literal('aegis/1'),
      primary_anchor: z.object({
        entry_hash: hex64,
        event_type: z.string().min(1),
        timestamp: z.string().datetime().optional(),
      }),
      secondary_anchors: z
        .array(
          z.object({
            entry_hash: hex64,
            event_type: z.string().min(1),
            timestamp: z.string().datetime().optional(),
          }),
        )
        .optional(),
      proof_of_action_bundle_id: z.string().nullable().optional(),
      verification: z.object({
        status: z.enum(['verified', 'partial', 'unverified', 'demo']),
        methods: z.array(z.string()),
        verified_at: z.string().datetime().nullable().optional(),
        portal_urls: z
          .object({
            auditor_portal: z.string().url().optional(),
            truth_portal: z.string().url().optional(),
            open_evidence: z.string().optional(),
          })
          .optional(),
      }),
    }),
    integrity: z.object({
      receipt_digest: hex64,
      signature_alg: z.enum(['RS256', 'Ed25519', 'none']),
      signature: z.string().nullable().optional(),
      manifest_signature_jws: z.string().nullable().optional(),
    }),
    diligence_summary: z.object({
      who_acted: z.string().max(2000),
      what_policy_allowed: z.string().max(2000),
      what_proof_says: z.string().max(2000),
      executive_headline: z.string().max(280).nullable().optional(),
      control_effectiveness: z
        .enum(['effective', 'effective_with_exceptions', 'not_effective', 'not_assessed'])
        .optional(),
      recommended_auditor_actions: z.array(z.string()).max(8).optional(),
    }),
    _meta: z.record(z.unknown()).optional(),
  })
  .strict();

const privacyEnvelopeSchema = z
  .object({
    envelope_version: z.string().min(1),
    subject_id: hex64,
    encrypted_fields: z.record(z.unknown()).nullable().optional(),
    shredded_at: z.string().datetime().nullable().optional(),
    erasure_certificate_id: z.string().uuid().nullable().optional(),
  })
  .strict();

export const liabilityReceiptV2ZodSchema = liabilityReceiptV1ZodSchema
  .omit({ schema: true })
  .extend({
    schema: z.literal('liability-receipt/v2'),
    privacy: privacyEnvelopeSchema.optional(),
  })
  .strict();

export type ParsedLiabilityReceipt = z.infer<typeof liabilityReceiptV1ZodSchema>;
export type ParsedLiabilityReceiptV2 = z.infer<typeof liabilityReceiptV2ZodSchema>;

export function parseLiabilityReceiptStructure(
  receiptData: unknown,
):
  | { ok: true; receipt: ParsedLiabilityReceipt | ParsedLiabilityReceiptV2; version: 'v1' | 'v2' }
  | { ok: false; error: string } {
  if (receiptData != null && typeof receiptData === 'object' && (receiptData as { schema?: string }).schema === 'liability-receipt/v2') {
    const parsed = liabilityReceiptV2ZodSchema.safeParse(receiptData);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const path = issue?.path?.length ? issue.path.join('.') : 'root';
      return { ok: false, error: `Structural validation failed at ${path}: ${issue?.message ?? 'invalid'}` };
    }
    return { ok: true, receipt: parsed.data, version: 'v2' };
  }
  const parsed = liabilityReceiptV1ZodSchema.safeParse(receiptData);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue?.path?.length ? issue.path.join('.') : 'root';
    return { ok: false, error: `Structural validation failed at ${path}: ${issue?.message ?? 'invalid'}` };
  }
  return { ok: true, receipt: parsed.data, version: 'v1' };
}
