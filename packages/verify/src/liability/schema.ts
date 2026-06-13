import { z } from 'zod';
import { causalLineageSchema } from './causalLineageSchema.js';
import { intentContextSchema } from './intentContext.js';
import { intentAlignmentSchema } from './intentAlignmentSchema.js';

const hex64 = z.string().regex(/^[a-f0-9]{64}$/);

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
      thresholds: z.record(z.union([z.number(), z.string(), z.boolean()])).optional(),
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

export type ParsedLiabilityReceipt = z.infer<typeof liabilityReceiptV1ZodSchema>;

export function parseLiabilityReceiptStructure(
  receiptData: unknown,
): { ok: true; receipt: ParsedLiabilityReceipt } | { ok: false; error: string } {
  const parsed = liabilityReceiptV1ZodSchema.safeParse(receiptData);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue?.path?.length ? issue.path.join('.') : 'root';
    return { ok: false, error: `Structural validation failed at ${path}: ${issue?.message ?? 'invalid'}` };
  }
  return { ok: true, receipt: parsed.data };
}
