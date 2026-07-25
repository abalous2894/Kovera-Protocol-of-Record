import { z } from 'zod';

const hex64 = z.string().regex(/^[a-f0-9]{64}$/);

/** Aevesa Proof Moat Phase 1 — external gateway decision bound to liability-receipt/v1. */
export const gatewayAttestationSchema = z
  .object({
    gateway_decision_id: z.string().min(1).max(512),
    gateway_source: z.enum([
      'databricks_unity_ai',
      'portkey',
      'microsoft_agent_365',
      'zscaler_ai_protect',
      'wiz_ai_spm',
      'azure_apim',
      'bedrock',
      'generic_otlp',
      'generic_webhook',
    ]),
    decision: z.enum(['permit', 'deny']),
    gateway_event_hash: hex64.optional(),
    data_classification_tag: z.string().max(256).nullable().optional(),
    policy_reference: z.string().max(512).nullable().optional(),
    evaluated_at: z.string().datetime().optional(),
  })
  .strict();

export type GatewayAttestation = z.infer<typeof gatewayAttestationSchema>;
