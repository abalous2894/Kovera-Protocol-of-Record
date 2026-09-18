import { z } from 'zod';
import { ENFORCEMENT_MODES } from '../core/proofStrengthDisclosure.js';

const hex64 = z.string().regex(/^[a-f0-9]{64}$/);

/** Proof Moat Phase 3 — session path binding on liability-receipt/v1. */
export const partialPathSchema = z
  .object({
    schema: z.literal('aevesa.partial-path/v1'),
    session_id: z.string().nullable().optional(),
    proposed_action: z.string().nullable().optional(),
    step_index: z.number().int().nonnegative().optional(),
    read_count_prior: z.number().int().nonnegative().nullable().optional(),
    path_digest: hex64.nullable().optional(),
    partial_steps: z
      .array(
        z.object({
          index: z.number().int(),
          tool_name: z.string(),
          verdict: z.string().optional(),
          entry_hash: hex64.nullable().optional(),
          path_hint: z.string().max(512).nullable().optional(),
          args_digest: hex64.nullable().optional(),
          binding_digest: hex64.nullable().optional(),
          /** Wave 15+ — per-hop enforcement disclosure (additive; optional on legacy receipts) */
          enforcement_mode: z.enum(ENFORCEMENT_MODES).optional(),
        }),
      )
      .optional(),
    partial_path_hash: hex64,
    capability_budget: z
      .object({
        schema: z.literal('aevesa.capability-budget/v1'),
        sinks: z.object({
          external_network: z.boolean(),
          email: z.boolean(),
          database_write: z.boolean(),
          file_export: z.boolean(),
          shell_exec: z.boolean(),
        }),
        taint_class: z.enum(['confidential', 'internal']).nullable().optional(),
        budget_state_hash: hex64,
      })
      .optional(),
    permit_execution: z
      .object({
        schema: z.literal('aevesa.permit-execution-binding/v1'),
        step_bindings: z
          .array(
            z.object({
              index: z.number().int(),
              tool_name: z.string(),
              args_digest: hex64,
              binding_digest: hex64,
            }),
          )
          .optional(),
        binding_state_hash: hex64,
      })
      .optional(),
  })
  .strict();

export type PartialPath = z.infer<typeof partialPathSchema>;
