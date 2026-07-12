import { z } from 'zod';

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
        }),
      )
      .optional(),
    partial_path_hash: hex64,
  })
  .strict();

export type PartialPath = z.infer<typeof partialPathSchema>;
