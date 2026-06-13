import { z } from 'zod';

const hex64 = z.string().regex(/^[a-f0-9]{64}$/);

/** KVR-301 — parent swarm anchor digest-bound on child receipts when delegation occurred. */
export const causalLineageSchema = z
  .object({
    parent_entry_hash: hex64,
    parent_session_id: z.string().min(1).max(256).optional(),
    root_session_id: z.string().min(1).max(256).optional(),
  })
  .strict();

export type CausalLineage = z.infer<typeof causalLineageSchema>;
