import { z } from 'zod';
import {
  MEMORY_ABSENT_REASONS,
  MEMORY_COMMITMENT_KINDS,
  MEMORY_COMMITMENT_SCHEMA,
} from '../core/memoryCommitment.js';

const hex64 = z.string().regex(/^[a-f0-9]{64}$/);

/** Wave 9 Track Q — optional memory state commitment on liability-receipt/v1. */
export const memoryCommitmentSchema = z
  .object({
    schema: z.literal(MEMORY_COMMITMENT_SCHEMA),
    present: z.boolean(),
    memory_root_hash: hex64.optional(),
    vector_store_id: z.string().max(512).nullable().optional(),
    commitment_kind: z.enum(MEMORY_COMMITMENT_KINDS).optional(),
    captured_at: z.string().datetime().optional(),
    session_id: z.string().max(256).nullable().optional(),
    tool_name: z.string().max(256).nullable().optional(),
    entry_count: z.number().int().nonnegative().optional(),
    provider_id: z.string().max(128).optional(),
    absent_reason: z
      .union([z.enum(MEMORY_ABSENT_REASONS), z.string().max(128)])
      .nullable()
      .optional(),
    commitment_digest: hex64,
  })
  .strict()
  .superRefine((val, ctx) => {
    if (val.present === true) {
      if (!val.memory_root_hash) {
        ctx.addIssue({
          code: 'custom',
          path: ['memory_root_hash'],
          message: 'memory_root_hash is required when present is true',
        });
      }
    } else if (val.absent_reason == null || String(val.absent_reason).trim() === '') {
      ctx.addIssue({
        code: 'custom',
        path: ['absent_reason'],
        message: 'absent_reason is required when present is false (honest absent marker)',
      });
    }
  });

export type MemoryCommitment = z.infer<typeof memoryCommitmentSchema>;
