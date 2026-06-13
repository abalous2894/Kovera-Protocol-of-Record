import { z } from 'zod';

export const intentAlignmentLevelSchema = z.enum(['ALIGNED', 'ELEVATED', 'CRITICAL']);

export const intentAlignmentSchema = z.object({
  score: z.number().min(0).max(1),
  level: intentAlignmentLevelSchema,
  signals: z.array(z.string().max(128)).max(16),
});

export type IntentAlignment = z.infer<typeof intentAlignmentSchema>;
