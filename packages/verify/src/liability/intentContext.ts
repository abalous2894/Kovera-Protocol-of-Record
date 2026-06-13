import { z } from 'zod';

export const intentContextSchema = z.object({
  reasoning_summary: z.string().min(1).max(4096),
  model_fingerprint: z.string().min(1).max(256),
});

export type IntentContext = z.infer<typeof intentContextSchema>;
