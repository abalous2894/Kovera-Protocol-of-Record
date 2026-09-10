import { z } from 'zod';
import {
  ATTEST_MCP_MANIFEST_PROFILE,
  TOOL_MANIFEST_ABSENT_REASONS,
  TOOL_MANIFEST_FINGERPRINT_SCHEMA,
} from '../core/toolManifestFingerprint.js';

const hex64 = z.string().regex(/^[a-f0-9]{64}$/);

/** Wave 9 Track R — optional MCP manifest bind on liability-receipt/v1. */
export const toolManifestFingerprintSchema = z
  .object({
    schema: z.literal(TOOL_MANIFEST_FINGERPRINT_SCHEMA),
    present: z.boolean(),
    manifest_fingerprint: hex64.optional(),
    tool_composite_hash: hex64.optional(),
    mcp_server_id: z.string().max(256).nullable().optional(),
    tool_name: z.string().max(256).nullable().optional(),
    manifest_version: z.number().int().positive().optional(),
    attest_profile: z.string().max(128).optional(),
    external_attestation_ref: z.string().max(512).nullable().optional(),
    captured_at: z.string().datetime().optional(),
    session_id: z.string().max(256).nullable().optional(),
    provider_id: z.string().max(128).optional(),
    absent_reason: z
      .union([z.enum(TOOL_MANIFEST_ABSENT_REASONS), z.string().max(128)])
      .nullable()
      .optional(),
    bind_digest: hex64,
  })
  .strict()
  .superRefine((val, ctx) => {
    if (val.present === true) {
      if (!val.manifest_fingerprint) {
        ctx.addIssue({
          code: 'custom',
          path: ['manifest_fingerprint'],
          message: 'manifest_fingerprint is required when present is true',
        });
      }
      if (!val.tool_composite_hash) {
        ctx.addIssue({
          code: 'custom',
          path: ['tool_composite_hash'],
          message: 'tool_composite_hash is required when present is true',
        });
      }
      if (val.attest_profile && val.attest_profile !== ATTEST_MCP_MANIFEST_PROFILE) {
        ctx.addIssue({
          code: 'custom',
          path: ['attest_profile'],
          message: `attest_profile must be ${ATTEST_MCP_MANIFEST_PROFILE} when set`,
        });
      }
    } else if (val.absent_reason == null || String(val.absent_reason).trim() === '') {
      ctx.addIssue({
        code: 'custom',
        path: ['absent_reason'],
        message: 'absent_reason is required when present is false',
      });
    }
  });

export type ToolManifestFingerprint = z.infer<typeof toolManifestFingerprintSchema>;
