export declare const PERMIT_EXECUTION_BINDING_SCHEMA: 'aevesa.permit-execution-binding/v1';
export declare const MANIFEST_CUSTODIAN_SCHEMA: 'aevesa.session-manifest-custodian/v1';

export declare function canonicalizeToolArgs(value: unknown): unknown;
export declare function computeArgsDigest(args: unknown): string;
export declare function computeToolParamsBindingDigest(toolName: string, args: unknown): string;
export declare function buildPermitExecutionStepBinding(
  toolName: string,
  args: unknown,
): { args_digest: string; binding_digest: string };
export declare function buildPermitExecutionCommitment(
  partialSteps?: Array<{ index?: number; tool_name?: string; args_digest?: string | null; binding_digest?: string | null }>,
): Record<string, unknown>;
export declare function verifyPermitExecutionCommitment(block: unknown): { ok: boolean; code: string; [k: string]: unknown };
export declare function verifyPartialStepsPermitExecution(
  partialSteps: Array<{ tool_name?: string; args_digest?: string | null; binding_digest?: string | null }>,
  permitExecutionBlock?: unknown,
): { ok: boolean; code: string; errors?: string[]; [k: string]: unknown };
export declare function verifyMemberReceiptsArgsAlignment(
  partialSteps: Array<{ tool_name?: string; args_digest?: string | null }>,
  memberReceipts: unknown[],
): { ok: boolean; code: string; errors?: string[] };
export declare function buildManifestCustodianCommitment(input?: {
  session_id?: string;
  set_root?: string;
  witness_entry_hash?: string | null;
}): Record<string, unknown>;
export declare function verifyManifestCustodianCommitment(
  block: unknown,
  expected?: { set_root?: string; session_id?: string; witness_entry_hash?: string | null },
): { ok: boolean; code: string; [k: string]: unknown };
