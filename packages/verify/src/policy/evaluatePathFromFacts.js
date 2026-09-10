/**
 * Offline Kaptein path policy re-evaluation from parsed Datalog facts.
 * Mirrors private-backend pathAwarePolicyEngine.evaluatePathFromState (deterministic).
 */

const READ_TOOLS = new Set(['read_file', 'list_directory', 'search_files', 'get_file_tree']);
const DESTRUCTIVE_TOOLS = new Set([
  'execute_command',
  'run_bash',
  'shell',
  'delete_file',
  'write_file',
  'create_file',
]);
const EXPORT_TOOLS = new Set(['export_file', 'export_data', 'download_file', 'bulk_export', 'write_file', 'create_file']);

/**
 * @param {{ steps?: { toolName: string, verdict?: string }[], readCount?: number, stepCount?: number, destructiveBurst?: number | null }} parsed
 * @param {string} proposedTool
 * @param {{ maxReadsBeforeDestructive?: number }} [params]
 */
export function evaluatePathFromFacts(parsed, proposedTool, params = {}) {
  const maxReads = Number(params.maxReadsBeforeDestructive ?? 12);
  const threshold = Number.isFinite(maxReads) && maxReads > 0 ? Math.min(maxReads, 500) : 12;

  const prior = parsed?.steps ?? [];
  const toolName = String(proposedTool || parsed?.proposedTool || '').trim() || '(unknown)';
  const readCount = parsed?.readCount ?? prior.filter((s) => READ_TOOLS.has(s.toolName)).length;
  const destructive = DESTRUCTIVE_TOOLS.has(toolName);
  const exportClass = EXPORT_TOOLS.has(toolName);
  const hitlReleased = prior.some((s) => s.verdict === 'HITL_RELEASED');

  const pathWitness = {
    sessionId: parsed?.sessionId ?? null,
    proposedTool: toolName,
    stepIndex: prior.length,
    readCountPrior: readCount,
    priorSteps: prior.slice(-32),
  };

  if (exportClass && readCount >= threshold && !hitlReleased) {
    return {
      allow: false,
      code: 'PATH_READ_VELOCITY_DESTRUCTIVE',
      message: `Execution path blocked: ${readCount} read-class tools without human witness before export ${toolName}.`,
      pathWitness,
      matched_engine_code: 'PATH_READ_VELOCITY_DESTRUCTIVE',
    };
  }

  if (destructive && readCount >= threshold && !hitlReleased) {
    return {
      allow: false,
      code: 'PATH_READ_VELOCITY_DESTRUCTIVE',
      message: `Execution path blocked: ${readCount} read-class tools without human witness before destructive ${toolName}.`,
      pathWitness,
      matched_engine_code: 'PATH_READ_VELOCITY_DESTRUCTIVE',
    };
  }

  if (prior.length >= 80 && destructive) {
    const recentDestructive = prior.slice(-10).filter((s) => DESTRUCTIVE_TOOLS.has(s.toolName)).length;
    const burst = parsed?.destructiveBurst ?? recentDestructive;
    if (burst >= 5) {
      return {
        allow: false,
        code: 'PATH_DESTRUCTIVE_BURST',
        message: 'Execution path blocked: destructive tool burst on long session without cooldown.',
        pathWitness,
        matched_engine_code: 'PATH_DESTRUCTIVE_BURST',
      };
    }
  }

  return {
    allow: true,
    code: 'PATH_ALLOW',
    message: 'Path-aware evaluation passed.',
    pathWitness,
    matched_engine_code: 'PATH_ALLOW',
  };
}

/**
 * @param {string} engineCode
 * @param {object} policyPack
 */
export function matchKapteinPolicies(engineCode, policyPack) {
  const policies = Array.isArray(policyPack?.policies) ? policyPack.policies : [];
  return policies
    .filter((p) => p.engine_code === engineCode)
    .map((p) => ({
      id: p.id,
      name: p.name,
      eu_ai_act_framing: p.eu_ai_act_framing ?? null,
      datalog_rule: p.datalog_rule ?? null,
    }));
}

export default { evaluatePathFromFacts, matchKapteinPolicies };
