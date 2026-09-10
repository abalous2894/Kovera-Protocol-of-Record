/**
 * Parse FORGE-style Datalog facts from aevesa.path-datalog-export/v1.
 */

const FACT_SESSION = /^session\("((?:\\.|[^"\\])*)"\)\.$/;
const FACT_STEP = /^step\("((?:\\.|[^"\\])*)", (\d+), "((?:\\.|[^"\\])*)", "((?:\\.|[^"\\])*)"\)\.$/;
const FACT_READ_COUNT = /^read_count\("((?:\\.|[^"\\])*)", (\d+)\)\.$/;
const FACT_STEP_COUNT = /^step_count\("((?:\\.|[^"\\])*)", (\d+)\)\.$/;
const FACT_PROPOSED = /^proposed\("((?:\\.|[^"\\])*)", "((?:\\.|[^"\\])*)"\)\.$/;
const FACT_DESTRUCTIVE_BURST = /^destructive_burst\("((?:\\.|[^"\\])*)", (\d+)\)\.$/;

function unescapeAtom(value) {
  return String(value || '').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

/**
 * @param {string[]} facts
 */
export function parseDatalogFacts(facts) {
  const errors = [];
  if (!Array.isArray(facts) || facts.length === 0) {
    return { ok: false, errors: ['facts array required'], parsed: null };
  }

  /** @type {string | null} */
  let sessionId = null;
  /** @type {{ toolName: string, verdict: string }[]} */
  const steps = [];
  let readCount = null;
  let stepCount = null;
  /** @type {string | null} */
  let proposedTool = null;
  let destructiveBurst = null;

  for (const raw of facts) {
    const fact = String(raw || '').trim();
    if (!fact) continue;

    let m = fact.match(FACT_SESSION);
    if (m) {
      sessionId = unescapeAtom(m[1]);
      continue;
    }

    m = fact.match(FACT_STEP);
    if (m) {
      const sid = unescapeAtom(m[1]);
      if (sessionId && sid !== sessionId) {
        errors.push('mixed session ids in facts');
      } else if (!sessionId) {
        sessionId = sid;
      }
      steps.push({
        toolName: unescapeAtom(m[3]),
        verdict: unescapeAtom(m[4]),
      });
      continue;
    }

    m = fact.match(FACT_READ_COUNT);
    if (m) {
      readCount = Number(m[2]);
      continue;
    }

    m = fact.match(FACT_STEP_COUNT);
    if (m) {
      stepCount = Number(m[2]);
      continue;
    }

    m = fact.match(FACT_PROPOSED);
    if (m) {
      proposedTool = unescapeAtom(m[2]);
      continue;
    }

    m = fact.match(FACT_DESTRUCTIVE_BURST);
    if (m) {
      destructiveBurst = Number(m[2]);
    }
  }

  if (!sessionId) errors.push('session fact missing');
  if (!proposedTool) errors.push('proposed fact missing');

  const computedReadCount = steps.filter((s) =>
    ['read_file', 'list_directory', 'search_files', 'get_file_tree'].includes(s.toolName),
  ).length;
  if (readCount != null && readCount !== computedReadCount) {
    errors.push(`read_count fact (${readCount}) != computed (${computedReadCount})`);
  }

  if (stepCount != null && stepCount !== steps.length) {
    errors.push(`step_count fact (${stepCount}) != parsed steps (${steps.length})`);
  }

  return {
    ok: errors.length === 0,
    errors,
    parsed: errors.length
      ? null
      : {
          sessionId,
          steps,
          readCount: readCount ?? computedReadCount,
          stepCount: stepCount ?? steps.length,
          proposedTool,
          destructiveBurst,
        },
  };
}

export default { parseDatalogFacts };
