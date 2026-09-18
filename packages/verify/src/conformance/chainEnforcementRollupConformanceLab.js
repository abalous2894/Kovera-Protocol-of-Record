/**
 * Offline conformance lab for aevesa.chain-enforcement-rollup-conformance/v1 (Wave 16-C).
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  rollupChainEnforcement,
  CHAIN_ENFORCEMENT_ROLLUP_SCHEMA,
} from '../../dist/index.js';

export const CHAIN_ENFORCEMENT_ROLLUP_CONFORMANCE_PROGRAM =
  'aevesa.chain-enforcement-rollup-conformance/v1';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_FIXTURES_DIR = join(
  __dirname,
  '../../../../diligence-kit/samples/conformance-lab/chain-enforcement-rollup/fixtures',
);

/**
 * @param {{ fixturesDir?: string; repoRoot?: string }} [opts]
 */
export function runChainEnforcementRollupConformanceLab(opts = {}) {
  const startedAt = Date.now();
  const fixturesDir =
    opts.fixturesDir ??
    (opts.repoRoot
      ? join(
          opts.repoRoot,
          'diligence-kit/samples/conformance-lab/chain-enforcement-rollup/fixtures',
        )
      : DEFAULT_FIXTURES_DIR);

  if (!existsSync(fixturesDir)) {
    return {
      ok: false,
      id: 'chain-enforcement-rollup/v1',
      program: CHAIN_ENFORCEMENT_ROLLUP_CONFORMANCE_PROGRAM,
      test: 'npm run test:chain-enforcement-conformance-lab',
      steps: [
        {
          step: 'load_rollup_fixtures',
          ok: false,
          error: `fixtures dir missing: ${fixturesDir}`,
        },
      ],
      elapsed_ms: Date.now() - startedAt,
      fixtures_passed: 0,
      fixtures_total: 0,
    };
  }

  const files = readdirSync(fixturesDir).filter((f) => f.endsWith('.json'));
  /** @type {object[]} */
  const steps = [];
  let fixturesPassed = 0;

  for (const file of files) {
    const fixture = JSON.parse(readFileSync(join(fixturesDir, file), 'utf8'));
    const label = String(fixture.label || file);
    const result = rollupChainEnforcement(fixture.input ?? {});
    const schemaOk = result.schema === CHAIN_ENFORCEMENT_ROLLUP_SCHEMA;
    const modeOk = result.chain_enforcement_mode === fixture.expected?.chain_enforcement_mode;
    const uniformOk = result.uniformly_enforced === fixture.expected?.uniformly_enforced;
    const weakestOk = result.weakest_link_index === fixture.expected?.weakest_link_index;
    const ok = schemaOk && modeOk && uniformOk && weakestOk;
    if (ok) fixturesPassed += 1;
    steps.push({
      step: label,
      ok,
      fixture: file,
      chain_enforcement_mode: result.chain_enforcement_mode,
      uniformly_enforced: result.uniformly_enforced,
      weakest_link_index: result.weakest_link_index,
    });
  }

  const elapsed_ms = Date.now() - startedAt;
  const ok = fixturesPassed === files.length && files.length > 0;

  return {
    ok,
    id: 'chain-enforcement-rollup/v1',
    program: CHAIN_ENFORCEMENT_ROLLUP_CONFORMANCE_PROGRAM,
    test: 'npm run test:chain-enforcement-conformance-lab',
    steps,
    elapsed_ms,
    fixtures_passed: fixturesPassed,
    fixtures_total: files.length,
    detail: ok
      ? `${fixturesPassed}/${files.length} rollup fixtures passed`
      : `${fixturesPassed}/${files.length} rollup fixtures passed (expected ${files.length})`,
  };
}

export default { runChainEnforcementRollupConformanceLab };
