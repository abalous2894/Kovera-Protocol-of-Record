#!/usr/bin/env node
/**
 * kovera — reference implementation CLI for kovera-sovereign-ledger-spec.md
 *
 * Exit codes: 0 verified | 1 mismatch | 2 file/config error
 */

import { Command } from 'commander';
import { runArt12PackCommand } from './commands/art12-pack.js';
import { runLedgerRowCommand } from './commands/ledger-row.js';
import { runVerifySpecVectorsCommand } from './commands/verify-spec-vectors.js';
import { ExitCode } from './exitCodes.js';

const program = new Command();

program
  .name('kovera')
  .description('Kovera sovereign ledger reference verifier (@kovera/verify)')
  .version('0.1.0');

program
  .command('art12-pack')
  .description('Validate Art. 12 Conformity Pack manifest signature and file_integrity')
  .argument('<path>', 'Path to .zip archive or extracted pack directory')
  .option('--secret <key>', 'COMPLIANCE_PACK_SIGNING_SECRET override')
  .option('--json', 'Emit machine-readable JSON')
  .action((packPath, opts) => {
    if (opts.secret) process.env.COMPLIANCE_PACK_SIGNING_SECRET = opts.secret;
    const code = runArt12PackCommand(packPath, opts);
    process.exit(code);
  });

program
  .command('ledger-row')
  .description('Validate aegis/1 entryHash (and optional contextHash) for a ledger row JSON export')
  .argument('<path>', 'Path to ledger row JSON (Mongo AuditLog shape)')
  .option('--prev-context-hash <hash>', 'Previous row contextHash when verifying context chain offline')
  .option('--skip-proof-of-intent', 'Skip proof-of-intent layer')
  .option('--json', 'Emit machine-readable JSON')
  .action((jsonPath, opts) => {
    const code = runLedgerRowCommand(jsonPath, {
      prevContextHash: opts.prevContextHash,
      skipProofOfIntent: opts.skipProofOfIntent,
      json: opts.json,
    });
    process.exit(code);
  });

program
  .command('verify-spec-vectors')
  .description('Run golden test vectors from kovera-sovereign-ledger-spec.md against this engine')
  .option('--spec <path>', 'Path to spec markdown (default: docs/spec/kovera-sovereign-ledger-spec.md)')
  .option('--json', 'Emit machine-readable JSON')
  .action((opts) => {
    const code = runVerifySpecVectorsCommand({ specPath: opts.spec, json: opts.json });
    process.exit(code);
  });

program.showHelpAfterError();
program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.help();
  process.exit(ExitCode.FILE_ERROR);
}
