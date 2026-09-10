#!/usr/bin/env node
/**
 * aevesa — reference implementation CLI for kovera-sovereign-ledger-spec.md
 *
 * Exit codes: 0 verified | 1 mismatch | 2 file/config error
 */

import { Command } from 'commander';
import { runArt12PackCommand } from './commands/art12-pack.js';
import { runLedgerRowCommand } from './commands/ledger-row.js';
import { runVerifySpecVectorsCommand } from './commands/verify-spec-vectors.js';
import { runReplayBundleCommand } from './commands/replay-bundle.js';
import { runWitnessVerifyCommand } from './commands/witness-verify.js';
import { runConformanceRunCommand, runConformanceVerifyCommand } from './commands/conformance-run.js';
import { runPolicyProofVerifyCommand } from './commands/policy-proof-verify.js';
import {
  runPolicyProofTemplateExportCommand,
  runPolicyProofTemplateListCommand,
} from './commands/policy-proof-template.js';
import { runVerifyCommand } from './commands/verify-unified.js';
import { runVerifySessionCommand } from './commands/verify-session.js';
import { ExitCode } from './exitCodes.js';

const program = new Command();

program
  .name('aevesa')
  .description('Aevesa sovereign ledger reference verifier (@aevesa/verify)')
  .version('0.1.2');

program
  .command('verify-session')
  .description('Offline CAP session proof — compositional accountability (set-completeness + terminal receipt + partial_path)')
  .argument('<path>', 'Path to aevesa.compositional-accountability/v1 bundle JSON')
  .option('--json', 'Emit aevesa.session-proof-verify/v1 JSON only')
  .option('--summary', 'Human-readable verification summary')
  .option('--require-members', 'Require member_receipts array with full per-hop verification')
  .option('--require-custodian', 'Require evidence custodian profile on terminal receipt')
  .option('--require-policy-proof', 'Require aevesa.policy-proof-bundle/v1')
  .action((bundlePath, opts) => {
    const code = runVerifySessionCommand(bundlePath, {
      json: opts.json,
      summary: opts.summary,
      requireMembers: opts.requireMembers,
      requireCustodian: opts.requireCustodian,
      requirePolicyProof: opts.requirePolicyProof,
    });
    process.exit(code);
  });

program
  .command('verify')
  .description('Unified offline verify — auto-detect receipt, proof bundle, policy proof, attestation, witness export')
  .argument('[path]', 'Path to evidence JSON (or omit with --entry-hash)')
  .option('--entry-hash <hash>', '64-char ledger entry hash (fetches public evidence when online)')
  .option('--no-fetch', 'Do not fetch public API for entry-hash-only input')
  .option('--api-base <url>', 'Aevesa API base for --entry-hash fetch', 'https://api.aevesa.com')
  .option('--json', 'Emit aevesa.verification-report/v1 JSON')
  .option('--summary', 'Human-readable verification summary')
  .action(async (inputPath, opts) => {
    if (!inputPath && !opts.entryHash) {
      console.error('Provide <path> or --entry-hash');
      process.exit(ExitCode.FILE_ERROR);
    }
    const code = await runVerifyCommand(inputPath || '', {
      raw: opts.entryHash ? String(opts.entryHash).trim() : undefined,
      fetch: opts.fetch,
      apiBase: opts.apiBase,
      json: opts.json,
      summary: opts.summary,
    });
    process.exit(code);
  });

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

program
  .command('replay-bundle')
  .description('Reconstruct offline session timeline from a Proof-of-Action bundle JSON export')
  .argument('<path>', 'Path to proof-of-action bundle JSON')
  .option('--json', 'Emit aevesa.session-replay/v1 JSON only')
  .option('--summary', 'Human-readable timeline summary')
  .action((bundlePath, opts) => {
    const code = runReplayBundleCommand(bundlePath, opts);
    process.exit(code);
  });

program
  .command('witness-verify')
  .description('Offline SCITT refusal witness + inclusion proof verification (no Aevesa API)')
  .argument('<path>', 'Path to witness offline export JSON')
  .option('--json', 'Emit aevesa.scitt-refusal-witness-verify/v1 JSON only')
  .option('--summary', 'Human-readable verification summary')
  .action((bundlePath, opts) => {
    const code = runWitnessVerifyCommand(bundlePath, opts);
    process.exit(code);
  });

const conformance = program
  .command('conformance')
  .description('Aevesa Conformance Lab — probe deployments and emit portable attestation JSON');

conformance
  .command('run')
  .description('Run local interop + optional remote deployment probes; emit aevesa.conformance-attestation/v1')
  .option('--api-base <url>', 'Deployed Aevesa API base URL (e.g. https://api.example.com)')
  .option('--local-only', 'Skip remote probes; offline golden receipt interop only')
  .option('--fixture <path>', 'Path to local interop fixture JSON')
  .option('--output <path>', 'Write attestation JSON to file')
  .option('--timeout-ms <ms>', 'Remote probe timeout', '15000')
  .option('--json', 'Emit attestation JSON to stdout')
  .option('--summary', 'Human-readable attestation summary')
  .action(async (opts) => {
    const code = await runConformanceRunCommand({
      apiBase: opts.apiBase,
      localOnly: opts.localOnly,
      fixture: opts.fixture,
      output: opts.output,
      json: opts.json,
      summary: opts.summary,
      timeoutMs: opts.timeoutMs ? Number(opts.timeoutMs) : undefined,
    });
    process.exit(code);
  });

conformance
  .command('verify')
  .description('Offline verification of aevesa.conformance-attestation/v1 (digest + program results)')
  .argument('<path>', 'Path to attestation JSON')
  .option('--json', 'Emit verification result JSON only')
  .option('--summary', 'Human-readable verification summary')
  .action((attestationPath, opts) => {
    const code = runConformanceVerifyCommand(attestationPath, opts);
    process.exit(code);
  });

const policyProof = program
  .command('policy-proof')
  .description('Offline Kaptein path policy proof — verify DENY or export audit templates');

policyProof
  .command('verify')
  .description('Verify aevesa.policy-proof-bundle/v1 offline')
  .argument('<path>', 'Path to policy proof bundle JSON')
  .option('--json', 'Emit aevesa.policy-proof-verify/v1 JSON only')
  .option('--summary', 'Human-readable verification summary')
  .action((bundlePath, opts) => {
    const code = runPolicyProofVerifyCommand(bundlePath, opts);
    process.exit(code);
  });

const policyProofTemplate = policyProof.command('template').description('Downloadable Kaptein DENY audit packs');

policyProofTemplate
  .command('list')
  .description('List policy-as-proof templates')
  .option('--json', 'Emit template index JSON')
  .action((opts) => {
    const code = runPolicyProofTemplateListCommand(opts);
    process.exit(code);
  });

policyProofTemplate
  .command('export')
  .description('Export template bundle + Kaptein pack to directory')
  .argument('<id>', 'Template id (see template list)')
  .option('--output <dir>', 'Output directory', './aevesa-policy-proof-pack')
  .option('--json', 'Emit export result JSON')
  .action((templateId, opts) => {
    const code = runPolicyProofTemplateExportCommand(templateId, opts);
    process.exit(code);
  });

// Shorthand: aevesa policy-proof ./bundle.json
policyProof
  .argument('[path]', 'Shorthand for verify subcommand')
  .option('--json', 'Emit aevesa.policy-proof-verify/v1 JSON only')
  .option('--summary', 'Human-readable verification summary')
  .action((bundlePath, opts) => {
    if (!bundlePath) {
      console.error('Provide <path> or use: aevesa policy-proof verify <path>');
      process.exit(ExitCode.FILE_ERROR);
    }
    const code = runPolicyProofVerifyCommand(bundlePath, opts);
    process.exit(code);
  });

program.showHelpAfterError();
program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.help();
  process.exit(ExitCode.FILE_ERROR);
}
