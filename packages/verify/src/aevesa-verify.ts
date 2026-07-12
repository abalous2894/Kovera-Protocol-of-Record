#!/usr/bin/env node
/**
 * aevesa-verify — offline cryptographic receipt leaf verifier (JCS / RFC 8785).
 *
 * Usage:
 *   aevesa-verify --receipt ./receipt.json
 *   aevesa-verify --receipt ./receipt.json --chain ./receipts/
 *   aevesa-verify --receipt ./r.json --chain ./a.json,./b.json,./c.json
 */
import { resolve } from 'node:path';
import {
  loadReceiptJson,
  resolveChainPaths,
  verifyCryptographicReceiptChain,
  verifyCryptographicReceiptLeafDocument,
} from './offline/verifyCryptographicReceiptLeaf.js';

const ExitCode = { VERIFIED: 0, MISMATCH: 1, FILE_ERROR: 2 } as const;

const GREEN = '\x1b[32m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

function usage(): never {
  console.error(`Usage: aevesa-verify --receipt <path> [--chain <dir|file1,file2|json-array>]

Offline verification of Aevesa cryptographic receipt leaves (JCS / RFC 8785 + SHA-256).

Options:
  --receipt <path>   Path to a liability receipt or cryptographic-receipt-leaf JSON file
  --chain <spec>     Optional sequential chain: directory of .json files, comma-separated
                     paths, or JSON array string — verifies prevEntryHash linkage
  -h, --help         Show this help

Exit codes: 0 verified | 1 mismatch | 2 file/config error`);
  process.exit(ExitCode.FILE_ERROR);
}

function parseArgs(argv: string[]): { receipt: string; chain: string } {
  let receipt = '';
  let chain = '';
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') usage();
    if (arg === '--receipt' && argv[i + 1]) {
      receipt = argv[++i];
      continue;
    }
    if (arg.startsWith('--receipt=')) {
      receipt = arg.slice('--receipt='.length);
      continue;
    }
    if (arg === '--chain' && argv[i + 1]) {
      chain = argv[++i];
      continue;
    }
    if (arg.startsWith('--chain=')) {
      chain = arg.slice('--chain='.length);
    }
  }
  return { receipt, chain };
}

function printVerified(digest: string, receiptPath: string, chainCount?: number): void {
  console.log(`${GREEN}${BOLD}[VERIFIED]${RESET} ${GREEN}Aevesa cryptographic receipt leaf${RESET}`);
  console.log(`${GREEN}  digest:${RESET} ${digest}`);
  console.log(`${GREEN}  receipt:${RESET} ${receiptPath}`);
  if (chainCount != null && chainCount > 0) {
    console.log(`${GREEN}  chain:${RESET} ${chainCount} sequential receipt(s) linked`);
  }
}

function fail(message: string, detail?: Record<string, unknown>): never {
  console.error(`aevesa-verify: ${message}`);
  if (detail) {
    for (const [k, v] of Object.entries(detail)) {
      if (v != null && v !== '') console.error(`  ${k}: ${v}`);
    }
  }
  process.exit(ExitCode.MISMATCH);
}

function main(): void {
  const { receipt, chain } = parseArgs(process.argv.slice(2));
  if (!receipt) usage();

  const receiptPath = resolve(process.cwd(), receipt);
  const loaded = loadReceiptJson(receiptPath);
  if (!loaded.ok) {
    console.error(`aevesa-verify: ${loaded.error.message}`);
    process.exit(ExitCode.FILE_ERROR);
  }

  const single = verifyCryptographicReceiptLeafDocument(loaded.doc, receiptPath);
  if (!single.ok) {
    fail(single.message, {
      code: single.code,
      field: single.fieldPath,
      stored: single.storedDigest,
      recomputed: single.recomputedDigest,
      suspectFields: single.mutatedFields?.join(', '),
    });
  }

  let chainCount = 0;
  if (chain) {
    let paths: string[];
    try {
      paths = resolveChainPaths(chain);
    } catch (e) {
      console.error(`aevesa-verify: invalid --chain argument: ${e instanceof Error ? e.message : String(e)}`);
      process.exit(ExitCode.FILE_ERROR);
    }

    if (!paths.includes(receiptPath)) {
      paths = [receiptPath, ...paths.filter((p) => p !== receiptPath)];
    }

    const chainResult = verifyCryptographicReceiptChain(paths);
    if (!chainResult.ok) {
      if (chainResult.code === 'CHAIN_BROKEN') {
        fail(chainResult.message, {
          code: chainResult.code,
          index: chainResult.index,
          file: chainResult.sourcePath,
          expectedPrevEntryHash: chainResult.expectedPrevHash,
          actualPrevEntryHash: chainResult.actualPrevHash,
        });
      }
      fail(chainResult.message, {
        code: chainResult.code,
        index: chainResult.index,
        file: chainResult.sourcePath,
        leafError: chainResult.leafFailure?.message,
      });
    }
    chainCount = chainResult.count;
  }

  printVerified(single.recomputedDigest, receiptPath, chainCount);
  process.exit(ExitCode.VERIFIED);
}

main();
