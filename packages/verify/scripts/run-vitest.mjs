#!/usr/bin/env node
/**
 * Wave 15 Track D — resolve vitest CLI without relying on shell PATH / .bin symlinks.
 * Works after `pnpm install` at monorepo root (vitest in packages/verify/node_modules).
 */
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgRoot = join(__dirname, '..');
const requireFromPkg = createRequire(join(pkgRoot, 'package.json'));

/**
 * @returns {string}
 */
export function resolveVitestCliPath() {
  const local = join(pkgRoot, 'node_modules', 'vitest', 'vitest.mjs');
  if (existsSync(local)) return local;

  try {
    return requireFromPkg.resolve('vitest/vitest.mjs');
  } catch {
    /* fall through */
  }

  const hoisted = join(pkgRoot, '..', '..', 'node_modules', 'vitest', 'vitest.mjs');
  if (existsSync(hoisted)) return hoisted;

  return '';
}

/**
 * @param {string[]} [args]
 */
export function runVitest(args = []) {
  const vitestCli = resolveVitestCliPath();
  if (!vitestCli) {
    console.error(
      '[@aevesa/verify] vitest is not installed.\n' +
        '  Monorepo: from repo root run `pnpm install --frozen-lockfile` (or `corepack pnpm install`).\n' +
        '  Package-only: `cd packages/verify && npm ci --workspaces=false` when using npm with package-lock.json.\n' +
        '  Smoke-only CI: `npm run test:verify-ci:scripts-only --workspace=@aevesa/verify`',
    );
    process.exit(1);
  }

  const result = spawnSync(process.execPath, [vitestCli, ...args], {
    cwd: pkgRoot,
    stdio: 'inherit',
  });
  process.exit(result.status ?? 1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runVitest(process.argv.slice(2));
}
