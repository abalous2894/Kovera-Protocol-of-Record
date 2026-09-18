# @aevesa/verify

Stateless cryptographic verification for **Aevesa `liability-receipt/v1`** (Verified Autonomous Sessions).

## Open-core boundary

| Open (this package) | Commercial (Aevesa platform) |
|---------------------|------------------------------|
| Schema validation | Runtime intercept / gateway |
| `receipt_digest` preimage | HITL signing service |
| Anchor hash format & chain | Ledger write / tenant Aegis |
| Optional Ed25519 / RS256 verify | Policy packs & enforcement |

## Install (monorepo workspace)

Canonical install uses **pnpm** (see root `packageManager` and `pnpm-lock.yaml`):

```bash
# from repo root
corepack enable && pnpm install --frozen-lockfile
pnpm --filter @aevesa/verify run build
pnpm --filter @aevesa/verify run test:verify-ci
```

Root shortcut: `pnpm run test:verify` (browser bundle + full verify-ci + sync check).

**Do not** rely on `npm install` at the monorepo root — npm workspaces + pnpm lockfile can fail with arborist errors. After `pnpm install`, unit tests resolve vitest via `scripts/run-vitest.mjs` (no global `vitest` binary required).

Package-only npm (evaluators hacking on verify in isolation):

```bash
cd packages/verify && npm ci --workspaces=false && npm run build
```

## Install (npm — evaluators & CI)

```bash
npm install @aevesa/verify
# or one-shot:
npx @aevesa/verify verify evidence.json --summary
```

Requires Node.js 20+. No Aevesa account or API key for offline verification.

**Publish (maintainers):** from repo root after `npm login` with `@aevesa` scope access and **npm 2FA enabled** (or a granular publish token with bypass-2FA):

```bash
npm run publish:verify
```

Runs tarball smoke test (`test:npm-pack`) then publishes `@aevesa/verify` only (not the monorepo root).

If first publish is private (scoped default), make it public:

```bash
npm access set status=public @aevesa/verify
```

## API

```typescript
import { verifyReceipt, computeReceiptDigest } from '@aevesa/verify';

const result = verifyReceipt(receiptJson);
// { isValid: true, details: { chainLength: 2, pillarsValidated: [...] } }
```

### Verification steps (stateless)

1. Structural validation (Zod / `liability-receipt/v1`)
2. SHA-256 `receipt_digest` over canonical pillar JSON (integrity excluded)
3. `aegis/1` anchor hash format, uniqueness, optional `chain_preimage` linkage
4. `integrity.signature_alg` — `none` (default), or Ed25519 / RS256 with issuer public key
5. Cross-pillar rules (HITL + `released_after_hitl`, financial void, diligence narrative)

No database, HTTP, or environment configuration is required.

## Public protocol repository scope

In **[Kovera-Protocol-Of-Record](https://github.com/abalous2894/Kovera-Protocol-Of-Record)** (this package synced via `scripts/sync-public-protocol.sh`), the supported open-core path is:

- **`verifyReceipt()` / `computeReceiptDigest()`** for `liability-receipt/v1`
- **`npm run test:liability-receipt`** — offline smoke test

The **aegis/1** and **Art. 12** commands below require `kovera-sovereign-ledger-spec.md`, which is **not** shipped in the public protocol repo. Run them from the full Aevesa monorepo or pass `--spec` to a local copy of that document.

See **SECURITY.md** at the protocol repository root (`docs/standards/SECURITY.md` in the private monorepo) for test-fixture signing notes and `security@aevesa.com`.

## Legacy ledger / Art. 12 CLI (full monorepo)

The **aegis/1** reference CLI and ledger exports remain under:

```bash
node packages/verify/src/cli.js verify-spec-vectors --spec path/to/kovera-sovereign-ledger-spec.md
# programmatic: import from '@aevesa/verify/ledger'
```

## Browser bundle (verify.aevesa.com Tier A)

Client-side `liability-receipt/v1` verification for the static verify portal:

```bash
npm run build:browser
# → aevesa-app-site/src/js/aevesa-verify.bundle.js
```

From the monorepo root: `npm run test:verify` (builds the bundle and runs `test:verify-ci`).

**Deploy policy (Strategy A):** The bundle is **committed** to `aevesa-app-site/src/js/aevesa-verify.bundle.js` (not gitignored). After changing verify code run `npm run build:browser --workspace=@aevesa/verify` and commit the regenerated bundle before deploy. CI enforces sync via `npm run check:browser-bundle-sync --workspace=@aevesa/verify`.

## Unified verify (Phase A — one front door)

```bash
# Auto-detect evidence type; human summary
npx @aevesa/verify verify ./evidence.json --summary

# Machine-readable aevesa.verification-report/v1
npx @aevesa/verify verify ./evidence.json --json

# Entry hash only (fetches public receipt when online)
npx @aevesa/verify verify --entry-hash <64-hex> --summary
```

Monorepo dev (same commands via local CLI):

```bash
node packages/verify/src/cli.js verify ./evidence.json --summary
```

## CAP session proof (Phase 0 — compositional accountability)

Offline verification of multi-hop agent session proof bundles:

```bash
npx @aevesa/verify verify-session ./session-proof.json --summary
```

Schema: `aevesa.compositional-accountability/v1` — composes set-completeness manifest + terminal `liability-receipt/v1` + `partial_path` alignment. See [docs/standards/CAP_V1.md](../../docs/standards/CAP_V1.md).

```bash
npm run test:cap-conformance --workspace=@aevesa/verify
```

Evaluators: see [EVALUATORS.md](../../EVALUATORS.md) at repo root.

## Smoke test

```bash
npm run test:liability-receipt
npm run test:verify-ci          # full suite (vitest + script conformance)
npm run test:verify-ci:scripts-only   # no vitest — diligence / minimal env escape hatch
```
