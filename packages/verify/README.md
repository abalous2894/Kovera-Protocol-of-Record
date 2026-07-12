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

```bash
cd packages/verify && npm install && npm run build
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
# → sentinul-app-site/src/js/aevesa-verify.bundle.js
```

From the monorepo root: `npm run test:verify` (builds the bundle and runs `test:verify-ci`).

**Deploy policy (Strategy A):** The bundle is **committed** to `sentinul-app-site/src/js/aevesa-verify.bundle.js` (not gitignored). After changing verify code run `npm run build:browser --workspace=@aevesa/verify` and commit the regenerated bundle before deploy. CI enforces sync via `npm run check:browser-bundle-sync --workspace=@aevesa/verify`.

## Smoke test

```bash
npm run test:liability-receipt
npm run test:verify-ci
```
