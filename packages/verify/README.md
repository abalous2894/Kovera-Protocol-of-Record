# @kovera/verify

Stateless cryptographic verification for **Kovera `liability-receipt/v1`** (Verified Autonomous Sessions).

## Open-core boundary

| Open (this package) | Commercial (Kovera platform) |
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
import { verifyReceipt, computeReceiptDigest } from '@kovera/verify';

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

The **aegis/1** and **Art. 12** commands below require `kovera-sovereign-ledger-spec.md`, which is **not** shipped in the public protocol repo. Run them from the full Kovera monorepo or pass `--spec` to a local copy of that document.

See **SECURITY.md** at the protocol repository root (`docs/standards/SECURITY.md` in the private monorepo) for test-fixture signing notes and `contact@kovera.tech`.

## Legacy ledger / Art. 12 CLI (full monorepo)

The **aegis/1** reference CLI and ledger exports remain under:

```bash
node packages/verify/src/cli.js verify-spec-vectors --spec path/to/kovera-sovereign-ledger-spec.md
# programmatic: import from '@kovera/verify/ledger'
```

## Smoke test

```bash
npm run test:liability-receipt
```
