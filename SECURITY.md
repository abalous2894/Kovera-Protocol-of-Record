# Security — Kovera Protocol of Record

## Reporting vulnerabilities

If you discover a security issue in this repository (specifications, schemas, or `@aevesa/verify`), report it privately:

**Email:** [security@aevesa.com](mailto:security@aevesa.com)

Please include steps to reproduce, affected files or versions, and impact. Do not open public GitHub issues for undisclosed vulnerabilities.

---

## Public test signing fixtures (not production secrets)

This repository intentionally ships **published conformance secrets** used only for offline golden-vector tests. They are **not** production HMAC keys and must not be used to secure live systems.

| Identifier | Value | Purpose |
|------------|-------|---------|
| `SPEC_TEST_VECTOR_SIGNING_SECRET` | `spec-test-vector-secret-v1` | Art. 12 / spec vector tests in `@aevesa/verify` (`goldenVectors.js`, `art12Manifest.js`) |
| Dev Art. 12 fallback | `dev-compliance-pack-signing-not-for-production` | Local CLI only when `COMPLIANCE_PACK_SIGNING_SECRET` is unset (non-production) |

**Production** conformity packs and live ledger signing use secrets configured via environment variables on the Aevesa platform (`COMPLIANCE_PACK_SIGNING_SECRET`, tenant keys, etc.). Those values are never committed to this public repository.

---

## What this repo does not contain

- API keys, JWT secrets, or `INTERNAL_SERVICE_KEY`
- Database connection strings or tenant data
- Private backend, dashboard, or enforcement-plane source code
- Built artifacts (`node_modules/`, `dist/`) — install and build locally after clone

---

## Scope of verification tooling

The open **`@aevesa/verify`** package in this repo is the reference implementation for **`liability-receipt/v1`** (stateless `verifyReceipt`, `computeReceiptDigest`).

Legacy **aegis/1** and **Art. 12** CLI commands (`verify-spec-vectors`, `ledger-row`, `art12-pack`) may require the full **kovera-sovereign-ledger-spec** document, which is maintained in the Aevesa product monorepo and diligence kit—not bundled here. Use `verifyReceipt` and `npm run test:liability-receipt` for protocol-only conformance in this repository.
