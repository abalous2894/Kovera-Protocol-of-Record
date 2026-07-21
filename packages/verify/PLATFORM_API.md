# @aevesa/verify — Platform API

**Bounded context:** BC-VER Cryptographic Verification  
**Stability tier:** T0 (slowest change velocity) — see [PROTOCOL_COMPATIBILITY_POLICY.md](.././PROTOCOL_COMPATIBILITY_POLICY.md)  
**Status:** Active · Phase 8 (2026-07-12)

This document is the **team-facing contract** for consumers of `@aevesa/verify`. Read it before adding imports from this package.

---

## What this package guarantees

- **Stateless verification** — no database, no network I/O in library code paths
- **Deterministic digests** — JCS canonicalization, receipt digest profiles, ledger preimage rules
- **Offline verifiability** — CLI and pack verify scripts work without Aevesa API access
- **Spec conformance** — golden vectors in `npm run test:verify-ci` gate regressions

Consumers may depend on **only** the export surfaces listed below. Deep imports (`packages/verify/src/...`, `@aevesa/verify/src/...`) are **forbidden** in runtime code (enforced by `npm run fitness:architecture:strict`).

---

## Public export surfaces (`package.json`)

| Import path | Built artifact | Intended consumers |
|-------------|----------------|-------------------|
| `@aevesa/verify` | `dist/index.js` | Backend, shared, dashboard, MCP, diligence scripts |
| `@aevesa/verify/ledger` | `src/ledgerExports.js` | Backend ledger sealing, pack generators, assurance |
| `@aevesa/verify/offline` | `src/offlinePromotionVerifier.js` | MCP plugin audit sync, offline promotion verify |
| `@aevesa/verify/core/stableStringify` | `dist/core/stableStringify.js` | Shared re-export, low-level canonical JSON |

### CLI binaries

| Bin | Entry | Role |
|-----|-------|------|
| `aevesa` | `src/cli.js` | Spec vectors, pack verify, developer tooling |
| `aevesa-verify` | `dist/aevesa-verify.js` | Built standalone verify binary |

---

## Root export (`@aevesa/verify`) — stable symbols

### Crypto primitives (shared kernel)

| Symbol | Purpose |
|--------|---------|
| `stableStringify` | Canonical JSON stringify (single repo-wide owner) |
| `sha256Utf8`, `sha256Buffer` | SHA-256 helpers |
| `isRecord` | Type guard for plain objects |
| `canonicalizeJcs`, `serializeJcs` | JCS number/string canonicalization |
| `assertNoForbiddenKeys` | Prototype-pollution guard for digest inputs |

### Liability receipt verification

| Symbol | Purpose |
|--------|---------|
| `verifyReceipt` | Full liability-receipt/v1 verification |
| `computeReceiptDigest`, `computeCanonicalReceiptDigest` | Digest profiles (permit, denied, intent-context) |
| `verifyReceiptDigestMatch` | Compare computed vs embedded digest |
| `verifyIntegritySignatures` | Ed25519 / integrity signature checks |
| `validateAccountabilityPillars` | Structural pillar validation |
| `verifyAnchorHashChain`, `verifyPolicyVersionHash` | Chain + policy hash checks |
| `liabilityReceiptV1ZodSchema`, `parseLiabilityReceiptStructure` | Structural parse |

### Intent & causal lineage

| Symbol | Purpose |
|--------|---------|
| `evaluateIntentAlignment`, `normalizeStructuralPayload` | KVR intent alignment scoring |
| `verifyIntentContextLedgerBinding`, `verifyCausalLineageLedgerBinding` | Ledger binding proofs |
| `extractCausalLineageFromPayload`, `canonicalizeCausalLineageForDigest` | Causal fields for receipts |

### Gateway & MCP attestation

| Symbol | Purpose |
|--------|---------|
| `canonicalizeGatewayAttestationForDigest` | Gateway attest digest input |
| `buildAttestMcpManifest`, `verifyToolAgainstManifest` | MCP tool manifest gate |
| `verifyCryptographicReceiptLeafDocument`, `verifyCryptographicReceiptChain` | Offline leaf/chain verify |

### Policy promotion (offline)

| Symbol | Purpose |
|--------|---------|
| `verifyPolicyPromotionProof` | Offline JWS promotion proof verify |

---

## Ledger export (`@aevesa/verify/ledger`) — stable symbols

| Symbol | Purpose |
|--------|---------|
| `sealAegisLedgerRow`, `verifyLedgerEntryPreimage` | Ledger row seal + preimage verify |
| `buildIntentContextFromSources`, `computeIntentContextDigest` | Intent context for ledger |
| `buildProofOfIntentFromSpecInput`, `verifyProofOfIntentForStoredRow` | Proof-of-intent binding |
| `signConformityPackManifest`, `verifyConformityPackManifestSignature` | Art. 12 pack manifest signing |
| `verifyArt12PackPath`, `verifyArt12PackDirectory` | Offline pack directory verify |
| `verifyDelegationChain`, `verifyHdpHopChain` | Delegation / HDP hop proofs |
| `validateDeniedReceiptProfile`, `buildDeniedReceiptProofSteps` | DENIED receipt profile |
| `validateIncidentCustodyPackManifest` | Art. 73 custody pack verify |
| `runSpecVectors`, `GOLDEN_VECTORS` | Conformance vector runner |

---

## Offline export (`@aevesa/verify/offline`)

| Symbol | Purpose |
|--------|---------|
| `verifyPolicyPromotionProof` | Policy promotion JWS verify (MCP audit sync) |

---

## Semver & breaking-change policy

| Version field | Policy |
|---------------|--------|
| `0.1.0` (current) | Pre-1.0 — additive changes are minor; breaking changes require `COMPAT:` ledger entry |
| Post-1.0 target | Semver: MAJOR = breaking digest/profile/verify API, MINOR = additive exports, PATCH = fixes |

**Breaking** (require `COMPAT:` + human approval per GUARDRAILS):

- Renaming or removing exported symbols
- Changing receipt digest profile key order or hash algorithm
- Tightening validation that fails previously passing golden vectors
- Removing `package.json` export paths

**Safe** (no version bump required):

- New optional exports
- New golden vectors that existing receipts still pass
- Internal refactors with unchanged public signatures

Process: [PROTOCOL_COMPATIBILITY_POLICY.md](.././PROTOCOL_COMPATIBILITY_POLICY.md) Appendix A + `CHANGELOG-LEDGER.md` `COMPAT:` entries.

---

## Explicit non-goals

Do **not** use `@aevesa/verify` for:

| Non-goal | Use instead |
|----------|-------------|
| Governance policy decisions (ALLOW/BLOCK/HITL) | `private-backend` gate services, `@aevesa/shared` policy evaluators |
| Persisting ledger rows or witness logs | `private-backend` witness port (`governanceWitnessService`) |
| HTTP API route handlers | `private-backend/src/routes/` |
| React UI components | `sentinul-dashboard/` |
| Prisma / Mongo / Redis access | `private-backend/src/db/` |
| Duplicating `stableStringify` / `sha256` locally | Import from `@aevesa/verify` (fitness-enforced) |

---

## Consumer checklist

Before merging a PR that imports `@aevesa/verify`:

1. Import path is one of the four `package.json` exports — not a deep `src/` path
2. New symbol usage is listed above (or you added it to this doc + export map in the same PR)
3. `npm run test:verify` passes
4. Breaking changes have `COMPAT:` ledger entry and explicit user approval

---

## Related

- CONTEXT-MAP (Aevesa monorepo internal) BC-VER
- COGNITIVE_LOAD_MAP (Aevesa monorepo internal)
- ARCHITECTURE_FITNESS_BASELINE (Aevesa monorepo internal)
