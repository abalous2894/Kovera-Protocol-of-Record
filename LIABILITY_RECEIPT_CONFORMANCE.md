# Liability Receipt v1 — Conformance Clause

**Standard ID:** `liability-receipt/v1`  
**Status:** Published · **Phase:** Architecture debt knockout Phase 7  
**Normative schema:** [./liability-receipt-v1.json](./liability-receipt-v1.json)  
**Companion spec:** [./liability-receipt-v1.md](../standards/liability-receipt-v1.md)

This document lists **numbered conformance requirements** (MUST / SHALL) and maps each clause to automated tests in the Aevesa monorepo. Third parties may use the same tests against their own producer or verifier implementations.

---

## Conformance roles

| Role | Definition |
|------|------------|
| **Producer** | Mints `liability-receipt/v1` documents with sealed `integrity.receipt_digest` and ledger anchors before issuance. |
| **Consumer** | Parses receipts, rejects unknown schemas, never treats UI rendering as verification. |
| **Verifier** | Recomputes digests and optional ledger bindings offline or via public APIs without issuer credentials. |

---

## Aevesa Conformant badge

An implementation MAY claim **Aevesa Conformant — liability-receipt/v1** when **all** of the following hold:

1. **Verifier path (minimum):** `npm run test:verify` passes using `@aevesa/verify` (or an equivalent port of the same test vectors).
2. **Schema lock:** Documents use top-level `schema: "liability-receipt/v1"` and validate against [./liability-receipt-v1.json](./liability-receipt-v1.json).
3. **Digest integrity:** `integrity.receipt_digest` is SHA-256 over the canonical pillar set defined in `@aevesa/verify` (`computeReceiptDigest` / profile order in `RECEIPT_DIGEST_PROFILE_ORDER`).
4. **Reference producer suite (Aevesa platform):** the commands in [§ Reference conformance command block](#reference-conformance-command-block) exit 0 on `main`.

**Display (optional):**

```markdown
[![Aevesa Conformant — liability-receipt/v1](https://img.shields.io/badge/Kovera_Conformant-liability--receipt%2Fv1-059669?style=flat-square)](https://aevesa.com/schemas/liability-receipt/v1)
```

Link the badge to this document or your own conformance statement. **Conformance inquiries:** sales@aevesa.com

---

## Document identity and schema

| ID | Requirement | Test(s) |
|----|-------------|---------|
| **LR-D-001** | Top-level field `schema` MUST equal `liability-receipt/v1`. | `@aevesa/verify` → `npm run test:liability-receipt`; `parseLiabilityReceiptStructure` in `packages/verify/src/liability/schema.js` |
| **LR-D-002** | `receipt_id` MUST be a UUID stable for the life of the evidence record. | `@aevesa/verify` → `test:liability-receipt`; `private-backend` → `npm run test:kvr-401` |
| **LR-D-003** | Unknown `schema` values MUST be rejected by consumers. | `@aevesa/verify` → `verifyReceipt` negative paths in `test:liability-receipt` |

---

## Integrity and digest binding

| ID | Requirement | Test(s) |
|----|-------------|---------|
| **LR-I-001** | `integrity.receipt_digest` MUST be SHA-256 over canonical JSON pillars per active digest profile. | `@aevesa/verify` → `npm run test:digest-binding` |
| **LR-I-002** | Tampering any digest-bound field after seal MUST fail `verifyReceiptDigestMatch`. | `@aevesa/verify` → `test:digest-binding`; `private-backend` → `test:kvr-401` |
| **LR-I-003** | When `intent_context` is present, `intent_alignment` MUST be digest-bound (KVR-102). | `@aevesa/verify` → `test:digest-binding`, `npm run test:intent-alignment`, `test:intent-divergence` |
| **LR-I-004** | Legacy receipts without digest-bound `intent_alignment` MUST verify under `v1_intent_context` profile. | `@aevesa/verify` → `test:digest-binding` (profile fallback vectors) |
| **LR-I-005** | JCS (RFC 8785) receipt-leaf digests MUST match golden vectors. | `@aevesa/verify` → `npm run test:jcs-receipt-leaf` |

---

## Accountability pillars

| ID | Requirement | Test(s) |
|----|-------------|---------|
| **LR-P-001** | Identity pillar: `identity.primary_actor` and `identity.authority` MUST be populated for governed sessions. | `@aevesa/verify` → `validateAccountabilityPillars` via `test:liability-receipt` |
| **LR-P-002** | Policy pillar: `policy.policy_version_hash` MUST be 64-char hex; decision enum MUST be valid. | `@aevesa/verify` → `test:liability-receipt`; `verifyPolicyVersionHash` |
| **LR-P-003** | HITL pillar: when `hitl.required` is true for financial void profiles, outcome MUST NOT be `released_after_hitl` unless `hitl.status === 'signed'` and `hitl.release_consumed === true`. | `@aevesa/verify` → `test:liability-receipt`; `private-backend` → `test:kvr-103-kvr-202`, `test:month2-workforce-hitl` |
| **LR-P-004** | Side-effects pillar: summaries MUST NOT embed secrets, PAN, or raw prompts (auditor-safe). | Schema + producer review; `private-backend` → `test:proof-of-intent` (redaction paths) |
| **LR-P-005** | Proof pillar: `proof.primary_anchor.entry_hash` MUST be 64-char hex when present. | `@aevesa/verify` → `verifyAnchorHashChain`, `test:liability-receipt` |
| **LR-P-006** | `diligence_summary` MUST include `who_acted`, `what_policy_allowed`, and `what_proof_says`. | `@aevesa/verify` → `test:liability-receipt` |

---

## Extensions (optional fields)

| ID | Requirement | Test(s) |
|----|-------------|---------|
| **LR-E-001** | `causal_lineage` when present MUST be digest-bound and match ledger `parentEntryHash` (KVR-301). | `@aevesa/verify` → `npm run test:kvr-301`; `private-backend` → `npm run test:kvr-301` |
| **LR-E-002** | `gateway_attestation` when present MUST be canonicalized for digest (`gateway_decision_id`, `gateway_event_hash`). | `@aevesa/verify` → `canonicalizeGatewayAttestationForDigest`; `private-backend` → `npm run test:gateway-attest-conformance` |
| **LR-E-003** | `receipt_profile: DENIED` MUST imply `session.outcome: blocked` and pre-execution denial invariants. | `private-backend` → `npm run test:denied-receipt-conformance`; diligence sample `diligence-kit/samples/denied-receipt/` |
| **LR-E-004** | `partial_path` when present MUST pass `verifyPartialPathCommitment` (Proof Moat Phase 3). | `@aevesa/verify` → partial path unit coverage in `test:digest-binding` / schema tests |
| **LR-E-005** | MCP skill inventory hashes MUST conform to `aevesa.attest-mcp-manifest/v1`. | `@aevesa/verify` → `npm run test:attest-mcp-manifest` |

---

## Verification behavior

| ID | Requirement | Test(s) |
|----|-------------|---------|
| **LR-V-001** | Verifier MUST recompute `receipt_digest` before trusting display metadata. | `@aevesa/verify` → `verifyReceipt`; portal → `scripts/verify-portal-intent-sample.mjs` |
| **LR-V-002** | Verifier MUST NOT require Aevesa dashboard login for Tier A (digest + structure) checks. | Manual: [verify.aevesa.com](https://verify.aevesa.com); `@aevesa/verify` CLI → `npm run test:aevesa-verify-cli` |
| **LR-V-003** | Offline cryptographic receipt-leaf chain verification MUST detect digest mismatch and broken chains. | `@aevesa/verify` → `verifyCryptographicReceiptLeafDocument`, `verifyCryptographicReceiptChain` (via `test:jcs-receipt-leaf`) |
| **LR-V-004** | Public verify portal intent-divergence sample MUST pass Tier A verification. | `@aevesa/verify` → `scripts/verify-portal-intent-sample.mjs` |

---

## Evidence packs and diligence artifacts

| ID | Requirement | Test(s) |
|----|-------------|---------|
| **LR-A-001** | Committed diligence-kit samples MUST regenerate with zero git diff (deterministic packs). | Root → `npm run diligence-kit:check-repro` (CI `test-core`) |
| **LR-A-002** | Embedded pack verify scripts MUST be generated from single compliance-pack generator (no inline `buildVerifyScript`). | Root → `npm run compliance-pack:test-generator`; `npm run fitness:architecture:strict` |
| **LR-A-003** | Golden diligence verification scripts MUST pass offline. | Root → `npm run diligence-kit:verify` (CI `test-core`) |

---

## Architecture guardrails (Aevesa reference implementation)

| ID | Requirement | Test(s) |
|----|-------------|---------|
| **LR-G-001** | Runtime backend MUST NOT define local `sha256` or `stableStringify` (use `@aevesa/verify`). | Root → `npm run fitness:architecture:strict` |
| **LR-G-002** | Single Aegis client tree via `@aevesa/shared/aegis/*`. | Root → `fitness:architecture:strict` (`aegis-duplicate-tree`) |
| **LR-G-003** | Shared type guard `isRecord` MUST be imported from `@aevesa/shared` or `@aevesa/verify` (one canonical definition). | `@aevesa/verify` → `scripts/test-isRecord-export.mjs`; `scripts/architecture-fitness.mjs` (`is-record-def`) |

---

## Reference conformance command block

Run from repository root on a clean tree (matches CI `test-core` + verify suite):

```bash
# Tier 1 — verifier + architecture (required for badge)
npm run fitness:architecture:strict
npm run test:verify

# Tier 2 — Aevesa reference producer paths
cd private-backend && npm run test:gateway-attest-conformance
cd private-backend && npm run test:denied-receipt-conformance
cd private-backend && npm run test:kvr-103-kvr-202

# Tier 3 — diligence artifacts
npm run diligence-kit:check-repro
npm run diligence-kit:verify
npm run compliance-pack:test-generator
```

**CI aggregation:** root `npm run test:core` runs Tier 1 plus backend core validation (includes gateway attest generator smoke via `core-validation.mjs`).

---

## Traceability matrix (quick lookup)

| Package / area | Primary tests |
|----------------|---------------|
| `@aevesa/verify` | `npm run test:verify-ci` inside package (liability, intent-alignment, digest-binding, kvr-301, jcs-receipt-leaf, attest-mcp, CLI, isRecord export) |
| `private-backend` | `npm test` → `core-validation.mjs`; `test:gateway-attest-conformance`, `test:denied-receipt-conformance`, phase conformance scripts |
| Root / CI | `fitness:architecture:strict`, `diligence-kit:check-repro`, `diligence-kit:verify`, `compliance-pack:test-generator` |
| Verify portal | `verify-portal-intent-sample.mjs`; manual paste at verify.aevesa.com |

---

## Version history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-06-25 | Initial conformance clause + test map (Phase 7) |

---

*This document is normative for Aevesa's "Conformant" badge criteria. The human-readable standard remains [liability-receipt-v1.md](../standards/liability-receipt-v1.md).*
