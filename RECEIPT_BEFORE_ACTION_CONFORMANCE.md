# Aevesa Receipt-Before-Action Conformance

| | |
|---|---|
| **Program ID** | `receipt-before-action/v1` |
| **Invariant** | If the ledger cannot commit, the tool does not run. |
| **Status** | Published · June 2026 |
| **Canonical URL** | https://aevesa.com/schemas/receipt-before-action/v1 |
| **Reference implementation** | `private-backend/src/services/pep/pepReceiptCommitGate.js` |

---

## Abstract

High-risk agent tool paths MUST NOT execute until an immutable audit-grade ledger row is committed with a verifiable `entryHash`. This program defines the conformance surface for MCP bridges, AI gateways, and custom PEP integrations.

---

## Normative requirements

1. **Pre-execution commit** — Before returning `ALLOW` to the runtime, the integrator MUST append a ledger row (or equivalent tamper-evident log) and obtain a non-empty `entryHash`.
2. **Fail-closed** — If commit fails, times out, or returns no `entryHash`, the integrator MUST deny tool execution and surface error code `PEP_RECEIPT_COMMIT_FAILED`.
3. **Payload marker** — Committed rows SHOULD include `pepInvariant: "receipt_before_action/v1"` and `decisionPhase: "pre_execution"`.
4. **No silent bypass** — Production deployments MUST NOT disable the invariant except in explicit audit-only mode documented out-of-band.

---

## Environment variables (Aevesa reference)

| Variable | Default | Description |
|----------|---------|-------------|
| `AEVESA_PEP_RECEIPT_BEFORE_ACTION` | `1` (on) | Set `0` or `false` to disable strict fail-closed (non-production only). |

---

## Conformance badge

Add to your MCP bridge or gateway README when passing the open test suite:

```markdown
[![Aevesa receipt-before-action/v1](https://img.shields.io/badge/conformance-receipt--before--action%2Fv1-0d9488?style=flat-square)](https://aevesa.com/schemas/receipt-before-action/v1)
**Receipt-before-action** — tool execution blocked when ledger commit fails (fail-closed).
```

---

## Running conformance tests

### Third-party MCP bridge stub

Integrators implement `appendAuditLog` and run against the published stub:

```bash
cd private-backend
node scripts/conformance/receipt-before-action-stub.mjs
node scripts/test-receipt-before-action-conformance.mjs
```

The stub (`scripts/conformance/receipt-before-action-stub.mjs`) exports:

- `evaluateToolWithReceiptBeforeAction({ appendAuditLog, toolName, sessionId })` — MUST return `{ allow: true, entryHash }` on success
- `evaluateToolWhenLedgerFails({ appendAuditLog })` — MUST return `{ allow: false, code: 'PEP_RECEIPT_COMMIT_FAILED' }` when commit returns no hash

### Aevesa internal suite

```bash
npm run test:phase2-conformance      # wiring + induced ledger failure
npm run test:receipt-before-action-conformance  # stub + runtime invariant
```

---

## Induced ledger failure (integration test)

**Scenario:** Simulate ledger hang / null `entryHash`.

**Expected:** Tool path returns `allow: false`, code `PEP_RECEIPT_COMMIT_FAILED`, no side effect.

Documented test: `scripts/test-receipt-before-action-conformance.mjs` → `induced ledger failure denies tool`.

---

## Relationship to liability receipts

Receipt-before-action governs **when** tools may run. `liability-receipt/v1` governs **what auditors receive** after a governed outcome. A committed PEP row becomes the primary anchor for liability receipt minting.

---

## Cross-references

- [liability-receipt-v1.md](./liability-receipt-v1.md)
- [TRUST_BUNDLE.md](../../diligence-kit/docs/TRUST_BUNDLE.md) — Phase 2 receipt-before-action invariant
- [AEVESA_PROOF_MOAT_ROADMAP.md](../architecture/AEVESA_PROOF_MOAT_ROADMAP.md) — Phase 3.1
