# Cryptographic vs Declarative Evidence for Art. 12 (Wave 3.1)

**Audience:** Standards buyers, EU AI Act conformity assessors, security architects

---

## The distinction

**Declarative evidence** — PDFs, dashboard exports, configuration attestations, W3C VCs without session binding. Answers: *"We claim we comply."*

**Cryptographic evidence** — Hash-anchored ledger rows, offline-verifiable receipts, fail-closed enforcement invariants. Answers: *"Prove what happened before side effects."*

Art. 12 record-keeping requires **tamper-evident, retrievable** logs. Art. 14 bounded autonomy requires **pre-execution** proof of policy consultation — not post-hoc narratives.

---

## Why declarative falls short

| Pattern | Example | Art. 12/14 gap |
|---------|---------|----------------|
| Platform audit log | Databricks, Cyera UI | Vendor-scoped; not portable |
| W3C Agent Receipt (VC) | Identity attestation | No enforcement plane; decoupled from session |
| SIEM aggregation | Splunk deny line | Post-hoc; mutable pipeline |
| GRC checkbox | "HITL enabled" config | Config ≠ executed oversight |

---

## Aevesa cryptographic stack

1. **Receipt-before-action** — tool blocked when ledger commit fails  
2. **`liability-receipt/v1`** — session-bound accountability artifact  
3. **`@aevesa/verify`** — offline verify without vendor login  
4. **Witness cosign** — independent guardian inclusion proof  

**Conformance:** `npm run test:conformance-lab` · [COMPETITIVE_MATRIX.md](./COMPETITIVE_MATRIX.md)

---

*Wave 3.1 · Companion: [CONFORMANCE_LAB_ONEPAGER.md](../sales/CONFORMANCE_LAB_ONEPAGER.md)*
