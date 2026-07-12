# DENIED Receipt Profile — Pre-Execution Refusal Evidence (Wave 2.2)

**Schema:** `liability-receipt/v1` · **`receipt_profile`:** `DENIED`  
**Machine-readable:** [`./liability-receipt-v1.json`](./liability-receipt-v1.json)

---

## Purpose

Prove that a **block happened before execution** — not a post-hoc log line. Required for Art. 14 bounded autonomy, insurance diligence, and gateway dual-vendor attach (Cyera + Unity AI Gateway + Aevesa).

**GTM line:** *"The gateway blocked it in their UI. Aevesa proves the block happened before execution — auditor verifies offline."*

---

## DENIED profile invariants

When `receipt_profile` is `DENIED`:

| Field | Requirement |
|-------|-------------|
| `session.outcome` | `blocked` |
| `policy.decision` | `deny` |
| `denial.pre_execution` | `true` |
| `denial.execution_occurred` | `false` |
| `side_effects.blocked_reason` | Non-empty code (e.g. `GATEWAY_DATABRICKS_UNITY_AI_DENY`) |
| `side_effects.effect_class` | Typically `none` — no material side effect |

Optional bindings:

- **`gateway_attestation`** — external gateway permit/deny (`aevesa.gateway-decision/v1`)
- **`refusal_alignment`** — SCITT refusal-event draft metadata

---

## Proof-of-Behavior: absence of DENIED record

If receipt-before-action (RBA) is enabled and **no DENIED receipt exists** for a material tool invocation, auditors should treat that as:

> **Policy was not consulted before execution** — the PEP did not fail-closed or the gateway did not attest the deny.

Conformance reference: `npm run test:receipt-before-action-conformance` (induced ledger failure denies tool).

See [PRE_EXECUTION_DENIED_EVIDENCE.md](./PRE_EXECUTION_DENIED_EVIDENCE.md).

---

## SCITT refusal-event alignment

Aevesa maps DENIED receipts to [draft-kamimura-scitt-refusal-events](https://datatracker.ietf.org/doc/draft-kamimura-scitt-refusal-events/) via `refusal_alignment`:

| SCITT concept | Aevesa field |
|---------------|--------------|
| Issuer | `issuer.name` |
| Subject | `identity.primary_actor.agent_id` |
| Decision | `policy.decision` (= deny) |
| Timestamp | `issued_at` |
| Evidence hash | `proof.primary_anchor.entry_hash` |

Full mapping: [SCITT_REFUSAL_EVENT_ALIGNMENT.md](./SCITT_REFUSAL_EVENT_ALIGNMENT.md)

---

## Demo & verify

| Asset | Location |
|-------|----------|
| Verify portal | https://verify.aevesa.com?demo=denied |
| Public API | `GET /api/v1/public/evidence/denied-demo` |
| Sample pack | `diligence-kit/samples/denied-receipt/` |
| Conformance | `npm run test:denied-receipt-conformance` |
| GTM one-pager | [DENIED_RECEIPT_ONEPAGER.md](../sales/DENIED_RECEIPT_ONEPAGER.md) |

---

*Wave 2.2 · Vector #5*
