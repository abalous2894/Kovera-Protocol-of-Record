# Pre-Execution DENIED Evidence — Proof-of-Behavior (Wave 2.2)

**Audience:** Auditors, compliance engineers, insurance diligence reviewers

---

## The question

When an agent attempts a material action, how do you know **policy was consulted before execution**?

Platform UI logs and Splunk entries are **post-hoc narratives**. Receipt-before-action (RBA) and the **DENIED receipt profile** provide a cryptographic answer.

---

## Positive proof (deny occurred)

A `liability-receipt/v1` with:

```json
{
  "receipt_profile": "DENIED",
  "session": { "outcome": "blocked" },
  "denial": {
    "pre_execution": true,
    "execution_occurred": false,
    "denial_stage": "gateway"
  }
}
```

…proves the deny was **recorded before side effects**, bound to `entryHash` and (when present) `gateway_event_hash`.

Verify offline at verify.aevesa.com — no vendor login.

---

## Negative inference (absence of DENIED record)

| Observation | Auditor inference |
|-------------|-------------------|
| RBA enabled + tool executed + **no** receipt (permit or deny) | PEP bypass or ledger commit failure not fail-closed |
| Gateway deny in vendor UI + **no** Aevesa DENIED receipt | Attest webhook missing — deny not in protocol of record |
| DENIED receipt with `execution_occurred: true` | **Invalid** — fails conformance |

Aevesa PEP invariant: `commitPepAuditLogOrThrow` — tool MUST NOT run if ledger returns null `entryHash` (`PEP_RECEIPT_COMMIT_FAILED`).

Test: `npm run test:receipt-before-action-conformance`

---

## Denial stages

| `denial.denial_stage` | Source |
|-----------------------|--------|
| `gateway` | Unity AI Gateway / webhook attest |
| `pep` | MCP receipt-before-action gate |
| `hitl` | Human rejected approval |
| `runtime_firewall` | Intent alignment / exfil block |
| `intent_alignment` | Structural Proof-of-Intent CRITICAL |

---

## Procurement language

> *"Provide verifiable pre-execution refusal evidence — either a DENIED liability receipt or documented RBA fail-closed when ledger commit fails."*

See [DENIED_RECEIPT_RFP_INSERT.md](../sales/DENIED_RECEIPT_RFP_INSERT.md).

---

*Wave 2.2 · Vector #5*
