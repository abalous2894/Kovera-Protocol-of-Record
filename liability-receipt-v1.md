# Open Standard for Autonomous Session Accountability

## Liability Receipt v1 (`liability-receipt/v1`)

| | |
|---|---|
| **Standard ID** | `liability-receipt/v1` |
| **Product context** | Aevesa Verified Autonomous Sessions (VAS) |
| **Normative schema** | [liability-receipt-v1.json](./liability-receipt-v1.json) · [Canonical URI](https://aevesa.com/schemas/liability-receipt/v1) |
| **Status** | Published reference implementation |
| **Maintainer** | Aevesa |
| **Intended adopters** | Financial institutions, acquirers, regulators, Big 4 assurance firms |

---

## Abstract

Autonomous agents execute high-impact actions—payment voids, fund transfers, privileged configuration—without the evidentiary rigor that auditors and regulators require. Conventional application logs establish chronology but do not bind **accountability** to **policy** and **human authorization** in a single, portable artifact.

**Liability Receipt v1** defines the minimum document that a governed autonomous session MUST produce to demonstrate accountability. Aevesa publishes this specification as an **open standard** so counterparties may require `liability-receipt/v1` in procurement, diligence, and regulatory examination without vendor lock-in to a proprietary export format.

---

## Scope

This standard applies to a **single governed outcome** within a Verified Autonomous Session: one intercept → decide → prove cycle that results in a permitted, blocked, or human-released action.

It does not replace:

- Full session record-keeping under EU AI Act Article 12 (see Aevesa Art. 12 conformity packs).
- Forensic Proof-of-Action bundles (artifact-level exports for litigation).
- Real-time monitoring or guardrail scoring.

It **does** provide the executive and auditor-facing summary that ties those systems together.

---

## Normative accountability pillars

Every conforming document MUST populate the following pillars. No pillar may be omitted for high-risk verticals (e.g. `fintech_payments`).

### Pillar I — Identity (Who acted)

Establishes the **primary actor** (autonomous agent or delegated kiosk), the **delegated authority** (JIT passport: role, permission ID, constraints digest), and—when applicable—the **human release actor** who signed an exception.

**Audit question:** *Can we name the agent and the authority under which it operated, independent of application UI claims?*

### Pillar II — Policy (What allowed it)

Records the active **policy pack**, a **SHA-256 policy version fingerprint**, the **decision** (`allow_within_ceiling`, `require_hitl`, `deny`, `released`), and applicable **thresholds** (e.g. maximum void amount).

**Audit question:** *Which governance rule was in force at decision time, and was it tamper-evident?*

### Pillar III — Human Release (HITL)

When policy requires escalation, attests that a qualified human **signed** the release, with `approval_request_id`, `required_role`, `release_consumed` (one-shot replay protection), and linkage to ledger artifact `HITL_DUAL_SIGNATURE`.

**Audit question:** *Was a high-risk exception explicitly authorized by a human with recorded authority—not merely logged after the fact?*

### Pillar IV — Side Effects (What happened)

Describes the governed **action** (tool, verb, metric) and **effect class** (e.g. `financial_void`) in an **auditor-safe summary** without PAN, SSN, raw prompts, or customer PII.

**Audit question:** *What material business outcome occurred, in language suitable for a board or regulator?*

### Pillar V — Proof (What the proof says)

Anchors the receipt to the **Aegis ledger** (`aegis/1` `entry_hash`), lists **verification methods** (preimage recompute, HITL dual-signature), and **verification status**. Proof MUST be independently verifiable without trusting the issuer's UI.

**Audit question:** *Can a third party recompute integrity without Aevesa credentials?*

### Optional — Proof-of-Intent (`intent_context`)

When present, `intent_context` captures what the agent **claimed** it was doing before a governed tool invocation:

| Field | Description |
|-------|-------------|
| `reasoning_summary` | Redacted rationale (max 4096 chars) — not raw chain-of-thought. |
| `model_fingerprint` | Exact model identifier that produced the stated intent. |

**Binding:** `intent_context` and **`intent_alignment`** (KVR-102) are included in `integrity.receipt_digest` when present. `intent_context` is also serialized into `governanceBinding.intentContext` for `aegis/1` `entryHash` preimages. The alignment object (`score`, `level`, `signals`) is canonicalized (sorted signal tags, two-decimal score) before hashing so tampering after seal fails verification. Legacy receipts without digest-bound `intent_alignment` verify under the `v1_intent_context` profile.

### Causal lineage (KVR-301)

When a child agent action follows an A2A delegation, the receipt MAY include:

| Field | Description |
|-------|-------------|
| `parent_entry_hash` | 64-char hex `entryHash` of the parent agent's governing ledger row at delegation time. |
| `parent_session_id` | Parent swarm session identifier (optional). |
| `root_session_id` | Root swarm session for multi-hop trees (optional). |

**Binding:** `causal_lineage` is included in `integrity.receipt_digest` when present and MUST match `payload.parentEntryHash` on the primary ledger anchor. This mirrors `causalBinding` in `aegis/1` proof-of-intent preimages but binds accountability at the receipt layer for offline verifier parity.

Demo: `node private-backend/scripts/mint-intent-divergence-demo.mjs` · `npm run test:intent-divergence` in `@aevesa/verify` · `npm run test:kvr-301` for swarm lineage digest binding.

### Session path binding (`partial_path`) — Proof Moat Phase 3

When present, `partial_path` binds the agent's multi-hop execution path and proposed action:

| Field | Description |
|-------|-------------|
| `partial_path_hash` | SHA-256 over canonical path material (`aevesa.partial-path/v1`) |
| `step_index` | Zero-based hop index (e.g. hop 4 of 4 → `step_index: 3`) |
| `proposed_action` | Tool name at receipt mint time |
| `partial_steps` | Redacted prior hops (tool, verdict, optional `entry_hash`) |

**Binding:** included in `integrity.receipt_digest` when present. Offline verify via `@aevesa/verify` → `verifyPartialPathCommitment()`.

---

## Document requirements

1. Top-level field `schema` MUST equal `liability-receipt/v1`.
2. `receipt_id` MUST be a UUID stable for the life of the evidence record.
3. `integrity.receipt_digest` MUST be SHA-256 over canonical JSON pillars (including `intent_context` when present; see schema).
4. For `session.vertical: fintech_payments` and `effect_class: financial_void` where `hitl.required` is true:
   - `session.outcome` MUST be `released_after_hitl` only if `hitl.status` is `signed` and `hitl.release_consumed` is true.
5. `diligence_summary` MUST include `who_acted`, `what_policy_allowed`, and `what_proof_says` in plain language.

---

## Conformance

| Level | Requirements |
|-------|----------------|
| **Producer** | Emits all required fields; seals `receipt_digest`; writes ledger anchors before issuing receipt. |
| **Consumer** | Rejects unknown `schema`; validates UUID and hex patterns; does not treat UI rendering as verification. |
| **Verifier** | Recomputes `aegis/1` preimages; confirms HITL completeness for financial void profiles. |

**Machine-readable clause + test map:** [LIABILITY_RECEIPT_CONFORMANCE.md](./LIABILITY_RECEIPT_CONFORMANCE.md) (Aevesa Conformant badge criteria).

Aevesa's reference implementation: Verified Autonomous Sessions platform, FinTech Lighthouse pilot (`fintech_payment_void_v1`).

---

## FinTech Lighthouse reference profile

The **FinTech Lighthouse** pilot demonstrates conformance for payment voids:

| Step | System behavior | `session.outcome` |
|------|-----------------|-------------------|
| 1 | Agent requests void above passport ceiling | `pending_human_release` |
| 2 | Aevesa intercepts; returns authority-required | — |
| 3 | Manager signs HITL (`POST /api/v1/approvals/sign`) | — |
| 4 | Agent retries with consumed release | `released_after_hitl` |
| 5 | `liability-receipt/v1` sealed | Final receipt issued |

**Reference demonstration (Aevesa VAS):**

- Simulate FinTech payment void: `POST /api/v1/public/lighthouse/fintech-payment-void/simulate`
- Retrieve receipt: `GET /api/v1/public/liability-receipt/:receiptId`
- Auditor diligence report: `https://app.aevesa.com/auditor-portal/:receiptId`

---

## Standardization badge (README)

Adopters may display the following badge in repository README files once they implement a conforming producer or verifier:

```markdown
[![Aevesa liability-receipt/v1](https://img.shields.io/badge/standard-liability--receipt%2Fv1-2563eb?style=flat-square)](https://aevesa.com/schemas/liability-receipt/v1)
**Verified Autonomous Session Accountability** — implements [liability-receipt/v1](https://aevesa.com/schemas/liability-receipt/v1)
```

Link the badge to your conformance statement or this specification.

---

## Security considerations

- Receipts MUST NOT embed secrets, API keys, PAN, or raw LLM prompts.
- `integrity.signature` SHOULD use RS256 or Ed25519 when a producer key is available.
- Public auditor portals MUST serve receipts over HTTPS with rate limiting.

---

## References

- **Aegis ledger (`aegis/1`):** hash-chained audit ledger specification (entryHash preimage binding)
- **Proof-of-Action bundle:** companion forensic export for single-anchor litigation and offline verify workflows
- **Public verification portal:** [https://verify.aevesa.com](https://verify.aevesa.com)
- **Open evidence API:** `GET /api/v1/public/evidence/spec` (hosted on Aevesa API)

---

## Intellectual property

Aevesa grants implementers a royalty-free license to reproduce and implement this specification for interoperability purposes, provided that `liability-receipt/v1` schema identifiers are not altered. Derivative schema versions MUST use a new version identifier (e.g. `liability-receipt/v2`).

**Conformance inquiries:** sales@aevesa.com

---

*Standard document version 1.0 — May 2026*
