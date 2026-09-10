# SCITT Alignment — Declared Adaptation Envelope (Track P9)

**Aevesa profiles:**

| Artifact | `scitt_alignment.profile` |
|----------|---------------------------|
| Declared Adaptation Envelope | `SCITT-adaptation-envelope-draft-01` |
| Substantial Modification Signal | `SCITT-adaptation-breach-draft-01` |

**Primary schemas:** `aevesa.declared-adaptation-envelope/v1-draft` · `aevesa.substantial-modification-signal/v1`  
**Verify API:** `applyAdaptationEnvelopeScittAlignment()` · `applySubstantialModificationScittAlignment()` · `validateAdaptationEnvelopeScittAlignment()`  
**Conformance:** `npm run test:adaptation-envelope-conformance` (SCITT block checks)  
**Related:** [SCITT_AIR_PROFILE_ALIGNMENT.md](./SCITT_AIR_PROFILE_ALIGNMENT.md) (per-action AIR receipts) · [DECLARED_ADAPTATION_ENVELOPE_PROFILE.md](./DECLARED_ADAPTATION_ENVELOPE_PROFILE.md)

---

## Scope

Maps **lifecycle adaptation artifacts** (envelope mint + breach signal) to emerging **SCITT Agent Interaction Record (AIR)** and agent-receipt draft vocabulary. Per-action liability receipts use the AIR profile; **envelope and breach packs** register as **transparency-service lifecycle statements** with digest-bound bounds and witness anchors.

Positions Aevesa as **Evidence Custodian / Transparency Service** for Art. 43(4) pre-determined changes evidence and Art. 12 logging substrate — complementary to per-action AIR alignment.

**Reference drafts (alignment only — not normative until IETF stabilization):**

- [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943) — SCITT architecture
- [draft-noa-scitt-ai-agent-receipt-01](https://datatracker.ietf.org/doc/draft-noa-scitt-ai-agent-receipt/) — agent receipt registration
- [draft-emirdag-scitt-ai-agent-execution](https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/) — agent interaction execution record

---

## Declared Adaptation Envelope mapping

Applied via `applyAdaptationEnvelopeScittAlignment(envelope, { entry_hash })` in `@aevesa/verify`:

| SCITT / AIR lifecycle concept (draft) | Aevesa envelope source |
|---------------------------------------|-------------------------|
| Agent / system subject | `system_id` → `lifecycle_record.agent_system_id` |
| Issuer scope | `organization_id` |
| Adaptation bounds | `bounds.policy_hash`, `bounds.tool_catalog_fingerprint`, optional memory/MCP digests |
| Statement digest | `envelope_digest` |
| Transparency log anchor | `envelope_entry_hash` → `lifecycle_record.entry_hash` |
| Declaration timestamp | `declared_at` |
| Operator posture | `operator_role` |
| Regulatory tags | `regulatory_framings[]` |
| Witness statement type | `https://aevesa.com/statement/adaptation-envelope-mint/v1` |

### Example `scitt_alignment` block (envelope)

```json
{
  "profile": "SCITT-adaptation-envelope-draft-01",
  "mapping_version": "1.0",
  "reference": "draft-noa-scitt-ai-agent-receipt-01",
  "scitt_statement_type": "https://aevesa.com/statement/adaptation-envelope-mint/v1",
  "lifecycle_record": {
    "agent_system_id": "agent-invoice-orchestrator",
    "organization_id": "org-ae-demo",
    "operator_role": "provider",
    "declared_at": "2026-09-09T12:00:00.000Z",
    "envelope_digest": "<64-hex>",
    "entry_hash": "<64-hex>",
    "policy_hash": "<64-hex>",
    "tool_catalog_fingerprint": "<64-hex>"
  },
  "evidence_custodian_role": "transparency_service",
  "compliance_mappings": [
    "EU AI Act Art. 43(4) pre-determined changes",
    "EU AI Act Art. 12 logging substrate",
    "RFC 9943 SCITT architecture",
    "OWASP Agentic AI Security v2.01 Level 3"
  ]
}
```

The block is **additive** — it does not participate in `envelope_digest` preimage. Mint services attach it after witness cosign when `AEVESA_LEDGER_WITNESS_COSIGN=1`.

---

## Substantial Modification Signal mapping

Applied via `applySubstantialModificationScittAlignment(signal, { entry_hash })`:

| SCITT breach / modification concept (draft) | Aevesa signal source |
|---------------------------------------------|------------------------|
| Parent lifecycle statement | `envelope_digest` |
| Modification / breach status | `drift_status` (must be `breach`) |
| Signal digest | `signal_digest` |
| Drift witness anchor | `drift_witness_entry_hash` |
| Signal registration anchor | `signal_entry_hash` |
| Witness statement type | `https://aevesa.com/statement/substantial-modification-signal/v1` |

---

## Verify API

```js
import {
  applyAdaptationEnvelopeScittAlignment,
  validateAdaptationEnvelopeScittAlignment,
  verifyDeclaredAdaptationEnvelopeBundle,
} from '@aevesa/verify';

const envelope = applyAdaptationEnvelopeScittAlignment(rawEnvelope, {
  entry_hash: witnessEntryHash,
});
const scitt = validateAdaptationEnvelopeScittAlignment(envelope.scitt_alignment);
const verify = verifyDeclaredAdaptationEnvelopeBundle(envelope);
// envelope verify is independent of scitt_alignment presence
```

---

## Interop stance

Aevesa **aligns** with SCITT agent-receipt and AIR draft vocabulary for procurement and standards-committee reviews. When draft field names stabilize, Aevesa will publish golden vectors in `@aevesa/verify` matching final IETF names.

**Problem 12 note:** SCITT drafts defer **transparency log monitoring** (consistency proofs, split-view detection) to external monitors — see Problem 12 in [MULTI_YEAR_RESEARCH_AGENDA.md](../strategy/MULTI_YEAR_RESEARCH_AGENDA.md). Envelope SCITT alignment registers statements; monitor attestation is a separate Year-1 module.

---

## Conformance reference

- `npm run test:adaptation-envelope-conformance` — SCITT alignment block validation
- `npm run test:scitt-air-conformance` — per-action AIR (companion profile)
- `npm run test:witness-cosign-conformance` — witness anchor path

---

*Track P9 · Year-1 module · ships through Track AE wedge · Protocol compatibility: safe additive*
