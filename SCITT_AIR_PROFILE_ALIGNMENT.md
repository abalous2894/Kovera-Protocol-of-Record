# SCITT AIR Profile Alignment — Liability Receipt (Wave 3.1)

**Aevesa profile:** `air_alignment.profile` = `SCITT-AIR-draft-alignment-01` (documentation draft)  
**Related:** [SCITT_REFUSAL_EVENT_ALIGNMENT.md](./SCITT_REFUSAL_EVENT_ALIGNMENT.md) (Wave 2.2 DENIED profile)

---

## Scope

This document maps **`liability-receipt/v1`** fields to emerging **SCITT Agent Identity / Incident Response (AIR)** draft concepts for procurement and standards workshops. It is **not** an IETF submission — it prepares Aevesa implementers and partners for full transparency-log profile work in Governance Horizon Phase 4.

---

## Mapping table (draft alignment)

| SCITT AIR concept (draft) | Aevesa `liability-receipt/v1` source |
|---------------------------|--------------------------------------|
| Agent identity | `identity.primary_actor.agent_id` |
| Session / run binding | `session.session_id`, `session.correlation_id` |
| Policy decision | `policy.decision`, `policy.policy_pack_id` |
| Action / tool | `side_effects.action.tool_name`, `side_effects.effect_class` |
| Evidence anchor | `proof.primary_anchor.entry_hash` |
| Timestamp | `issued_at` |
| Human oversight | `hitl.*`, Art. 14 oversight packs |
| Refusal / deny | `receipt_profile: DENIED`, `refusal_alignment.*` |
| Witness cosign | Independent log via `AEVESA_LEDGER_WITNESS_COSIGN` |

---

## Wave 3.1 deliverable vs Horizon 4

| Layer | Wave 3.1 (this doc) | Horizon 4 |
|-------|---------------------|-----------|
| Field mapping | ✅ Published | — |
| SCRAPI witness log | Preview shipped | Full SCITT transparency log |
| Rekor / dual-write | — | P1 in Wave 3.2 |
| IETF profile submission | Partner workshop ready | Formal submission track |

---

## Conformance reference

- `npm run test:witness-cosign-conformance`  
- `npm run test:conformance-lab`  
- Witness GA: [GUARDIAN_WITNESS_GA_RUNBOOK.md](../operations/GUARDIAN_WITNESS_GA_RUNBOOK.md)

---

*Wave 3.1 · Vector #7 · Full SCITT log: [AEVESA_GOVERNANCE_HORIZON_ROADMAP.md](../architecture/AEVESA_GOVERNANCE_HORIZON_ROADMAP.md) §4.1*
