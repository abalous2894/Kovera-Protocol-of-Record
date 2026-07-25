# SCITT AIR Profile Alignment — Liability Receipt (Tier 1)

**Aevesa profile:** `air_alignment.profile` = `SCITT-AIR-draft-alignment-01`  
**Verify schema:** `aevesa.scitt-air-verify/v1` · **SKU:** `aevesa-scitt-air-v1`  
**Conformance:** `npm run test:scitt-air-conformance`  
**Public demo:** `GET /api/v1/public/evidence/scitt-air-demo`  
**Related:** [SCITT_REFUSAL_EVENT_ALIGNMENT.md](./SCITT_REFUSAL_EVENT_ALIGNMENT.md) (Wave 2.2 DENIED profile)

---

## Scope

Maps **`liability-receipt/v1`** fields to emerging **SCITT Agent Interaction Record (AIR)** draft concepts per `draft-emirdag-scitt-ai-agent-execution`. Positions Aevesa as **Evidence Custodian / Transparency Service** for EU Art. 12/19, DORA, and NIST examiner crosswalks.

---

## `air_alignment` block

Applied via `applyScittAirAlignment(receipt)` in `@aevesa/verify`:

| Field | Source on receipt |
|-------|-------------------|
| `agent_id` | `identity.primary_actor.agent_id` |
| `session_id` | `session.session_id` |
| `entry_hash` | `proof.primary_anchor.entry_hash` |
| `action_tool` | `side_effects.action.tool_name` |
| `policy_decision` | `policy.decision` |
| `issued_at` | `issued_at` |
| `evidence_custodian_role` | `transparency_service` |

---

## Verify API

```js
import { verifyScittAirBundle, applyScittAirAlignment } from '@aevesa/verify';

const receipt = applyScittAirAlignment(liabilityReceipt);
const result = verifyScittAirBundle(receipt, { entryHash, gatewayDecision, requireWitnessCosign: true });
```

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

## Conformance reference

- `npm run test:scitt-air-conformance`
- `npm run test:witness-cosign-conformance`
- `npm run test:evidence-custodian-conformance`

---

*Tier 1 · IETF draft: draft-emirdag-scitt-ai-agent-execution*
