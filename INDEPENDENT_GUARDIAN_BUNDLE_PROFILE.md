# Independent Guardian Bundle Profile — `aevesa.independent-guardian-bundle/v1`

**Status:** Wave 8 Track F PR1 · **SKU:** `aevesa-independent-guardian-bundle-v1`  
**Verifier:** `verifyIndependentGuardianBundle()` in `@aevesa/verify`  
**Open schema:** [`./aevesa-independent-guardian-bundle-v1.json`](./aevesa-independent-guardian-bundle-v1.json)

---

## Purpose

Unify **Evidence Custodian** (PERMITTED + independent witness cosign) and **DENIED** (pre-execution refusal) into one offline-verifiable bundle for metagovernance / Gartner Guardian Agents diligence.

## Safe claims

| Claim | Allowed |
|-------|---------|
| Guardian/platform decision bound to liability receipt with witness cosign | ✅ (PERMITTED member) |
| Pre-execution refusal proved before side effects | ✅ (DENIED member) |
| Bundle integrity via `bundle_digest` | ✅ |
| Separation-of-duties evidence outside vendor admin plane | ✅ (when witness cosign valid) |
| Universal shadow AI discovery | ❌ |
| Replacing Cyera / Unity AI Gateway | ❌ |

## Bundle modes

| Mode | Required members |
|------|------------------|
| `dual_profile` | ≥1 valid PERMITTED custodian + ≥1 valid DENIED |
| `custodian_only` | ≥1 valid PERMITTED custodian |
| `denied_only` | ≥1 valid DENIED |

## Composition

| Member profile | Verify path |
|----------------|-------------|
| `PERMITTED` | `verifyEvidenceCustodianBundle()` — gateway source + witness cosign |
| `DENIED` | `validateDeniedReceiptProfile()` + `verifyProveBundle()` |

## Offline verification

```bash
npx @aevesa/verify aevesa verify independent-guardian-bundle.json --summary
```

Library:

```javascript
import { verifyIndependentGuardianBundle } from '@aevesa/verify';
```

Pass per-member witness/gateway context via `memberContexts` keyed by `member_id` or `entry_hash`.

## Non-goals

- Enterprise-wide passive shadow AI discovery (Cyera lane)
- Full AI gateway replacement
- Legal conformity / notified-body opinions

## Related profiles

- [`aevesa.evidence-custodian-verify/v1`](../sales/EVIDENCE_CUSTODIAN_ONEPAGER.md)
- [`DENIED` receipt profile](../sales/DENIED_RECEIPT_ONEPAGER.md)
- [Wave 8 roadmap](../architecture/AEVESA_WAVE8_PROVE_INDEPENDENCE_ROADMAP.md) Track F

**GTM line:** *Platforms log decisions. Aevesa cosigns permits and refusals — auditors verify without the guardian admin plane.*

---

*Wave 8 Track F PR1 — schema + offline verify*
