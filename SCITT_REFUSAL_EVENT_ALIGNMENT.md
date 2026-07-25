# SCITT Refusal-Event Alignment — DENIED Receipt Profile (Wave 2.2)

**Aevesa profile:** `refusal_alignment.profile` = `SCITT-refusal-event-draft-01`  
**Reference draft:** [draft-kamimura-scitt-refusal-events](https://datatracker.ietf.org/doc/draft-kamimura-scitt-refusal-events/)

---

## Mapping table

| SCITT refusal-event field (draft-01) | Aevesa `liability-receipt/v1` source |
|--------------------------------------|--------------------------------------|
| `issuer` | `issuer.name` + `issuer.product` |
| `subject` | `identity.primary_actor.agent_id` |
| `decision` | `policy.decision` (must be `deny` for DENIED profile) |
| `timestamp` | `issued_at` |
| `evidence_hash` | `proof.primary_anchor.entry_hash` or `integrity.receipt_digest` |
| `refusal_reason` | `side_effects.blocked_reason` |
| `policy_ref` | `gateway_attestation.policy_reference` or `policy.policy_pack_id` |
| `classification` | `gateway_attestation.data_classification_tag` |

---

## Aevesa extension fields

Stored in `refusal_alignment` on DENIED receipts:

```json
{
  "profile": "SCITT-refusal-event-draft-01",
  "mapping_version": "1.0",
  "reference": "draft-kamimura-scitt-refusal-events",
  "scitt_event_type": "refusal",
  "mapped_fields": ["issuer", "subject", "decision", "timestamp", "evidence_hash"],
  "evidence_hash": "<64-hex>",
  "kovera_receipt_profile": "DENIED"
}
```

---

## Interop stance

Aevesa **aligns** with SCITT refusal-event vocabulary for procurement reviews. Gateway DENIED receipts register a SCRAPI refusal statement (`https://scitt.io/statement/refusal/v0`) in the Aevesa witness transparency log when `AEVESA_LEDGER_WITNESS_COSIGN=1`.

Verify: `GET /api/v1/public/evidence/scitt-refusal/:receiptDigest` · `npm run test:scitt-refusal-witness-conformance`

When draft-01 stabilizes, Aevesa will publish a conformance vector in `@aevesa/verify` matching the final field names.

---

*Companion: [DENIED_RECEIPT_PROFILE.md](./DENIED_RECEIPT_PROFILE.md)*
