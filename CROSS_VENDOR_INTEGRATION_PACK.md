# Cross-Vendor Integration Pack (Wave 3.2)

Named export packs on the Prove ledger — **no parallel platform bets**.

| Pack SKU | Priority | Capability |
|----------|----------|------------|
| `kovera-cross-vendor-evidence-push-v1` | P1 | GRC auto-push on ledger events |
| `aevesa-witness-transparency-v1` | P1 | Rekor metadata depth + SCRAPI witness |
| `aevesa-gateway-otlp-pilot-v1` | P1 | OTLP attest production pilot |
| `aevesa-verifiable-tool-treaties-v1` | P2 | in-toto + treaty registry |
| `aevesa-fortress-pdp-v1` | P2 | Out-of-process PDP (mTLS) |

**Open spec:** [./kovera-cross-vendor-integration-1.json](./kovera-cross-vendor-integration-1.json)  
**Conformance:** `npm run test:cross-vendor-integration`  
**Public demo:** `GET /api/v1/public/evidence/cross-vendor-demo`  
**Sample pack:** `diligence-kit/samples/cross-vendor-integration/`

---

## GRC auto-push

Manual GRC sink dispatch (`POST /api/v1/apor/grc-sink/dispatch`) records operator-initiated exports. **Auto-push** subscribes to governance ledger events and fires Vanta/Drata receipt-sink webhooks when configured.

### Enable

```bash
AEVESA_GRC_AUTO_PUSH=1
AEVESA_GRC_AUTO_PUSH_TARGETS=vanta,drata
# Optional — default includes MCP permit/block, gateway attest, incident freeze
AEVESA_GRC_AUTO_PUSH_EVENT_TYPES=MCP_TOOL_GOVERNANCE_ALLOWED,MCP_TOOL_GOVERNANCE_BLOCKED,GATEWAY_DECISION_ATTESTATION
```

Subscribed event types (default):

| Event type | Source |
|------------|--------|
| `MCP_TOOL_GOVERNANCE_ALLOWED` | MCP PEP permit |
| `MCP_TOOL_GOVERNANCE_BLOCKED` | MCP PEP deny / guard block |
| `MCP_GUARD_BLOCKED` | Legacy guard blocks |
| `GATEWAY_DECISION_ATTESTATION` | Gateway OTLP/attest ingest |
| `POLICY_DECISION_ANCHORED` | Policy engine |
| `INCIDENT_FREEZE_ANCHORED` | Incident freeze |

Legacy env aliases (`MCP_TOOL_GOVERNANCE_DENIED`, `GATEWAY_ATTEST_INGESTED`) normalize to the canonical types above.

Auto-push hooks **`appendAuditLog`** (MCP gate, gateway attest, guard blocks, APoR). Duplicate delivery for the same `entryHash` is suppressed in-process.

### Webhook env (per adapter)

| Target | URL env | Token env |
|--------|---------|-----------|
| Vanta | `VANTA_RECEIPT_WEBHOOK_URL` | `VANTA_RECEIPT_WEBHOOK_TOKEN` |
| Drata | `DRATA_RECEIPT_WEBHOOK_URL` | `DRATA_RECEIPT_WEBHOOK_TOKEN` |

Each push includes `verify_url` and `grc_evidence` (`aevesa.grc-evidence/v1`). A `GRC_EVIDENCE_AUTO_PUSHED` ledger row attests delivery (excluded from re-push to prevent loops).

### Service

`private-backend/src/services/integrations/grcAutoPushService.js`

---

## Witness transparency

Witness statements now persist **Rekor transparency-log metadata** (UUID, log index, log ID) when `AEVESA_REKOR_WITNESS_URL` is set.

Profile: [WITNESS_TRANSPARENCY_PROFILE.md](./WITNESS_TRANSPARENCY_PROFILE.md)

---

## OTLP pilot

Generic OTLP gateway attest is GA. Production pilots use the runbook:

[../operations/GATEWAY_OTLP_PILOT_RUNBOOK.md](../operations/GATEWAY_OTLP_PILOT_RUNBOOK.md)

---

## Tool treaties

Unifies existing **treaty registry** + **in-toto tool manifest** evaluation on MCP promotion paths. Conformance: `npm run test:phase4-conformance`.

---

## Fortress PDP

Out-of-process PDP with mTLS and signed decisions — see [PEP_PDP_ARCHITECTURE.md](../../diligence-kit/docs/PEP_PDP_ARCHITECTURE.md). Conformance: `npm run test:phase3-isolation-conformance`.

---

*Wave 3.2 · Companion: [CROSS_VENDOR_INTEGRATION_ONEPAGER.md](../sales/CROSS_VENDOR_INTEGRATION_ONEPAGER.md)*
