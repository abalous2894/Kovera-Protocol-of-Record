# Art. 73 Incident Custody Pack — Evidence Preservation Profile (Wave 2.3)

**Schema:** `kovera-incident-custody-pack/1`  
**Machine-readable:** [`./kovera-incident-custody-pack-1.json`](./kovera-incident-custody-pack-1.json)

---

## Purpose

Compose immutable ledger, legal hold, witness cosign, and receipt graph into a **single exportable custody bundle** for EU AI Act Art. 73 serious incident evidence preservation.

**GTM line:** *"Your GRC tool holds the workflow. Aevesa holds the proof — frozen and cosigned for Art. 73."*

---

## Freeze receipt (`aevesa.apor.incident-freeze-receipt/v1`)

Emitted on `POST /api/v1/apor/incidents/:incidentId/freeze`:

| Field | Requirement |
|-------|-------------|
| `incidentRef` | Stable incident reference |
| `frozenAt` | ISO timestamp of freeze |
| `freezeAnchorEntryHash` | Ledger `entryHash` of `GOVERNANCE_INCIDENT_FROZEN` |
| `legalHoldEntryHashes` | Anchors under legal hold |
| `policyVersionHashAtFreeze` | Policy fingerprint at freeze time |
| `modelFingerprintsAtFreeze` | Model IDs from session ledger rows |

---

## Custody pack layout

```
incident-custody-pack/
  manifest.json / manifest.sig
  incident/freeze-receipt.json
  incident/eu-export-stub.json
  custody/legal-holds.json
  custody/witness-cosign-freeze.json
  custody/delegation-graph-snapshot.json
  custody/receipt-index.json
  compliance/policy-at-freeze.json
  compliance/model-fingerprints-at-freeze.json
```

---

## Demo & verify

| Asset | Location |
|-------|----------|
| Public API | `GET /api/v1/public/evidence/incident-freeze-demo` |
| Sample pack | `diligence-kit/samples/incident-custody-pack/` |
| Conformance | `npm run test:incident-custody-pack` |
| GTM one-pager | [ART73_INCIDENT_CUSTODY_ONEPAGER.md](../sales/ART73_INCIDENT_CUSTODY_ONEPAGER.md) |

---

*Wave 2.3 · Vector #6*
