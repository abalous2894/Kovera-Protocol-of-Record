# Transparency Log Monitor Profile (Track P12)

**Status:** Track P12 P12-PR1 + P12-PR2 · Problem 12 (SCITT monitor economy)  
**Monitor status schema:** `aevesa.transparency-log-monitor-status/v1`  
**Monitor attestation schema:** `aevesa.transparency-log-monitor-attestation/v1`  
**Consistency proof schema:** `aevesa.witness.consistency-proof/v1`  
**Conformance:** `npm run test:transparency-log-monitor-conformance`

---

## Purpose

SCITT agent-receipt drafts defer **transparency log monitoring** (consistency proofs, split-view detection) to external operators. Aevesa ships a **public monitor surface** so relying parties can verify that witness log entries form a consistent append-only sequence—supporting non-equivocation claims for Problem 2 independence evidence.

**GTM line:** *Aevesa proves your receipts were included—and that the transparency log did not equivocate.*

This is an **evidence substrate**, not a certified CT log operator or legal attestation service.

---

## Public endpoints

| Endpoint | Role |
|----------|------|
| `GET /api/v1/public/transparency-log/monitor-status` | Live monitor snapshot (witness log health + latest consistency proof) |
| `GET /api/v1/public/transparency-log/consistency-proof?from=&to=` | Consistency proof for index range |
| `GET /api/v1/public/evidence/transparency-log-monitor-demo` | Offline-friendly demo snapshot |
| `/transparency-log-monitor.html` | Public status page (verify.aevesa.com) |

Authenticated APoR equivalents remain at `/api/v1/apor/witness-log/*` for tenant-scoped operations.

---

## Monitor status (`aevesa.transparency-log-monitor-status/v1`)

| Field | Meaning |
|-------|---------|
| `monitor_state` | `healthy` · `degraded` · `unavailable` |
| `witness_log` | Embedded `aevesa.witness-log-status/v1` block |
| `consistency_proof_latest` | Proof over full log tail (when entries exist) |
| `consistency_verify` | Offline verify result when digests available |
| `monitor_assertions` | `log_enabled`, `consistency_proof_available`, `consistency_proof_verified`, etc. |

---

## Consistency proof verification

```js
import { verifyWitnessConsistencyProof, WITNESS_CONSISTENCY_PROOF_SCHEMA } from '@aevesa/verify';

const result = verifyWitnessConsistencyProof(proof, entryDigestsInRange);
// root_hash must match SHA-256 of JSON.stringify(digest array) — mirrors witnessLogService
```

---

## Problem 12 / SCITT framing

| SCITT gap | Aevesa monitor role |
|-----------|---------------------|
| Registration ≠ non-equivocation | Publishes consistency proofs over witness log tail |
| Split-view / tail truncation | Monitor state degrades when proof verify fails |
| External monitor operators | Public API + offline `@aevesa/verify` helpers |

## Monitor attestation (`aevesa.transparency-log-monitor-attestation/v1`) — P12-PR2

Digest-bound attestation embedding the latest consistency proof and monitor state. Optional field on `aevesa.independent-guardian-bundle/v1`:

| Field | Meaning |
|-------|---------|
| `monitor_state` | Snapshot state at attestation time |
| `consistency_proof` | Bound proof over log tail |
| `monitor_assertions` | `consistency_proof_verified`, `third_party_monitorable` |
| `attestation_digest` | SHA-256 of stable preimage (excludes digest field) |

Offline verify:

```js
import { verifyTransparencyLogMonitorAttestation } from '@aevesa/verify';

verifyTransparencyLogMonitorAttestation(attestation, { entryDigests });
```

Guardian bundle verify accepts optional `transparency_log_monitor_attestation` when present (additive preimage field).

## Alert hooks (P12-PR2)

When monitor state is `degraded` or `unavailable`, or consistency proof verify fails, the backend may POST to `AEVESA_TS_MONITOR_ALERT_WEBHOOK` (JSON payload `aevesa.transparency-log-monitor-alert/v1`). Hooks fire from witness append and public monitor-status polling (60s cooldown per state).

---

## Related

- [SCITT_AIR_PROFILE_ALIGNMENT.md](./SCITT_AIR_PROFILE_ALIGNMENT.md)
- [DECLARED_ADAPTATION_ENVELOPE_SCITT_ALIGNMENT.md](./DECLARED_ADAPTATION_ENVELOPE_SCITT_ALIGNMENT.md)
- Wave 14 Track G — witness diversity

---

*Track P12 · Year-1 module · Protocol compatibility: safe additive*
