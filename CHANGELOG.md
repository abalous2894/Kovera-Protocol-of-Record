# Changelog — Kovera Protocol of Record

All notable changes to open specifications and `@aevesa/verify` in this repository.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [2026-09-09]

### Added

- **`aevesa.declared-adaptation-envelope/v1-draft`** — Track AE: declared bounds, drift evaluation, substantial modification breach pack; profile [DECLARED_ADAPTATION_ENVELOPE_PROFILE.md](./DECLARED_ADAPTATION_ENVELOPE_PROFILE.md), open spec [aevesa-declared-adaptation-envelope-v1-draft.json](./aevesa-declared-adaptation-envelope-v1-draft.json).
- **`aevesa.substantial-modification-signal/v1`** — breach pack member schema; [aevesa-substantial-modification-signal-v1.json](./aevesa-substantial-modification-signal-v1.json).
- **`aevesa.adaptation-lifecycle-export/v1`** — Track P6 composed export (envelope + drift timeline + breach signal); [aevesa-adaptation-lifecycle-export-v1.json](./aevesa-adaptation-lifecycle-export-v1.json).
- **SCITT alignment (Track P9)** — additive `scitt_alignment` blocks; [DECLARED_ADAPTATION_ENVELOPE_SCITT_ALIGNMENT.md](./DECLARED_ADAPTATION_ENVELOPE_SCITT_ALIGNMENT.md).
- **`aevesa.transparency-log-monitor-attestation/v1`** — Track P12 PR2 monitor attestation for guardian bundles; profile [TRANSPARENCY_LOG_MONITOR_PROFILE.md](./TRANSPARENCY_LOG_MONITOR_PROFILE.md), spec [aevesa-transparency-log-monitor-attestation-v1.json](./aevesa-transparency-log-monitor-attestation-v1.json).
- **`aevesa.independent-guardian-bundle/v1`** — optional `transparency_log_monitor_attestation` field (additive); [INDEPENDENT_GUARDIAN_BUNDLE_PROFILE.md](./INDEPENDENT_GUARDIAN_BUNDLE_PROFILE.md), [aevesa-independent-guardian-bundle-v1.json](./aevesa-independent-guardian-bundle-v1.json).
- **`@aevesa/verify`** — `verifyDeclaredAdaptationEnvelopeBundle`, `verifySubstantialModificationSignalBundle`, `verifyAdaptationLifecycleExportBundle`, `verifyWitnessConsistencyProof`, `verifyTransparencyLogMonitorStatus`, `verifyTransparencyLogMonitorAttestation`; unified CLI detect kinds for lifecycle export and monitor artifacts.

### Changed

- P12 offline verify **fail-closed** when consistency proof digests are omitted (security hardening).

---

## [2026-09-05]

### Added

- **`tool_manifest_fingerprint` on `liability-receipt/v1`** — Wave 9 Track R: ASI04 MCP manifest session bind (`aevesa.tool-manifest-fingerprint/v1`), AttestMCP integration, profile [TOOL_MANIFEST_FINGERPRINT_PROFILE.md](./TOOL_MANIFEST_FINGERPRINT_PROFILE.md), RFP insert [ASI04_MCP_MANIFEST_BIND_RFP_INSERT.md](../sales/ASI04_MCP_MANIFEST_BIND_RFP_INSERT.md).
- **Conformance:** `npm run test:mcp-manifest-bind-conformance` (manifest drift + rug-pull tool verify).

- **`memory_commitment` on `liability-receipt/v1`** — Wave 9 Track Q: ASI06 memory root hash at material-action intercept (`aevesa.memory-commitment/v1`), `verifyMemoryCommitment`, MCP pluggable provider, profile [MEMORY_COMMITMENT_RECEIPT_PROFILE.md](./MEMORY_COMMITMENT_RECEIPT_PROFILE.md), mapping [ASI06_MEMORY_COMMITMENT_MAPPING.md](./ASI06_MEMORY_COMMITMENT_MAPPING.md).
- **Conformance:** `npm run test:memory-commitment-conformance` (root mismatch + honest absent marker).

- **`aevesa.cluster-custody-graph/v1`** — Wave 9 Track P: multi-agent cluster custody graph (nodes, delegation/quorum edges, quorum receipts), `verifyClusterCustodyGraph`, optional member on rogue containment pack, profile [CLUSTER_CUSTODY_GRAPH_PROFILE.md](./CLUSTER_CUSTODY_GRAPH_PROFILE.md), open spec [`./aevesa-cluster-custody-graph-v1.json`](./aevesa-cluster-custody-graph-v1.json).
- **Conformance:** `npm run test:cluster-custody-conformance` (ASI08 tabletop + rogue pack extension).

- **`aevesa.reasoning-baseline-receipt/v1`** — Wave 9 Track O: institutional policy/ontology baseline hash with material tool decision pointers, `verifyReasoningBaselineReceipt`, profile [REASONING_BASELINE_RECEIPT_PROFILE.md](./REASONING_BASELINE_RECEIPT_PROFILE.md), open spec [`./aevesa-reasoning-baseline-receipt-v1.json`](./aevesa-reasoning-baseline-receipt-v1.json).
- **Conformance:** `npm run test:reasoning-baseline-conformance` (baseline swap + forbidden chain-of-thought checks).

- **`aevesa.rogue-containment-pack/v1`** — Wave 9 Track N: ASI10 containment evidence pack composing freeze, delegation chain, DENIED/guardian, custody summary; profile [ROGUE_CONTAINMENT_PACK_PROFILE.md](./ROGUE_CONTAINMENT_PACK_PROFILE.md).
- **Conformance:** `npm run test:flight-recorder-conformance` (hash-only profile + ISO crosswalk self-check).

- **`aevesa.flight-recorder-export/v1` PR2** — `GET /api/v1/apor/path/:sessionId/flight-recorder`, verify portal `?demo=flight-recorder`, conformance lab row.

- **`aevesa.flight-recorder-export/v1` PR1** — `flightRecorderExportService`, public demo `GET /api/v1/public/evidence/flight-recorder-demo`.

- **`aevesa.insurance-signal-digest/v1` Track L6** — `kill_switch_drill_at` + `kill_switch_drill_freshness_digest` in metrics (remint to populate).

- **`aevesa.shutdown-drill-bundle/v1` PR1** — `shutdownDrillService`, `POST /api/v1/apor/governance/shutdown-drill`, public demo, verify portal `?demo=shutdown-drill`.

- **`aevesa.shutdown-drill-bundle/v1`** — Wave 9 Track L PR0: shutdown drill bundle schema, `buildShutdownDrillBundleDocument`, `verifyShutdownDrillBundle`, open spec [`./aevesa-shutdown-drill-bundle-v1.json`](./aevesa-shutdown-drill-bundle-v1.json), profile [SHUTDOWN_DRILL_BUNDLE_PROFILE.md](./SHUTDOWN_DRILL_BUNDLE_PROFILE.md).
- **Conformance:** `npm run test:shutdown-drill-conformance` (kill-switch composition + silence window).

- **`aevesa.ap2-conduct-receipt/v1` PR1** — live session export (`buildAp2ConductReceiptFromSession`), public demo route, dashboard `Ap2ConductReceiptPanel`, APoR `GET .../ap2-conduct-receipt`.

---

## [2026-09-05]

### Added

- **`aevesa.ap2-conduct-receipt/v1`** — Wave 9 Track K PR0: supplemental AP2 conduct receipt schema, `buildAp2ConductReceiptDocument`, `verifyAp2ConductReceipt`, open spec [`./aevesa-ap2-conduct-receipt-v1.json`](./aevesa-ap2-conduct-receipt-v1.json), profile [AP2_CONDUCT_RECEIPT_PROFILE.md](./AP2_CONDUCT_RECEIPT_PROFILE.md).
- **Conformance:** `npm run test:ap2-conduct-conformance` (offline verify + crosswalk stubs).

---

## [2026-07-25]

### Added

- **`@aevesa/verify` Tier 1 offline profiles** — commit-gate (`verifyCommitGateBundle`), kill-switch attestation, SCITT AIR alignment (`verifyScittAirBundle`), NAIC examiner pack helpers.
- **`@aevesa/verify` Tier 2 offline profiles** — autonomy tier attestation (CSA 4-tier), delegation accountability (OWASP ASI-03/07/08), OWASP ASI runtime integrity, IMDA agentic pack helpers.
- **Gateway attest expansion** — Portkey, Microsoft Agent 365, and generic OTLP/webhook adapters; `gatewayDecisionEvent` normalization helpers.
- **Wave 4 verify exports** — `verifyProveBundle`, `verifyEvidenceCustodianBundle`, `verifySetCompletenessBundle`.

### Changed

- **`packages/verify/PLATFORM_API.md`** — documents Tier 1/2 export surfaces and Wave 4 symbols.
- **SCITT_AIR_PROFILE_ALIGNMENT.md** / **SCITT_REFUSAL_EVENT_ALIGNMENT.md** — Tier 1 conformance metadata, public demo routes, verify schema SKUs.

---

## [2026-07-21]

### Added

- **PROTOCOL_COMPATIBILITY_POLICY.md** — public copy of the BC-PRT open-protocol compatibility policy (safe vs breaking changes for receipts, APIs, and `@aevesa/verify`).
- **`packages/verify/PLATFORM_API.md`** — mirrored with the verify package sync.

### Changed

- **CRYPTOGRAPHIC_VS_DECLARATIVE_EVIDENCE.md** — links the hosted public article at `https://aevesa.com/cryptographic-vs-declarative-evidence`.
- **README.md** — compatibility-policy row resolves to the flat-root public copy.

---

## [2026-07-11]

### Added

- **STANDARDS.md** — index of all published open standards in this repository.
- **LIABILITY_RECEIPT_CONFORMANCE.md** — numbered conformance clauses and Aevesa Conformant badge criteria for `liability-receipt/v1`.
- **Wave 2.2 — DENIED receipt profile** — [DENIED_RECEIPT_PROFILE.md](./DENIED_RECEIPT_PROFILE.md), [PRE_EXECUTION_DENIED_EVIDENCE.md](./PRE_EXECUTION_DENIED_EVIDENCE.md), [SCITT_REFUSAL_EVENT_ALIGNMENT.md](./SCITT_REFUSAL_EVENT_ALIGNMENT.md).
- **Wave 2.1 — Delegation chain** — [kovera-delegation-chain-1.md](./kovera-delegation-chain-1.md) + [kovera-delegation-chain-1.json](./kovera-delegation-chain-1.json).
- **Wave 2.3 — Art. 73 incident custody** — [INCIDENT_CUSTODY_PACK.md](./INCIDENT_CUSTODY_PACK.md) + [kovera-incident-custody-pack-1.json](./kovera-incident-custody-pack-1.json).
- **Wave 3.2 — Cross-vendor integration** — [CROSS_VENDOR_INTEGRATION_PACK.md](./CROSS_VENDOR_INTEGRATION_PACK.md) + [kovera-cross-vendor-integration-1.json](./kovera-cross-vendor-integration-1.json), [WITNESS_TRANSPARENCY_PROFILE.md](./WITNESS_TRANSPARENCY_PROFILE.md).
- **Receipt-before-action v1** — [RECEIPT_BEFORE_ACTION_CONFORMANCE.md](./RECEIPT_BEFORE_ACTION_CONFORMANCE.md).
- **Comparison docs** — [AGENT_RECEIPTS_VS_LIABILITY_RECEIPT.md](./AGENT_RECEIPTS_VS_LIABILITY_RECEIPT.md), [CRYPTOGRAPHIC_VS_DECLARATIVE_EVIDENCE.md](./CRYPTOGRAPHIC_VS_DECLARATIVE_EVIDENCE.md), [SCITT_AIR_PROFILE_ALIGNMENT.md](./SCITT_AIR_PROFILE_ALIGNMENT.md), [DELEGATION_CHAIN_STANDARDS_BLOG.md](./DELEGATION_CHAIN_STANDARDS_BLOG.md).

### Changed

- **Branding:** Maintainer and canonical schema URI updated from Kovera / `kovera.tech` to Aevesa / `aevesa.com`.
- **`liability-receipt/v1` schema** — new optional fields:
  - `receipt_profile` (`PERMITTED` | `DENIED` | `HITL_PENDING` | `HITL_RELEASED`)
  - `denial` (pre-execution refusal semantics)
  - `gateway_attestation` (external gateway permit/deny binding)
  - `refusal_alignment` (SCITT refusal-event interop metadata)
  - `partial_path` (session path binding — Proof Moat Phase 3)
- **`@aevesa/verify`** — package entry renamed from `kovera-verify` to `aevesa-verify`; added gateway attestation, DENIED profile, and partial-path verification helpers.
- **README.md** — expanded product and protocol documentation from Aevesa Governance Protocol reference.

### Removed

- Legacy Sentinul Twin-Core docs (`GETTING-STARTED.md`, `TWIN-CORE-PROTOCOL.md`, `MULTI-AGENT-SECURITY.md`, `COMPLIANCE-MAPPING.md`) superseded by README + STANDARDS.md.

---

## [2026-06-13]

### Added

- Initial public release of **`liability-receipt/v1`** normative spec and JSON schema.
- **`@aevesa/verify`** reference verifier (`verifyReceipt`, `computeReceiptDigest`).
- [COMPETITIVE_MATRIX.md](./COMPETITIVE_MATRIX.md) and [SECURITY.md](./SECURITY.md).
