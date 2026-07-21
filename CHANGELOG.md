# Changelog — Kovera Protocol of Record

All notable changes to open specifications and `@aevesa/verify` in this repository.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
