# kovera-delegation-chain/1 — Normative Specification (Wave 2.1)

**Schema ID:** `kovera-delegation-chain/1`  
**Machine-readable:** [`./kovera-delegation-chain-1.json`](./kovera-delegation-chain-1.json)  
**ADCS alignment:** ADCS v0.1 field mapping (see schema `$defs.adcs_field_mapping`)  
**Status:** Published · Wave 2.1

---

## Purpose

Define a portable, offline-verifiable document for **multi-agent delegation provenance** — from human principal through ordered agent hops, with monotonic scope narrowing and HDP-style signed hop proofs.

Kovera ships this as the open export format atop Phase 3 delegation runtime (`A2A_DELEGATION` ledger events, hop policy, ROA scope narrowing).

---

## Document structure

| Section | Role |
|---------|------|
| `origin` | Human principal — **MUST NOT** change across hops |
| `links[]` | ADCS-aligned delegation hops (profile, run, scopes, tools, budget) |
| `depth` | MUST equal `links.length` |
| `invariants` | Declarative rules verified by conforming implementations |
| `proof` | HDP hop receipt chain (`kovera.hdp-hop-receipt/v1`) |
| `adcs_alignment` | Interop metadata for procurement |

---

## Verification profile

1. Validate schema = `kovera-delegation-chain/1`  
2. Check ADCS invariants (scope/tool narrowing, budget propagation, parent run IDs)  
3. Verify each HDP hop: `hop_hash` preimage + HMAC-SHA256 signature  
4. Verify chain links: hop[i].`parent_hop_hash` = hop[i-1].`hop_hash`

Reference implementations:

- `@aevesa/verify` — `packages/verify/src/core/delegationChainVerify.js`  
- Private backend — `private-backend/src/services/apor/delegationChainService.js`  
- Sample verifier — `diligence-kit/samples/delegation-chain/verify-delegation-chain.mjs`

---

## Public demo

Deterministic scenario: **Alice (human) → Strategy orchestrator → Remote researcher** with narrowed scopes.

- API: `GET /api/v1/public/evidence/delegation-demo`  
- Portal: https://verify.kovera.tech?demo=delegation  
- Demo signing secret (public sample only): documented in sample pack README — **not for production**

Production chains use `KOVERA_HDP_SIGNING_SECRET`.

---

## Relationship to internal schemas

| Internal ID | Role in kovera-delegation-chain/1 |
|-------------|-----------------------------------|
| `kovera.hdp-hop-receipt/v1` | Single hop in `proof.hops[]` |
| `kovera.hdp-hop-chain/v1` | `proof.profile` wrapper |
| `kovera.swarm.delegation-tree/v1` | Ledger graph view (complementary) |

---

## Changelog

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-18 | Initial publish — Wave 2.1, ADCS v0.1 mapping |

---

*See also: [A2A_DELEGATION_INTEGRATION_GUIDE.md](../../diligence-kit/docs/A2A_DELEGATION_INTEGRATION_GUIDE.md)*
