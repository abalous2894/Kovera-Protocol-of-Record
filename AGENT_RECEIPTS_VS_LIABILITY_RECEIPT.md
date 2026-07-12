# Agent Receipts (W3C VC) vs Aevesa `liability-receipt/v1` (Wave 3.1)

**Audience:** Standards evaluators comparing W3C Verifiable Credentials to session-bound liability receipts

---

## Summary

**Agent Receipts** (W3C VC credential type) excel at **decentralized identity** and isolated cryptographic assertions.

**Aevesa `liability-receipt/v1`** excels at **enterprise liability workflows** — atomic session packages linking trigger, policy, HITL, gateway attest, and ledger anchor for offline audit.

They are **complementary**, not interchangeable.

---

## Property matrix

| Property | W3C Agent Receipt (VC) | Aevesa `liability-receipt/v1` |
|----------|------------------------|-------------------------------|
| Primary use | Sovereign attribute verification | Enterprise diligence + Art. 12/14 |
| Session binding | Decoupled credential graph | **Atomic session** receipt |
| Enforcement plane | Verification only | **Inline intercept + RBA** |
| HITL state | External to VC | **Deterministic 402/release** on receipt |
| Gateway cosign | Not standard | **`gateway_attestation`** field |
| DENIED / refusal proof | Not standard | **`receipt_profile: DENIED`** |
| Offline verify | VC verifier | `@aevesa/verify` + verify.aevesa.com |
| Open conformance test | Vendor-specific | `npm run test:conformance-lab` |

---

## When to use which

- **Agent Receipts:** Cross-org identity, attribute federation, wallet-based agent passports  
- **Aevesa receipts:** Regulated workflows, insurance diligence, EU AI Act packs, dual-vendor gateway attest  

**Interop path:** Map VC subject claims to `identity.primary_actor`; anchor material actions as `liability-receipt/v1` with shared `entryHash`.

---

*See also: [COMPETITIVE_MATRIX.md](./COMPETITIVE_MATRIX.md) · [DELEGATION_CHAIN_STANDARDS_BLOG.md](./DELEGATION_CHAIN_STANDARDS_BLOG.md)*
