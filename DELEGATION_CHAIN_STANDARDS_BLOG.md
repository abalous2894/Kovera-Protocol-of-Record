# Delegation Chain Standards Blog — Cryptographic vs Declarative Multi-Agent Provenance (Wave 2.1)

**Audience:** Security architects, standards committees, procurement  
**Published:** Wave 2.1 · June 2026

---

Multi-agent AI systems are delegating faster than accountability infrastructure is standardizing. Three patterns are racing to own the vocabulary:

1. **Declarative chains** — ADCS v0.1, OIDC-A delegation claims  
2. **Cryptographic hop proofs** — HDP-style signed receipts per delegation event  
3. **Vendor-scoped logs** — orchestrator traces that don't survive export

Aevesa's position: **both declarative and cryptographic evidence are required**. Declarative shape gets you procurement alignment. Cryptographic hops get you offline verification.

---

## Why declarative alone fails audits

ADCS v0.1 gives buyers a common JSON shape: `originSub`, ordered `links[]`, scope intersection rules. That's necessary — it answers *"what should the artifact look like?"*

It does not, by itself, answer *"did this artifact come from the system that actually enforced the delegation?"* Without signatures, a chain is a JSON file anyone can edit.

---

## Why cryptographic alone fails procurement

HDP hop receipts prove integrity of individual hops — but security reviewers still ask for **field names they recognize** in RFP checklists. Pure hex chains don't map to ADCS conformance matrices.

---

## kovera-delegation-chain/1 — both layers

`kovera-delegation-chain/1` publishes:

- **ADCS-aligned `links[]`** for procurement and interop  
- **HDP `proof.hops[]`** for offline verify at verify.aevesa.com  
- **Human origin invariant** — `origin_sub` never mutates across hops  

Demo scenario shipped: Human → Agent A (orchestrator) → Agent B (researcher), scopes narrowed, full chain verified in under 90 seconds.

---

## Does Aevesa implement ADCS?

**Aligned on data shape and invariants.** Aevesa extends ADCS with signed hop proofs — see [DELEGATION_CHAIN_ADCS_FAQ.md](../sales/DELEGATION_CHAIN_ADCS_FAQ.md).

We acknowledge ADCS v0.1 and HDP as prior art. Aevesa's contribution is binding them to the **Prove ledger** — every material action still terminates in `liability-receipt/v1`.

---

## Try it

- Open spec: `spec/kovera-delegation-chain-1.json`  
- Verify demo: https://verify.aevesa.com?demo=delegation  
- Sample pack: `diligence-kit/samples/delegation-chain/`

---

*Aevesa · Agentic Evidence Infrastructure · Wave 2.1*
