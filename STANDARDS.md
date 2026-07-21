# Aevesa Open Standards

Published specifications for Verified Autonomous Sessions (VAS) and agent accountability.

| Standard | Document | Schema |
|----------|----------|--------|
| **Liability Receipt v1** | [liability-receipt-v1.md](./liability-receipt-v1.md) | [liability-receipt-v1.json](./liability-receipt-v1.json) |
| **Receipt-before-action v1** | [RECEIPT_BEFORE_ACTION_CONFORMANCE.md](./RECEIPT_BEFORE_ACTION_CONFORMANCE.md) | — |
| **Delegation chain v1** | [kovera-delegation-chain-1.md](./kovera-delegation-chain-1.md) | [kovera-delegation-chain-1.json](./kovera-delegation-chain-1.json) |
| **DENIED receipt profile** | [DENIED_RECEIPT_PROFILE.md](./DENIED_RECEIPT_PROFILE.md) | fields on `liability-receipt/v1` |
| **Art. 73 custody pack** | [INCIDENT_CUSTODY_PACK.md](./INCIDENT_CUSTODY_PACK.md) | [kovera-incident-custody-pack-1.json](./kovera-incident-custody-pack-1.json) |
| **Cross-vendor integration v1** | [CROSS_VENDOR_INTEGRATION_PACK.md](./CROSS_VENDOR_INTEGRATION_PACK.md) | [kovera-cross-vendor-integration-1.json](./kovera-cross-vendor-integration-1.json) |

**Release history:** [CHANGELOG.md](./CHANGELOG.md)

**Compatibility:** [PROTOCOL_COMPATIBILITY_POLICY.md](./PROTOCOL_COMPATIBILITY_POLICY.md) — what may change without a version bump on receipts, public APIs, and `@aevesa/verify`.

## Conformance & verification

| Program | Document / tool |
|---------|-----------------|
| Liability receipt clauses | [LIABILITY_RECEIPT_CONFORMANCE.md](./LIABILITY_RECEIPT_CONFORMANCE.md) |
| Offline verifier | [`packages/verify/`](./packages/verify/README.md) — `npm run test:liability-receipt` |
| Conformance lab (hosted) | [aevesa.com/conformance-lab.html](https://aevesa.com/conformance-lab.html) |

## Competitive & comparison docs

- [COMPETITIVE_MATRIX.md](./COMPETITIVE_MATRIX.md) — industry reference matrix
- [AGENT_RECEIPTS_VS_LIABILITY_RECEIPT.md](./AGENT_RECEIPTS_VS_LIABILITY_RECEIPT.md)
- [CRYPTOGRAPHIC_VS_DECLARATIVE_EVIDENCE.md](./CRYPTOGRAPHIC_VS_DECLARATIVE_EVIDENCE.md)
- [SCITT_AIR_PROFILE_ALIGNMENT.md](./SCITT_AIR_PROFILE_ALIGNMENT.md)
- [SCITT_REFUSAL_EVENT_ALIGNMENT.md](./SCITT_REFUSAL_EVENT_ALIGNMENT.md)
- [WITNESS_TRANSPARENCY_PROFILE.md](./WITNESS_TRANSPARENCY_PROFILE.md)
- [PRE_EXECUTION_DENIED_EVIDENCE.md](./PRE_EXECUTION_DENIED_EVIDENCE.md)
- [DELEGATION_CHAIN_STANDARDS_BLOG.md](./DELEGATION_CHAIN_STANDARDS_BLOG.md)

## Standardization badges

### liability-receipt/v1

When your implementation conforms to `liability-receipt/v1`, add the following to your project README:

```markdown
[![Aevesa liability-receipt/v1](https://img.shields.io/badge/standard-liability--receipt%2Fv1-2563eb?style=flat-square)](https://aevesa.com/schemas/liability-receipt/v1)
**Verified Autonomous Session Accountability** — implements liability-receipt/v1
```

Link the badge to [LIABILITY_RECEIPT_CONFORMANCE.md](./LIABILITY_RECEIPT_CONFORMANCE.md) or [liability-receipt-v1.md](./liability-receipt-v1.md).

### receipt-before-action/v1

When your MCP bridge or gateway enforces ledger commit before ALLOW:

```markdown
[![Aevesa receipt-before-action/v1](https://img.shields.io/badge/conformance-receipt--before--action%2Fv1-0d9488?style=flat-square)](https://aevesa.com/schemas/receipt-before-action/v1)
**Receipt-before-action** — tool execution blocked when ledger commit fails (fail-closed).
```

See [RECEIPT_BEFORE_ACTION_CONFORMANCE.md](./RECEIPT_BEFORE_ACTION_CONFORMANCE.md).

### conformance-lab/v1

When your integration reproduces gateway attest → verify interop:

```markdown
[![Aevesa conformance-lab/v1](https://img.shields.io/badge/conformance-lab-v1-7c3aed?style=flat-square)](https://aevesa.com/conformance-lab.html)
**Aevesa Conformance Lab** — gateway attest → receipt → offline verify reproducible.
```
