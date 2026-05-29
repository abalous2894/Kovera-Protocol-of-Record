# Kovera Protocol of Record

Open specifications and reference tooling for **Verified Autonomous Sessions (VAS)**
and the `liability-receipt/v1` accountability standard.

## Design Philosophy & Market Architecture

Kovera introduces the industry's first integrated system for **Verified Autonomous Sessions (VAS)**.
Unlike standard logging layers, telemetry networks, or detached identity credentials, Kovera enforces
cryptographic constraints directly on the active execution path before high-risk actions can take effect.

For a structural comparison against AIGP, W3C Agent Receipts, Capsule Protocol, and Project AIR, see the
[Architecture & Competitive Matrix](./COMPETITIVE_MATRIX.md).

---


Published specifications for Verified Autonomous Sessions (VAS) and agent accountability.

| Standard | Document | Schema |
|----------|----------|--------|
| **Liability Receipt v1** | [liability-receipt-v1.md](./liability-receipt-v1.md) | [liability-receipt-v1.json](./liability-receipt-v1.json) |

## Standardization badge (for repository README)

When your implementation conforms to `liability-receipt/v1`, add the following to your project README:

```markdown
[![Kovera liability-receipt/v1](https://img.shields.io/badge/standard-liability--receipt%2Fv1-2563eb?style=flat-square)](https://kovera.tech/schemas/liability-receipt/v1)
**Verified Autonomous Session Accountability** — implements liability-receipt/v1
```

Link the badge to your conformance statement or `./liability-receipt-v1.md`.

## Reference verifier (`@kovera/verify`)

Stateless offline validation for `liability-receipt/v1` lives in [`packages/verify/`](./packages/verify/README.md).

```bash
cd packages/verify && npm install && npm run build && npm run test:liability-receipt
```

## Canonical schema URL

- Document: [liability-receipt-v1.md](./liability-receipt-v1.md)
- Machine-readable: [liability-receipt-v1.json](./liability-receipt-v1.json)
- Hosted alias: [https://kovera.tech/schemas/liability-receipt/v1](https://kovera.tech/schemas/liability-receipt/v1)

## Security

Vulnerability reporting and notes on public test signing fixtures: [SECURITY.md](./SECURITY.md).

**Contact:** contact@kovera.tech
