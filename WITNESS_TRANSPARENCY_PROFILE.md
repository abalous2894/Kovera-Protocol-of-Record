# Witness Transparency Profile (Rekor + SCRAPI)

Wave 3.2 upgrade beyond OpenTimestamps-only witness backends.

## Statement envelope

Witness entries use `aevesa.witness-log-entry/v1` with a SCRAPI-compatible statement:

- `schema`: `https://scitt.io/statement/v1`
- `digest`: `{ alg: sha256, value: <64-hex> }`
- `statement_type`: `https://aevesa.com/statement/ledger-anchor/v1`

## Rekor metadata (`aevesa.witness.rekor-metadata/v1`)

When `AEVESA_REKOR_WITNESS_URL` is configured, POST responses are parsed into portable metadata:

| Field | Purpose |
|-------|---------|
| `uuid` | Rekor entry lookup key |
| `logIndex` | Transparency log sequence |
| `logId` | Log instance identifier |
| `verification_hint` | Offline lookup URL template |

Third parties verify without Aevesa dashboard access:

```http
GET {AEVESA_REKOR_WITNESS_URL}/api/v1/log/entries/{uuid}
```

## Backends (stack order)

1. OpenTimestamps (`opentimestamps`)
2. Rekor transparency log (`rekor`) — when URL configured
3. Witness cosign HMAC (`witness-cosign`) — when URL configured
4. Merkle witness ledger (Postgres or memory)

## Conformance

`npm run test:cross-vendor-integration` — validates Rekor metadata parsing and demo snapshot.

## Environment

```bash
AEVESA_WITNESS_LOG=1
AEVESA_REKOR_WITNESS_URL=https://rekor.sigstore.dev
AEVESA_WITNESS_COSIGN_URL=https://witness.example/cosign
AEVESA_WITNESS_LOG_ID=aevesa-witness-log-1
```

---

*Companion: [CROSS_VENDOR_INTEGRATION_PACK.md](./CROSS_VENDOR_INTEGRATION_PACK.md)*
