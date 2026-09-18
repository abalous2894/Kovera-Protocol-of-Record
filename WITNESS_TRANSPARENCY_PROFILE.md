# Witness Transparency Profile (Rekor + SCRAPI)

Wave 3.2 upgrade beyond OpenTimestamps-only witness backends.  
**Wave 15 Track B** adds offline Rekor RFC 6962 inclusion proof verification — not metadata-only lookup.

## Statement envelope

Witness entries use `aevesa.witness-log-entry/v1` with a SCRAPI-compatible statement:

- `schema`: `https://scitt.io/statement/v1`
- `digest`: `{ alg: sha256, value: <64-hex> }`
- `statement_type`: `https://aevesa.com/statement/ledger-anchor/v1` (or SCITT refusal type for gateway DENY)

## Rekor metadata (`aevesa.witness.rekor-metadata/v1`)

When `AEVESA_REKOR_WITNESS_URL` is configured, POST responses are parsed into portable metadata:

| Field | Purpose |
|-------|---------|
| `uuid` | Rekor entry lookup key |
| `logIndex` | Transparency log sequence |
| `logId` | Log instance identifier |
| `digest` | Statement digest bound at submit time |
| `verification_hint` | Offline lookup URL template |

Third parties can independently fetch the entry (HTTP — not required when crypto is bundled):

```http
GET {AEVESA_REKOR_WITNESS_URL}/api/v1/log/entries/{uuid}
```

## Rekor inclusion proof (`aevesa.witness.rekor-inclusion-proof/v1`)

**Wave 15 Track B** — bundled RFC 6962 artifacts for offline crypto verify (no Rekor HTTP at verify time).

| Field | Purpose |
|-------|---------|
| `log_index` | Leaf position in Rekor tree |
| `tree_size` | Tree size at integration |
| `root_hash` | Merkle root asserted by proof |
| `hashes` | Audit path (sibling hashes leaf → root) |
| `entry_body_base64` | Rekor entry body — binds proof to signed leaf (`SHA-256(0x00 \|\| body)`) and, for `hashedrekord`, to statement digest via `spec.data.hash.value` |
| `checkpoint` | Optional signed tree head envelope (root + tree size binding; cosign signature verify deferred) |

Bundled on witness rows as `rekor_inclusion_proof` and on offline exports as `rekorInclusionProof`.

Open schema: [`./aevesa-witness-rekor-inclusion-proof-v1.json`](./aevesa-witness-rekor-inclusion-proof-v1.json)

### Submit + export flow

1. POST digest to Rekor (`hashedrekord` kind)
2. GET `/api/v1/log/entries/{uuid}` — extract `verification.inclusionProof`
3. Normalize via `buildRekorInclusionProofDocument()` → attach to witness + offline export

When `AEVESA_SCITT_LIVE_WITNESS=1`, step 2 is **required** — registration fail-closed if inclusion proof is missing.

### Offline verify behavior

| Export claims | Bundled crypto | Result |
|---------------|----------------|--------|
| `rekor_metadata_only` (or no proof-strength block) | absent | Metadata valid; inclusion crypto not required |
| `rekor_inclusion_verified` (proof-strength disclosure) | absent | **Fail** — `REKOR_INCLUSION_PROOF_REQUIRED` |
| any | present + valid RFC 6962 root + digest binding | Pass — `externalRekorInclusionCrypto: true` |
| any | present + Merkle valid but entry body digest ≠ statement | Fail — `REKOR_INCLUSION_DIGEST_MISMATCH` |
| any | present + tampered root/path | Fail — root mismatch |

Verifier entry points:

- `verifyRekorCryptoInclusionProof()` — pure inclusion crypto
- `verifyExternalRekorWitnessWithInclusion()` — metadata + optional/required crypto
- `verifyScittRefusalWitnessBundle()` — full SCITT refusal export; honors `proof_strength_disclosure.external_transparency`

## Backends (stack order)

1. OpenTimestamps (`opentimestamps`)
2. Rekor transparency log (`rekor`) — when URL configured
3. Witness cosign HMAC (`witness-cosign`) — when URL configured
4. Merkle witness ledger (Postgres or memory)

## Environment matrix

### External transparency (Rekor)

| Variable | Effect on Rekor witness |
|----------|-------------------------|
| `AEVESA_REKOR_WITNESS_URL` | Enables Rekor POST + GET inclusion fetch |
| `AEVESA_SCITT_LIVE_WITNESS=1` | Fail-closed if inclusion proof not bundled; disclosure defaults to `rekor_inclusion_verified` |
| `AEVESA_SCITT_EXTERNAL_TS_URL` | Alias for Rekor URL |
| `AEVESA_WITNESS_LOG=1` | Local Merkle witness log (separate from Rekor inclusion) |

### Witness ledger custody (Wave 15 Track C)

| Variable | Production behavior |
|----------|---------------------|
| `AEVESA_LEDGER_WITNESS_REQUIRED=1` | Witness ledger submission required — boot guard active |
| `AEVESA_LEDGER_WITNESS_COSIGN=1` | Same as required for boot guard (cosign path) |
| `AEVESA_WITNESS_LEDGER_DB=1` | Postgres durable witness Merkle ledger (requires `DATABASE_URL`) |
| `AEVESA_WITNESS_LEDGER_DB=0` | **Memory lab store** — loud boot warning in production |
| `DATABASE_URL` | When set and `AEVESA_WITNESS_LEDGER_DB` unset, Postgres witness ledger auto-enabled |

**Boot guard (`assertWitnessProductionConfigOrExit`):** when `NODE_ENV=production` and witness submission is required (`AEVESA_LEDGER_WITNESS_REQUIRED=1` or `AEVESA_LEDGER_WITNESS_COSIGN=1`):

1. `AEVESA_WITNESS_LOG` must be enabled
2. Postgres witness persistence must be available (`DATABASE_URL` + not `AEVESA_WITNESS_LEDGER_DB=0`)

Process exits with `[SECURITY] Refusing to start` if misconfigured. Lab/test (`NODE_ENV !== production`) unchanged.

Example production stack:

```bash
AEVESA_WITNESS_LOG=1
AEVESA_LEDGER_WITNESS_REQUIRED=1
AEVESA_WITNESS_LEDGER_DB=1
DATABASE_URL=postgres://...
AEVESA_REKOR_WITNESS_URL=https://rekor.sigstore.dev
AEVESA_SCITT_LIVE_WITNESS=1
AEVESA_WITNESS_COSIGN_URL=https://witness.example/cosign
AEVESA_WITNESS_LOG_ID=aevesa-witness-log-1
```

## Proof-strength disclosure linkage

`aevesa.proof-strength-disclosure/v1` field `external_transparency`:

| Value | Meaning |
|-------|---------|
| `none` | No external TS configured |
| `rekor_metadata_only` | UUID/logIndex stored; offline crypto not claimed |
| `rekor_inclusion_verified` | Export must bundle `aevesa.witness.rekor-inclusion-proof/v1` or offline verify fails closed |

## Conformance

| Command | Scope |
|---------|-------|
| `npm run test:rekor-inclusion --workspace=@aevesa/verify` | RFC 6962 verify + SCITT export fail-closed |
| `npm run test:rekor-inclusion-conformance --workspace=aevesa-backend` | Backend export + profile + end-to-end |
| `npm run test:witness-production-config --workspace=aevesa-backend` | Production boot guard (Track C) |
| `npm run test:rekor-inclusion-export --workspace=aevesa-backend` | Submit mock + export bundling |
| `node private-backend/scripts/test-scitt-live-witness.mjs` | SCITT refusal + Rekor crypto in live fixture |
| `npm run test:cross-vendor-integration --workspace=aevesa-backend` | Rekor metadata + inclusion doc parsing |

Fixtures:

- `packages/verify/fixtures/rekor-inclusion-proof-demo.json` — synthetic 4-leaf tree
- `packages/verify/fixtures/scitt-live-witness-export.json` — full SCITT refusal export with bundled Rekor crypto

## Limitations (Wave 15 B)

- Checkpoint **cosign signature** verification is not yet performed offline (root + tree size binding only).
- Consistency proofs between tree heads (append-only claim) — planned; not in Wave 15 B scope.

---

*Companion: [CROSS_VENDOR_INTEGRATION_PACK.md](./CROSS_VENDOR_INTEGRATION_PACK.md)*
