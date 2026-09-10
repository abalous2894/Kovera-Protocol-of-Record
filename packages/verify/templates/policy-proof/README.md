# Policy-as-proof templates (Kaptein path pack)

Downloadable bundles for **auditors to re-run DENY logic offline** — no Aevesa policy engine API.

## List templates

```bash
aevesa policy-proof template list
```

## Export template to directory

```bash
aevesa policy-proof template export read-chain-export-deny --output ./my-audit-pack
```

Exports:

- `bundle.json` — `aevesa.policy-proof-bundle/v1` with Datalog facts + receipt
- `kaptein-path-policies-v1.json` — full Kaptein reference pack
- `README.txt` — verify commands

## Verify exported bundle

```bash
aevesa policy-proof verify ./my-audit-pack/bundle.json --summary
aevesa verify ./my-audit-pack/bundle.json --summary
```

## What this proves

The evaluator re-executes Kaptein path Datalog rules against exported session facts and confirms the **DENY was policy-correct** — stronger than a log line saying "blocked".

See [KAPTEIN_PATH_POLICY_PACK.md](../../../diligence-kit/docs/KAPTEIN_PATH_POLICY_PACK.md).
