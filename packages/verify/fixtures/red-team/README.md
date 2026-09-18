# Red team composite mutator fixtures (Lane 4)

Offline bundles used by the red team orchestrator (`npm run test:red-team:offline -- --lane=4`).

## Primary fixtures (in-repo)

| Fixture / builder | Script | Attack template |
|-------------------|--------|-----------------|
| `fixtures/cap-session-proof-demo.json` | `test-composite-evidence-graph-gate4.mjs` | Full CAP baseline |
| `fixtures/red-team/cap-digest-only-carrier-mutator.json` | `test-red-team-lane4-composite-mutators.mjs` | `member_receipts: []` — INV-04 |
| `fixtures/red-team/cap-terminal-only-portal-mutator.json` | same | Terminal paste without manifest/members — INV-09 |
| `fixtures/red-team/mga-exporter-verify-ok-without-body-mutator.json` | same | Exporter `verify_ok: true` without proof layer — INV-03 (PC-09) |
| MGA demo snapshot | `carrierMgaAcceptanceDemoService.js` | Hash-only kit without `member_documents` (Gate 4 inline) |
| Policy deny bundle | `fixtures/policy-proof-deny-bundle.json` | DENY terminal with closure rows |

## Oracle

For carrier profile, `evaluateCompositeEvidenceGraph()` must return:

- `fail` or `warn` on incomplete / digest-only graphs
- never silent `pass` when required statement types are absent

## Adding new mutators

1. Add mutated JSON or inline builder in a conformance script under `packages/verify/scripts/`.
2. Wire the script into `scripts/test-red-team-offline.mjs` Lane 4.
3. Document the invariant (INV-XX) in [AEVESA_RED_TEAM_PLAYBOOK.md](../../../../docs/security/AEVESA_RED_TEAM_PLAYBOOK.md).

Do not commit customer receipts or production keys.
