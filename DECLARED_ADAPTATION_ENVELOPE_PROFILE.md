# Declared Adaptation Envelope Profile (Track AE)

**Status:** Track AE PR1–PR5 · **Draft schema** until design-partner relying-party review (Amendment A3)  
**Primary schema:** `aevesa.declared-adaptation-envelope/v1-draft`  
**Breach pack schema:** `aevesa.substantial-modification-signal/v1`  
**Machine-readable:** [`./aevesa-declared-adaptation-envelope-v1-draft.json`](./aevesa-declared-adaptation-envelope-v1-draft.json) · [`./aevesa-substantial-modification-signal-v1.json`](./aevesa-substantial-modification-signal-v1.json)

---

## Purpose

Digest-bind **pre-determined adaptation bounds** at conformity or deployer baseline time, then produce **independent, replayable proof** that runtime behavior stayed inside those bounds — or a **Substantial Modification Signal** when it did not.

This is an **evidence substrate**, not a conformity assessment, CE marking, or legal classification service.

**GTM line:** *Ship independent proof that a governed agent stayed inside its declared adaptation envelope — or prove exactly when and how it did not.*

---

## Triple regulatory framing (Amendment A2)

One schema family, three examiner-facing framings — selected via `regulatory_framings[]` and role-specific breach-pack blocks:

| Framing key | Audience | What the artifact supports |
|-------------|----------|----------------------------|
| `eu_art_43_4_envelope` | EU AI Act **provider** / in-house builder | Pre-determined changes envelope (Art. 43(4) ¶2; Annex IV 2(f) update mechanism, metrics, thresholds, reversion) |
| `eu_art_26_monitoring` | EU AI Act **deployer** | Post-market monitoring evidence — drift witness, not provider envelope conformity |
| `naic_exhibit_c_drift` | US state examiners / NAIC AI Systems Evaluation Tool | Exhibit C–style drift documentation (hash-only; no raw prompts) |
| `owasp_level_3_governance` | OWASP Agentic AI Security v2.01 maturity | Governance Level 3 evidence for AT6/AT7 deployment posture |

**Citation hygiene (fact-checked):**

- Substantial modification reassessment hook: **Art. 43(4)** — not Art. 45  
- EU database re-registration after substantial modification: **Art. 49**  
- OWASP: AT6/AT7 critical gap at **Level 0–1**; **AT8 do-not-deploy below Level 3**  
- NAIC Model Bulletin: **25 jurisdictions** (24 states + DC); CA/CO/NY/TX independent → **29** jurisdictions with AI expectations  
- FRE **707** is proposed/stalled — near-term insurer hook: FRE **902(13)/(14)**

---

## Operator roles (Amendment A1 — copy-critical)

| `operator_role` | Primary artifact language | Must not |
|-----------------|---------------------------|----------|
| `provider` | Art. 43(4) declared envelope + provider breach signal (`eu_art_43_4_signal`) | Claim deployer-only Art. 26 monitoring as envelope conformity |
| `deployer` | Art. 26 monitoring signal + optional NAIC Exhibit C drift | Claim Art. 43(4) envelope conformity without `eu_art_26_monitoring` framing |

Offline verify enforces framing: deployer artifacts with Art. 43(4)-only provider framing **fail** verify (`DEPLOYER_ART43_FRAMING_INVALID`).

---

## Declared Adaptation Envelope — `aevesa.declared-adaptation-envelope/v1-draft`

### Required bounds (SHA-256 hex)

| Field | Source at mint |
|-------|----------------|
| `policy_hash` | Active gate policy version hash |
| `tool_catalog_fingerprint` | Aggregated AttestMCP pinned manifest digests |
| `memory_root_hash` | Optional — session episodic root at intercept |
| `mcp_manifest_fingerprint` | Optional — MCP manifest bind digest |
| `tool_allowlist_digest` | Optional — explicit allowlist digest |

### Monitored metrics and thresholds

Default monitored metrics: `receipt_drift_score`, `tool_catalog_delta`.  
Drift evaluation is **pure** in `@aevesa/verify` (`evaluateAdaptationEnvelopeDrift()`).

### Composed member digests (optional slots)

| Slot | Typical source |
|------|----------------|
| `behavioral_sbom_digest` | Wave 7 behavioral SBOM export |
| `memory_commitment_profile_digest` | Memory commitment profile |
| `mcp_manifest_bind_digest` | MCP manifest bind at intercept |

### Integrity

`envelope_digest = SHA-256(stableStringify(preimage))` — preimage excludes `envelope_entry_hash` and `envelope_digest`.

Optional ledger witness: `ADAPTATION_ENVELOPE_MINTED` → `envelope_entry_hash` + guardian cosign.

### Offline verify

```javascript
import { verifyDeclaredAdaptationEnvelopeBundle } from '@aevesa/verify';
```

---

## Substantial Modification Signal — `aevesa.substantial-modification-signal/v1`

Emitted only when `drift_status === 'breach'`. Composes:

| Member | Role |
|--------|------|
| Declared adaptation envelope digest | Baseline at breach time |
| Adaptation drift witness digest | Runtime snapshot vs bounds evaluation |

`contributing_entry_hashes[]` must include replayable ledger anchors (envelope mint + drift witness).

Provider vs deployer `regulatory_framing` blocks differ — see Amendment A1 in verify (`validateSubstantialModificationSignalFraming()`).

### Offline verify

```javascript
import { verifySubstantialModificationSignalBundle } from '@aevesa/verify';
```

---

## API surfaces

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/api/v1/apor/adaptation/envelope` | Governance viewer + tenant org | Mint declared envelope |
| `POST` | `/api/v1/apor/adaptation/drift-witness` | Governance viewer + tenant org | Compare runtime snapshot vs envelope |
| `GET` | `/api/v1/apor/adaptation/envelope/latest` | Governance viewer + tenant org | Recent envelope mint rows |
| `POST` | `/api/v1/apor/adaptation/breach-pack` | Governance viewer + tenant org | Mint substantial modification signal (breach only) |
| `GET` | `/api/v1/apor/adaptation/breach-pack/latest` | Governance viewer + tenant org | Recent breach pack rows |
| `GET` | `/api/v1/public/evidence/adaptation-envelope-demo` | Public | Demo arc (mint → 30 days inside → breach) |

**Rate limits:** APoR trust-boundary POST limiter (same class as insurance signal digest).

**Assurance Autopilot:** When `AEVESA_ADAPTATION_ENVELOPE_DRIFT_ENABLE` is not `0`, nightly tenant assurance runs adaptation drift witness after cryptographic drift batch (`adaptationEnvelopeDrift` on signed report).

---

## Safe claims

| Claim | Allowed |
|-------|---------|
| Envelope bounds were digest-bound at declared baseline | ✅ |
| Nightly drift witness shows inside_envelope or breach with field-level diff | ✅ |
| Breach pack binds envelope + witness to replayable entry hashes | ✅ |
| Provider Art. 43(4) **evidence alignment** for pre-determined changes | ✅ (word as evidence, not certification) |
| Deployer Art. 26 **monitoring evidence** for post-market drift | ✅ |
| NAIC Exhibit C–style **drift signal** for examiner file | ✅ (hash-only) |
| OWASP Level 3 **governance evidence** for declared envelope | ✅ |
| Legal conformity assessment / CE marking / notified-body outcome | ❌ |
| Legal advice on whether modification is "substantial" | ❌ |

---

## Non-goals

- Replacing notified-body or conformity assessment procedures  
- Implied certification that an agent is "EU AI Act compliant"  
- Raw prompt, PII, or tool argument export in envelope or breach packs  
- Conflating provider and deployer regulatory framing in a single artifact  
- Freezing schema to `/v1` before first external relying-party review (Amendment A3)

---

## Verify portal and demo

| Surface | URL |
|---------|-----|
| Public demo | [verify.aevesa.com?demo=adaptation-envelope](https://verify.aevesa.com?demo=adaptation-envelope) |
| Offline demo data | `aevesa-app-site/src/js/adaptationEnvelopeDemoData.js` |
| Unified CLI | `aevesa verify` auto-detects both schemas |

---

## Conformance

```bash
npm run test:adaptation-envelope-conformance --workspace=aevesa-backend
```

Included in backend core validation (`test:backend:core`).

---

## Protocol compatibility

**Classification:** Safe additive — new schemas and routes; no changes to existing receipt profiles.

Draft envelope schema ID (`/v1-draft`) will promote to `/v1` after design-partner relying-party sign-off per Amendment A3.

---

## Adaptation lifecycle export (Track P6)

Composed litigation / Art. 12 shaped export: **`aevesa.adaptation-lifecycle-export/v1`** bundles the declared envelope, drift witness timeline, and optional substantial modification signal.

| Surface | Path |
|---------|------|
| APoR export | `GET /api/v1/apor/adaptation/lifecycle-export?systemId=...` |
| Public demo API | `GET /api/v1/public/evidence/adaptation-lifecycle-export-demo` |
| Verify portal | `https://verify.aevesa.com?demo=adaptation-lifecycle-export` |
| Offline regen | `npm run generate:adaptation-lifecycle-export-demo-sample` (from `private-backend/`) |
| Open schema | [`./aevesa-adaptation-lifecycle-export-v1.json`](./aevesa-adaptation-lifecycle-export-v1.json) |

Verify: `verifyAdaptationLifecycleExportBundle()` in `@aevesa/verify` · unified CLI auto-detects schema.

---

## SCITT alignment (Track P9)

Lifecycle envelope and breach signal artifacts carry an additive `scitt_alignment` block mapping to SCITT agent-receipt and AIR draft vocabulary. The block does **not** participate in digest preimage.

| Doc | Role |
|-----|------|
| [`./DECLARED_ADAPTATION_ENVELOPE_SCITT_ALIGNMENT.md`](DECLARED_ADAPTATION_ENVELOPE_SCITT_ALIGNMENT.md) | Mapping tables, statement types, verify API |

Mint and breach-pack services attach alignment via `applyAdaptationEnvelopeScittAlignment()` / `applySubstantialModificationScittAlignment()` in `@aevesa/verify`.

---

## Related artifacts

| Doc | Role |
|-----|------|
| [`docs/sales/DECLARED_ADAPTATION_ENVELOPE_ONEPAGER.md`](../sales/DECLARED_ADAPTATION_ENVELOPE_ONEPAGER.md) | GTM one-pager |
| [`docs/strategy/MULTI_YEAR_RESEARCH_AGENDA.md`](../strategy/MULTI_YEAR_RESEARCH_AGENDA.md) | Track AE decision + PR sequence |
| [`./BEHAVIORAL_SBOM_PROFILE.md`](BEHAVIORAL_SBOM_PROFILE.md) | Composed SBOM digest source |
| [`./INSURANCE_SIGNAL_DIGEST_PROFILE.md`](INSURANCE_SIGNAL_DIGEST_PROFILE.md) | Adjacent cadence-friendly insurer digest |
