# Protocol & API Compatibility Policy

**Status:** Active · **Adopted:** 2026-07-12 · **Owner:** Engineering  
**Bounded context:** BC-PRT Open Protocol · **Companion:** CONTEXT-MAP (Aevesa monorepo internal)

> Contracts are infrastructure. Integrators, auditors, and offline verifiers depend on Aevesa surfaces remaining predictable. This policy defines what may ship without a version bump, what requires explicit versioning, and how changes are reviewed.

**Inspiration:** [Stripe API versioning](https://stripe.com/blog/api-versioning) — lightweight upgrades, first-class versioning, fixed-cost compatibility layers.

---

## Scope — versioned surfaces

| Surface | ID / prefix | Owner | Integrator expectation |
|---------|-------------|-------|------------------------|
| **Liability receipt** | `liability-receipt/v1` | BC-PRT / BC-VER | Offline verify forever; schema field is normative |
| **Audit event (legacy export)** | `sentinul-audit-event/v1` | BC-SOV | SIEM/CEF consumers; additive only on v1 |
| **Governance event** | `aevesa-governance-event/v2` | BC-SOV | Webhook/SIEM/OTLP; v2 is current export shape |
| **Webhook batch** | `aevesa-webhook-batch/v2` | BC-SOV | Batched governance delivery |
| **HTTP API** | `/api/v1/*` | private-backend | Session JWT + documented public routes |
| **Public verify API** | `/api/v1/public/*` | BC-VER | Unauthenticated verify; highest stability bar |
| **Open protocol repo** | Sentinul-Governance-Protocol/ | BC-PRT | Published spec + verify reference |
| **Verify package exports** | `@aevesa/verify` package.json `exports` | BC-VER | Library + CLI contract |
| **Shared package exports** | `@aevesa/shared` package.json `exports` | BC-GOV | Aegis client + dashboard helpers |
| **Conformance clauses** | ./LIABILITY_RECEIPT_CONFORMANCE.md | BC-VER | Numbered LR-* requirements |
| **JSON Schema artifacts** | spec/liability-receipt-v1.json | BC-PRT | Machine validation |

**Out of scope (internal, no compatibility promise):**

- `/api/v1/internal/*` — service-key only; may change with deploy
- Lab routes behind `GENESIS_API_PUBLIC` / `SKILLS_GAVEL_API_PUBLIC` gates
- Dashboard React components and non-exported backend services
- Prisma schema (separate ASK FIRST gate in GUARDRAILS (Aevesa monorepo internal))

---

## Principles

1. **Get design right first** — prefer additive changes; breaking changes are a last resort.
2. **Pinned integrator experience** — code written against `liability-receipt/v1` or `/api/v1/public/verify-receipt` must keep working until the integrator opts into a new version.
3. **Core logic stays current** — engineers implement against the latest internal schema; compatibility layers translate outward (Stripe model).
4. **Fixed-cost old versions** — encapsulate breaking deltas in version modules or new schema IDs; never scatter `if (version)` across business logic.
5. **Evidence is immutable** — receipts and ledger entries already issued are never retroactively reinterpreted.

---

## Safe changes (no version bump required)

Ship freely when **all** checks pass:

| Category | Examples |
|----------|----------|
| **New optional request field** | New optional header on `POST /api/v1/genesis/proxy/call` |
| **New optional response field** | New metadata on verify response; old clients ignore |
| **New endpoint** | `GET /api/v1/assurance/latest` (did not exist before) |
| **New enum value appended** | New `verdict` subtype documented as optional |
| **New extension block on receipt** | New optional top-level extension with digest-binding rules documented |
| **New conformance clause** | New LR-E-* row in LIABILITY_RECEIPT_CONFORMANCE.md with tests |
| **New export from verify/shared** | New `./foo` export path; existing exports unchanged |
| **Documentation-only** | Clarifications that do not alter normative MUST/SHALL |
| **Performance / internal refactor** | Same bytes on the wire |

### Safe-change checklist (author self-certifies)

- [ ] Existing required fields unchanged (name, type, semantics)
- [ ] Existing clients ignoring unknown fields still succeed
- [ ] `@aevesa/verify` spec vectors still pass (`npm run test:verify`)
- [ ] No change to digest-binding pillar order without new profile
- [ ] API review checklist (Appendix A) completed for HTTP changes

---

## Breaking changes (version bump + ledger required)

Require **explicit versioning** and a **CHANGELOG-LEDGER** `COMPAT:` entry:

| Category | Examples | Resolution |
|----------|----------|------------|
| **Rename field** | `verified` → `status` on API resource | New schema ID or `/api/v2/` + transform module |
| **Change field type** | `boolean` → `object` | New schema version |
| **Change semantics** | `PERMIT` now implies async HITL complete | New schema or documented migration window |
| **Remove field** | Drop response field integrators may depend on | Version module or major bump |
| **Add required request field** | New mandatory body property | New API version or major bump |
| **Tighten validation** | Reject payloads previously accepted | Breaking unless gated behind opt-in flag |
| **Change digest profile** | Reorder canonical pillars | New `receipt_profile` or `liability-receipt/v2` |
| **Delete export** | Remove `@aevesa/verify` export path | Deprecation period + ledger |
| **Auth scope change** | Public route becomes authenticated | Breaking for anonymous integrators |

### Breaking-change process

1. **ASK FIRST** — human greenlight per GUARDRAILS (Aevesa monorepo internal)
2. **Design note** — 1-page summary: who breaks, migration path, sunset timeline
3. **Version artifact** — one of:
   - New document schema (`liability-receipt/v2`, `aevesa-governance-event/v3`)
   - New HTTP prefix (`/api/v2/...`) with transforms from v1 responses
   - Deprecation shim with `Sunset` header (minimum 90 days for public HTTP)
4. **Tests** — negative tests proving old clients still work on pinned version OR migration guide with conformance vectors
5. **Ledger** — append `COMPAT:` entry (format below)
6. **Docs** — update Sentinul-Governance-Protocol/, conformance doc, CONTEXT-MAP if boundary moves

---

## Versioning mechanics by surface

### Document schemas (`*/v1`, `*/v2`)

- Schema identity is the `schema` string field (e.g. `liability-receipt/v1`).
- **Minor evolution within v1:** optional extensions only; must pass LR-E-* conformance rules.
- **Major evolution:** new schema ID (`liability-receipt/v2`); v1 verifiers remain valid for v1 documents.
- Producers MUST emit the correct `schema` value; consumers MUST reject unknown schemas (LR-D-003).

### HTTP API (`/api/v1/`)

- URL prefix `v1` is the integrator pin. Treat it like Stripe's dated versions conceptually.
- **Current policy:** all production integrator routes live under `/api/v1/`. Breaking changes ship as:
  1. **Preferred:** additive v1 + new endpoint, OR
  2. **When unavoidable:** `/api/v2/` with response transform layer (future), OR
  3. **Opt-in flags:** `?compat=2026-07-12` or `Aevesa-Version` header (document per change)
- **Public verify routes** (`/api/v1/public/*`) — slowest change velocity; treat as Tier 0 stability.

### Package exports (`@aevesa/verify`, `@aevesa/shared`)

- Follow **additive-only** on existing export paths.
- New capability → new subpath export (e.g. `./core/isRecord`).
- Removing or renaming export → deprecation release + ledger + fitness allowlist update if needed.

### Sentinul-Governance-Protocol/

- Normative MUST/SHALL in spec markdown is a contract.
- Typos and clarifications that don't change testable behavior = safe.
- Any change that would fail existing `npm run test:liability-receipt` = breaking.

---

## Worked examples

### Example 1 — Safe: add optional receipt extension

**Change:** Add optional `environmental_metadata` block to `liability-receipt/v1` producers.

| Question | Answer |
|----------|--------|
| Safe or breaking? | **Safe** — optional, not in digest profile unless documented |
| Version bump? | No |
| Required tests | Extend LR-E-* clause + `test:liability-receipt` vector |
| Ledger? | Optional `COMPAT: additive` note |

### Example 2 — Safe: new public endpoint

**Change:** Add `GET /api/v1/public/transparency-commitments` (already shipped).

| Question | Answer |
|----------|--------|
| Safe or breaking? | **Safe** — new endpoint, no existing client depends on it |
| Version bump? | No |
| Required tests | Route smoke + rate-limit behavior |
| Ledger? | No |

### Example 3 — Breaking: rename response field

**Change:** Rename API field `entryHash` → `entry_hash` on a documented public response.

| Question | Answer |
|----------|--------|
| Safe or breaking? | **Breaking** — clients parsing `entryHash` break |
| Version bump? | Yes — dual-field sunset period OR `/api/v2/` |
| Required tests | Golden response fixtures for both shapes during sunset |
| Ledger? | **Required** `COMPAT:` entry with sunset date |

### Example 4 — Breaking: digest pillar reorder

**Change:** Reorder `RECEIPT_DIGEST_PROFILE_ORDER` in `@aevesa/verify`.

| Question | Answer |
|----------|--------|
| Safe or breaking? | **Breaking** — all previously sealed digests invalidate |
| Version bump? | New `receipt_profile` or `liability-receipt/v2` |
| Required tests | Full `test:digest-binding` + diligence-kit sample regeneration |
| Ledger? | **Required**; ASK FIRST |

---

## CHANGELOG-LEDGER convention

Append on every breaking or sunset change:

```markdown
## [YYYY-MM-DD] COMPAT: <short title>

**Surface:** liability-receipt/v1 | /api/v1/public | @aevesa/verify | …
**Type:** breaking | sunset | deprecation
**Sunset:** YYYY-MM-DD (if applicable)
**Migration:** <one sentence integrator action>
**Validation:** <npm script that proves compatibility>
```

**Safe additive changes** may use a lighter `COMPAT: additive` note when integrators benefit from awareness (optional).

---

## Roles & review

| Role | Responsibility |
|------|----------------|
| **Author** | Classify safe vs breaking; complete Appendix A for HTTP |
| **Reviewer** | Challenge classification; verify tests exist |
| **Human approver** | Required for all breaking changes (ASK FIRST) |
| **Agent (Cursor)** | MUST NOT merge breaking protocol edits without explicit user approval |

---

## Appendix A — Lightweight API review checklist

Complete before merging any HTTP contract change under `/api/v1/`:

| # | Question | Yes / N/A |
|---|----------|-----------|
| A1 | Is this route documented in Sentinul-Governance-Protocol/ or module stub? | |
| A2 | Is the change **safe** per § Safe changes? If no → breaking process | |
| A3 | Are existing required JSON fields unchanged in name, type, and meaning? | |
| A4 | Will old dashboard / MCP / diligence-kit clients work without code changes? | |
| A5 | If public (`/api/v1/public/*`), is rate-limit behavior unchanged or documented? | |
| A6 | Are error codes additive (not repurposed)? | |
| A7 | Does `npm run test:core` pass? | |
| A8 | If receipt/governance schema touched, does `npm run test:verify` pass? | |
| A9 | Bounded context declared (BC-* from CONTEXT-MAP)? | |
| A10 | Ledger entry needed? If breaking → `COMPAT:` drafted | |

**Reviewer sign-off:** PR description includes `Compatibility: safe|breaking` and completed A1–A10.

---

## Appendix B — Stability tiers

| Tier | Routes / artifacts | Change velocity |
|------|-------------------|-----------------|
| **T0** | `liability-receipt/v1`, `/api/v1/public/*`, `@aevesa/verify` CLI | Slowest; breaking needs v2 + 90-day sunset minimum |
| **T1** | `/api/v1/aegis`, `/api/v1/apor`, `/api/v1/assurance`, governance webhooks | Additive preferred; breaking needs ledger |
| **T2** | `/api/v1/genesis/*`, `/api/v1/governance/*` (authenticated) | Faster; document in protocol README |
| **T3** | `/api/v1/internal/*`, lab flags | No compatibility promise |

---

## Related artifacts

| Doc | Role |
|-----|------|
| [LIABILITY_RECEIPT_CONFORMANCE.md](./LIABILITY_RECEIPT_CONFORMANCE.md) | Normative LR-* clauses |
| CONTEXT-MAP (Aevesa monorepo internal) | BC-PRT boundaries |
| GUARDRAILS (Aevesa monorepo internal) | ASK FIRST enforcement |
| [EXPERT_GAPS_ROADMAP.md](../architecture/EXPERT_GAPS_ROADMAP.md) | Phase 2 deliverable |
| [Sentinul-Governance-Protocol/README.md](../../Sentinul-Governance-Protocol/README.md) | Integrator-facing spec |
