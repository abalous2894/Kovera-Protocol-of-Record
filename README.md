# KOVERA: SOVEREIGN SECURITY INFRASTRUCTURE

**Enterprise-Grade Enforcement for Autonomous AI Agents and Multi-Agent Systems**

**Version:** 5.0.0 · Genesis Phase 5–6 (Production)  
**Edition:** Sovereign Security Infrastructure

> Beyond Guardrails. Real-Time Sovereignty.

| | |
|---|---|
| **Dashboard** | [app.kovera.tech](https://app.kovera.tech) — sign up, operate agents, export proof |
| **Verify portal** | [verify.kovera.tech](https://verify.kovera.tech) — zero-trust receipt & bundle checks |
| **API** | `https://api.kovera.tech` |
| **Standard** | [`liability-receipt/v1`](./liability-receipt-v1.md) · [`@kovera/verify`](./packages/verify/) |

---

## Overview

**Kovera** is a deterministic, multi-layer **enforcement** platform for autonomous AI agents in production. Every LLM call, MCP tool invocation, and delegated action passes through a fail-closed pipeline **before** side effects occur. Decisions are recorded on the **Aegis audit ledger** (hash-chained, tamper-evident) and exportable as **Proof-of-Action bundles** or **`liability-receipt/v1`** documents for auditors.

Product loop: **Intercept · Decide · Prove.**

This is not a monitoring system. It is an enforcement system.

**This repository** publishes the open **`liability-receipt/v1`** specification, the **`@kovera/verify`** reference verifier, and product usage documentation. The hosted control plane (dashboard, Genesis gateway, HITL broker) runs at **kovera.tech** — you do not need to self-host to use Kovera.

---

## Getting started

Pick the path that matches your role:

| I am a… | Do this first |
|---|---|
| **Operator / security lead** | [Sign up](https://app.kovera.tech) → open **Infrastructure** (`/?tab=vanguard-infrastructure`) → run **Preset B · Exceeds mandate** → complete manager HITL → **Open verification dashboard** |
| **Developer integrating agents** | [Log in](https://app.kovera.tech) → copy session JWT → route LLM calls through **`POST /api/v1/genesis/proxy/call`** ([§4 Proxied LLM Calls](#proxied-llm-calls)) |
| **Auditor / compliance** | Export a Proof-of-Action bundle from the dashboard → paste at [verify.kovera.tech](https://verify.kovera.tech) ([§4 Proof-of-Action export](#proof-of-action-export-and-verification-loop)) |
| **Protocol adopter / integrator** | Read [`liability-receipt-v1.md`](./liability-receipt-v1.md) → run `cd packages/verify && npm install && npm run build && npm run test:liability-receipt` |
| **IDE / MCP user** | `npm install -g @kovera/mcp-server` → `kovera-mcp setup` ([§4 MCP plugin](#kovera-mcp-plugin-public-mcp-plugin)) |

### Five-minute operator demo

1. Go to [app.kovera.tech](https://app.kovera.tech) and create an account.
2. Navigate to **Infrastructure** (Vanguard lab).
3. Run **Preset B · Exceeds mandate** — you should see **`402 PENDING_APPROVAL`** (step-up required).
4. Click **Complete manager HITL sign** — expect **`200 PERMITTED`**.
5. Click **Open verification dashboard** (requires governance viewer role) or copy the export JSON to [verify.kovera.tech](https://verify.kovera.tech).

Every step above appends to your tenant's Aegis ledger. You can export auditor-grade proof without trusting Kovera's UI alone.

### Five-minute developer integration

After logging into the dashboard, route one LLM call through Genesis:

```bash
curl -X POST "https://api.kovera.tech/api/v1/genesis/proxy/call" \
  -H "Authorization: Bearer <dashboard-jwt>" \
  -H "Content-Type: application/json" \
  -H "X-LLM-Api-Key: <your-openai-or-anthropic-key>" \
  -d '{
    "endpoint": "https://api.openai.com/v1/chat/completions",
    "model": "gpt-4o",
    "messages": [{ "role": "user", "content": "Summarize this policy clause." }],
    "sessionId": "dev-session-001"
  }'
```

- **`403`** + `blockPhase` → enforcement blocked the call; an audit row was written.
- **`200`** → clean response plus inspection metadata (`intentVerdict`, `skillScanVerdict`, …).

Provider API keys go in the **`X-LLM-Api-Key`** header (or your tenant's configured env) — never in the JSON body.

---

## Table of Contents

0. [Getting started](#getting-started)
1. [The Sovereign Architecture](#1-the-sovereign-architecture)
2. [Key Features](#2-key-features)
   - [Skill Scanner](#skill-scanner)
   - [Intent Binder](#intent-binder)
   - [Chain Detector](#chain-detector)
   - [LLM Proxy Adapter](#llm-proxy-adapter)
   - [FinTech FDLP](#fintech-fdlp-regulated-data-policy)
   - [Step-Up Authorization (HITL)](#step-up-authorization-hitl)
   - [Proof-of-Action bundles](#proof-of-action-bundles)
3. [Account setup & integrations](#3-account-setup--integrations)
   - [Dashboard access](#dashboard-access)
   - [Offline verifier (`@kovera/verify`)](#offline-verifier-koveraverify)
   - [Open standard (`liability-receipt/v1`)](#open-standard-liability-receiptv1)
4. [Usage](#4-usage)
   - [Proxied LLM Calls](#proxied-llm-calls)
   - [FinTech FDLP configuration](#fintech-fdlp-configuration-and-behavior)
   - [Non-LLM Genesis scan (FDLP)](#non-llm-genesis-scan-fdlp-only)
   - [The HITL approval flow (step-up)](#the-hitl-approval-flow-step-up)
   - [Tool Registration and Skill Scanning](#tool-registration-and-skill-scanning)
   - [Public sovereignty verification (receipt portal)](#public-sovereignty-verification-receipt-portal)
   - [Proof-of-Action export and verification loop](#proof-of-action-export-and-verification-loop)
   - [Operator dashboard workspaces](#operator-dashboard-workspaces)
   - [Kovera MCP plugin](#kovera-mcp-plugin-public-mcp-plugin)
   - [Live Telemetry Dashboard](#live-telemetry-dashboard)
   - [Web dashboard, MFA, and settings](#web-dashboard-mfa-and-settings)
   - [Live Threat Feed (SSE)](#live-threat-feed-sse)
5. [API Reference](#5-api-reference)
   - [Governance and Proof-of-Action](#governance-and-proof-of-action)
   - [Public verification (unauthenticated)](#public-verification-unauthenticated)
6. [Security Mandate](#6-security-mandate)
7. [Configuration](#7-configuration)
8. [BYOK (Bring Your Own Key)](#8-byok-bring-your-own-key)
9. [Related documents](#related-documents-in-this-repository)

---

## 1. The Sovereign Architecture

Every LLM call, tool invocation, and agent action is forced through a **5-Layer Enforcement Gauntlet** before execution and again upon response. Layers execute sequentially; a block at any layer terminates the operation immediately and emits an immutable audit record. There is no bypass path.

**Cryptographic accountability:** Enforcement decisions, delegated-action outcomes, and **human-in-the-loop (HITL)** releases are written into the **Aegis audit ledger** with hash-chained entries (Merkle-oriented binding per event). That design yields a **tamper-evident history**: the agent request, the Kovera verdict, and (when applicable) the manager's step-up approval are linked in a way that breaks forensic integrity if any single row is altered—not merely a conventional append-only SQL log.

```
INBOUND REQUEST
       │
       ▼
┌─────────────────────┐
│  LAYER 1: INTENT    │  Neural Mirror + Intent Binder
│                     │  Real-time prompt risk-scoring; semantic alignment
│  Pre-call intent    │  verification; jailbreak detection; persona-override
│  verification       │  blocking; divergence analysis against declared context
└────────┬────────────┘
         │ PASS
         ▼
┌─────────────────────┐
│  LAYER 2: SKILL     │  Skill Scanner — Proprietary Sovereign Logic
│                     │  Static analysis of tool payloads and prompt content;
│  Supply-chain gate  │  exfiltration-probe detection; code-injection pattern
│  for all tools      │  detection; supply-chain poisoning signals
└────────┬────────────┘
         │ PASS
         ▼
┌─────────────────────┐
│  LAYER 3: ROUTING   │  Routing Validator
│                     │  Pre-call cryptographic lock binding the declared model
│  Model routing      │  to the session; post-response verification that the
│  integrity lock     │  correct model identity actually responded
└────────┬────────────┘
         │ PASS
         ▼
    ── LLM CALL ──
         │
         ▼
┌─────────────────────┐
│  LAYER 4: RESPONSE  │  Response Binder — Proprietary Sovereign Logic
│                     │  Indirect prompt-injection detection; instruction
│  Post-call LLM      │  override signals; goal hijacking; persona replacement;
│  response guard     │  exfiltration-probe detection in LLM output
└────────┬────────────┘
         │ PASS
         ▼
┌─────────────────────┐
│  LAYER 5: CHAIN     │  Chain Detector — Proprietary Sovereign Logic
│                     │  Stateful, session-scoped behavioral sequencing;
│  Cross-turn attack  │  detects Salami Slicing, credential-harvesting chains,
│  sequence analysis  │  and multi-turn permission escalation campaigns
└────────┬────────────┘
         │ PASS
         ▼
  RESPONSE DELIVERED
```

Any layer returning a `CRITICAL` block produces:

- `HTTP 403` with `blockPhase` and `blockReason` in the response body
- An immutable audit log entry
- A real-time event on the Sovereign SSE governance stream

---

## 2. Key Features

### Skill Scanner

The Skill Scanner is the mandatory execution gate for all MCP tool calls and LLM prompt content entering the enforcement pipeline. It applies **Proprietary Sovereign Logic** to perform static analysis of every tool payload and prompt, detecting:

- Code-injection and command-injection patterns
- Data exfiltration probes and exfiltration-staged payloads
- Prompt-injection attempts embedded in tool arguments
- Supply-chain poisoning signals in third-party tool definitions

**Verdicts:** `TRUSTED` | `SUSPICIOUS` | `UNTRUSTED`

An `UNTRUSTED` verdict is an immediate, fail-closed block. `SUSPICIOUS` verdicts are logged and forwarded to the Chain Detector for session-level sequence analysis.

Every MCP tool execution is gated through the Skill Scanner before the tool runs. This is not configurable — it is the enforcement contract.

---

### Intent Binder

The Intent Binder performs real-time semantic alignment verification of agent reasoning against the declared operation context. It operates as an Express middleware, evaluating every privileged request that carries a reasoning descriptor, before any route handler is invoked.

It detects:

- Jailbreak attempts: instruction-override injections, persona activation attacks
- Prompt injection targeting system-level directives
- Semantic divergence between declared reasoning and the actual operation type

**Divergence levels:** `ALIGNED` | `WARNING` | `SUSPICIOUS` | `CRITICAL`

A `CRITICAL` divergence terminates the request at the middleware layer — `HTTP 403` is returned before the route handler executes. The `blockOnCritical` enforcement posture is always active and is not a runtime option.

---

### Chain Detector

The Chain Detector maintains stateful, session-scoped behavioral records across conversation turns. Its purpose is to identify **attack sequences** — coordinated patterns that exploit the fact that individual turns appear innocuous when evaluated in isolation.

Attack patterns detected include:

- **Salami Slicing:** Incremental privilege escalation where each turn stays below the individual block threshold
- **Credential Harvesting Chains:** Progressive tool calls that collectively stage a data exfiltration
- **Permission Escalation Sequences:** Multi-turn attempts to widen scope beyond original task authorization

Every enforcement event across all five layers feeds the Chain Detector for the active session. A detected chain fires a `CHAIN_DETECTION_VIOLATION` event on the governance stream and quarantines the session.

---

### LLM Proxy Adapter

The Proxy Adapter is the fail-closed gateway for all proxied LLM calls. It is the single point through which every model invocation must pass. The Adapter orchestrates all five enforcement layers and enforces provider-aware API key resolution — **API keys are never accepted in the request body**.

**Supported providers, detected automatically from the endpoint hostname:**

| Provider | Hostname |
|---|---|
| OpenAI | `api.openai.com` |
| Anthropic | `api.anthropic.com` |
| Google Gemini | `generativelanguage.googleapis.com` |
| Generic (any OpenAI-compatible) | all other hostnames |

**API key resolution order** (server-side only):

1. `X-LLM-Api-Key` request header
2. `ANTHROPIC_API_KEY` env var (for Anthropic endpoints)
3. `GEMINI_API_KEY` env var (for Gemini endpoints)
4. `OPENAI_API_KEY` env var (for OpenAI endpoints)
5. `LLM_API_KEY` env var (generic fallback)

**SSRF protection** is unconditional: private IP ranges (RFC 1918), link-local (RFC 3927), and CGNAT addresses are always blocked. `localhost` is permitted only in non-production environments.

**Block phases** — where in the pipeline the call was terminated:

| Phase | Trigger |
|---|---|
| `SSRF` | Endpoint failed SSRF/private-range validation |
| `NEURAL` | Neural Mirror returned a high-risk score |
| `INTENT` | Intent Binder blocked (jailbreak or CRITICAL divergence) |
| `SKILL_SCAN` | Skill Scanner returned `UNTRUSTED` verdict |
| `RESPONSE` | Response Binder blocked the LLM output |
| `ROUTING` | Routing Validator detected model substitution |
| `DATA_POLICY` | FinTech FDLP blocked prompt or response (regulated-data / credential pattern policy) |

The Proxy Adapter returns the same `HTTP 403` shape for any block phase. It does not surface distinguishing error signals that would allow a caller to probe which enforcement layer was triggered.

**FinTech FDLP:** When a policy pack is active (see [§4 FinTech FDLP configuration](#fintech-fdlp-configuration-and-behavior)), prompts and assistant responses are scanned for regulated-data patterns (e.g. PAN/Luhn, US SSN, US ABA routing, bearer tokens, common API-credential shapes). Matches can **block**, **redact**, or **log only**, per pack and env overrides. A block is reported as `blockPhase: "DATA_POLICY"`.

---

### FinTech FDLP (regulated data policy)

**FDLP** (FinTech Data Loss Prevention) is an optional, pack-driven layer on the **LLM Proxy Adapter** path and on **POST /api/v1/genesis/scan** (non-LLM inspection).

- **Policy packs:** FinTech FDLP packs (`customer_support_copilot`, `internal_ops_strict`, `fraud_aml_analyst_assistant`, etc.) with per-direction actions **`block`** | **`redact`** | **`log_only`**. Activated per tenant via dashboard settings or **`KOVERA_FINTECH_POLICY_PACK`** (see [§4 FinTech FDLP configuration](#fintech-fdlp-configuration-and-behavior)).
- **Default:** FDLP is off until a pack is selected.

This is distinct from Skill Scanner (supply-chain / injection). FDLP targets **regulated or secret-bearing content** in chat transcripts.

---

### Step-Up Authorization (HITL)

Kovera implements a **Human-in-the-Loop (HITL) gate** for high-risk **delegated** actions—patterns that matter for POS, fintech, and operations workflows where a kiosk or agent must not move money or void transactions beyond its **passport ceiling** without explicit human authority.

- **402 Payment Required (authority required):** When an invoke exceeds the delegated passport threshold (e.g. a **$500 void** with a **$50** ceiling), the gateway returns **`HTTP 402`** with a **`PENDING_APPROVAL`** verdict—not a silent deny. The body includes **`approval_request_id`** and **`correlation_id`** for binding the manager step-up to that single intent.
- **Multi-role release:** A secondary party holding an elevated scoped role (e.g. **`MANAGER`** or **`ADMIN`**) must **`POST /api/v1/approvals/sign`** with their **manager passport `access_token`**. The broker verifies role and binds a **dual-signature** release to the pending row.
- **One-shot consumption:** The release is **cryptographically bound** to the pending **`approval_request_id`** and is **consumed** when the kiosk retries the original invoke with **`hitl_approval_request_id`** set. Replays without a fresh pending row **fail closed**.
- **Fail-closed:** Without a valid signed release, the delegated action **never** clears the gateway. Kovera blocks business only by default; **authorized exceptions** are explicit, audited, and non-replayable.

Try the full flow in the dashboard **Infrastructure** lab ([§4 HITL approval flow](#the-hitl-approval-flow-step-up)) or via the POS delegation API when your integration uses delegated passports.

---

### Proof-of-Action bundles

**Proof-of-Action** is the auditor-facing export that closes the enforcement loop: one JSON artifact proves **what happened** on a single action by binding:

| Layer | Role |
|---|---|
| **Primary anchor** | Aegis ledger row + **`aegis/1`** entryHash recompute (authoritative). |
| **Secondary (MCP)** | Intent receipt + approval witness JWS (authorization digest—does **not** replace entryHash). |
| **Secondary (forensic)** | MCP session receipt chain, **`session_digest`**, **`policy_drift`** (policy-context stability). |
| **Manifest** | Per-file SHA-256 **`file_integrity`** + optional **RS256** **`manifest_signature_jws`**. |

Exports are **redacted** before leaving the API (no raw prompts, bearer tokens, or tool argument bodies—digests and JWS only).

**Abandoned HITL:** If a pending approval never received a dual-signature release, export returns **`404`** with **`BUNDLE_INCOMPLETE`**—not a partial success bundle.

---

## 3. Account setup & integrations

### Dashboard access

1. **Sign up** at [app.kovera.tech](https://app.kovera.tech).
2. **Log in** with email + password (Cloudflare Turnstile on production hosts). Enable **MFA** at `/settings/mfa` when available.
3. **Enterprise SSO:** if your tenant has Okta enabled, use **Sign in with Okta** on the login page.
4. **Obtain a session JWT** for API calls — use browser devtools (session cookie) or your integration's auth flow. All **`/api/v1/genesis/*`** and **`/api/v1/governance/*`** routes require this token unless documented as public.

**Deep links:** workspaces use `https://app.kovera.tech/?tab=<workspaceId>` — e.g. `vanguard-infrastructure`, `governance`, `compliance`. See [Operator dashboard workspaces](#operator-dashboard-workspaces).

### Offline verifier (`@kovera/verify`)

This repository ships the reference implementation for **`liability-receipt/v1`**. No Kovera account required for offline digest checks.

```bash
cd packages/verify
npm install
npm run build
npm run test:liability-receipt
```

```javascript
import { verifyReceipt, computeReceiptDigest } from '@kovera/verify';

const result = verifyReceipt(receiptJson);
// { isValid: true, details: { chainLength, pillarsValidated, ... } }
```

See [`packages/verify/README.md`](./packages/verify/README.md) for the full API, browser bundle build, and open-core boundary.

### Open standard (`liability-receipt/v1`)

| Resource | Location |
|---|---|
| Normative spec | [`liability-receipt-v1.md`](./liability-receipt-v1.md) |
| JSON Schema | [`liability-receipt-v1.json`](./liability-receipt-v1.json) |
| Hosted schema URI | [kovera.tech/schemas/liability-receipt/v1](https://kovera.tech/schemas/liability-receipt/v1) |
| Category context | [`COMPETITIVE_MATRIX.md`](./COMPETITIVE_MATRIX.md) |
| Security / reporting | [`SECURITY.md`](./SECURITY.md) |

Adopters can require **`liability-receipt/v1`** in procurement and verify conformance with **`@kovera/verify`** without access to Kovera's hosted UI.

### MCP IDE plugin

```bash
npm install -g @kovera/mcp-server
kovera-mcp setup    # set backendUrl to https://api.kovera.tech
kovera-mcp --check
```

Configure in Claude Desktop — see [§4 MCP plugin](#kovera-mcp-plugin-public-mcp-plugin).

---

## 4. Usage

### Proxied LLM Calls

All production LLM calls must be routed through the Proxy Adapter. Direct calls to LLM provider APIs that bypass this endpoint are outside the enforcement perimeter.

```bash
curl -X POST https://api.kovera.tech/api/v1/genesis/proxy/call \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -H "X-LLM-Api-Key: <provider-api-key>" \
  -d '{
    "endpoint": "https://api.openai.com/v1/chat/completions",
    "model": "gpt-4o",
    "messages": [
      { "role": "system", "content": "You are a compliance auditor." },
      { "role": "user",   "content": "Summarize the attached contract." }
    ],
    "sessionId": "sess_abc123"
  }'
```

**Blocked response (`HTTP 403`):**

```json
{
  "blocked": true,
  "blockPhase": "INTENT",
  "blockReason": "Jailbreak pattern detected (score 0.95)",
  "callId": "f3a19c...",
  "model": "gpt-4o",
  "timestamp": "2026-03-26T12:00:00.000Z"
}
```

**Clean response (`HTTP 200`):**

```json
{
  "blocked": false,
  "response": {
    "id": "chatcmpl-...",
    "choices": [{ "message": { "role": "assistant", "content": "..." } }]
  },
  "neuralRiskScore": 12,
  "intentVerdict": "ALIGNED",
  "skillScanVerdict": "TRUSTED",
  "routingIntact": true,
  "responseVerdict": "CLEAN",
  "durationMs": 843
}
```

---

### FinTech FDLP configuration and behavior

1. **Choose a pack** — contact your tenant admin or set **`KOVERA_FINTECH_POLICY_PACK`** if you operate a dedicated deployment.
2. **Activate** via dashboard policy settings or environment variables. Legacy **`SENTINUL_*`** names are still honored with a deprecation warning.

| Variable | Purpose |
|---|---|
| `KOVERA_FINTECH_POLICY_PACK` | Pack id (e.g. `customer_support_copilot`, `internal_ops_strict`). Overrides YAML `default_active_pack` when set. *Legacy:* `SENTINUL_FINTECH_POLICY_PACK` |
| `KOVERA_FDLP_ENABLED` | Set to `0` / `false` to force FDLP off even if a pack is selected. *Legacy:* `SENTINUL_FDLP_ENABLED` |
| `KOVERA_FDLP_PROMPT_ACTION` | Optional override: `block` \| `redact` \| `log_only`. *Legacy:* `SENTINUL_FDLP_PROMPT_ACTION` |
| `KOVERA_FDLP_RESPONSE_ACTION` | Optional override: `block` \| `redact` \| `log_only`. *Legacy:* `SENTINUL_FDLP_RESPONSE_ACTION` |
| `KOVERA_FDLP_MAX_SCAN_CHARS` | Cap scanned characters (bounded in code). *Legacy:* `SENTINUL_FDLP_MAX_SCAN_CHARS` |
| `KOVERA_FINTECH_POLICY_PACKS_PATH` | Absolute path to an alternate YAML packs file. *Legacy:* `SENTINUL_FINTECH_POLICY_PACKS_PATH` |

With no pack active, FDLP does not run. When active, proxy statistics include FDLP-related counters in the Genesis adapter stats API.

---

### Non-LLM Genesis scan (FDLP-only)

Inspect chat-style **messages** without calling an LLM — useful for UI “preflight” or DLP checks using the same policy pack as the proxy.

```bash
curl -X POST https://api.kovera.tech/api/v1/genesis/scan \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      { "role": "user", "content": "…" }
    ],
    "sessionId": "optional-session-id"
  }'
```

**Note:** In production, `/api/v1/genesis/*` (including this route) is protected by the **lab API gate**: callers need a valid **user JWT** (or `x-internal-service-key`), unless `GENESIS_API_PUBLIC=1` (not recommended on the public internet).

---

### The HITL approval flow (step-up)

Use this handshake when a **delegated invoke** returns **`HTTP 402`** with **`verdict: "PENDING_APPROVAL"`** (e.g. POS void above passport ceiling). Integration partners using delegated passports obtain kiosk and manager **`permission_id` / `access_token`** pairs via **`POST /api/v1/identity/mint`** and **`POST /api/v1/permissions/passport`** (enterprise integrations — contact Kovera for **`INTERNAL_SERVICE_KEY`** provisioning).

**Dashboard demo:** use the **Infrastructure** tab at [app.kovera.tech](https://app.kovera.tech/?tab=vanguard-infrastructure) — no manual API calls required.

**API integration example** (requires tenant **`INTERNAL_SERVICE_KEY`** — never expose in browser code):

**1) Invoke — exceeds ceiling → capture IDs**

```bash
curl -sS -X POST "https://api.kovera.tech/api/v1/internal/vanguard/pos-delegation/invoke" \
  -H "Content-Type: application/json" \
  -H "x-internal-service-key: $INTERNAL_SERVICE_KEY" \
  -d '{
    "permission_id": "<kiosk_permission_id>",
    "access_token": "<kiosk_access_token>",
    "tool_name": "void_transaction",
    "amount": 500,
    "location_id": "LA-01"
  }'
```

**Example `402` body (shape):**

```json
{
  "verdict": "PENDING_APPROVAL",
  "code": "PENDING_APPROVAL",
  "approval_request_id": "…",
  "correlation_id": "…",
  "framing": "HITL / POS void above passport ceiling"
}
```

**2) Manager authorizes — dual-signature release**

```bash
curl -sS -X POST "https://api.kovera.tech/api/v1/approvals/sign" \
  -H "Content-Type: application/json" \
  -H "x-internal-service-key: $INTERNAL_SERVICE_KEY" \
  -d '{
    "approval_request_id": "<approval_request_id_from_402>",
    "manager_access_token": "<manager_passport_access_token>"
  }'
```

The manager passport must carry an elevated scoped role (**`MANAGER`** / **`ADMIN`**) sufficient for the pending policy.

**3) Retry invoke — one-shot binding**

```bash
curl -sS -X POST "https://api.kovera.tech/api/v1/internal/vanguard/pos-delegation/invoke" \
  -H "Content-Type: application/json" \
  -H "x-internal-service-key: $INTERNAL_SERVICE_KEY" \
  -d '{
    "permission_id": "<kiosk_permission_id>",
    "access_token": "<kiosk_access_token>",
    "tool_name": "void_transaction",
    "amount": 500,
    "location_id": "LA-01",
    "hitl_approval_request_id": "<same_approval_request_id>"
  }'
```

Expect **`HTTP 200`** with **`verdict: "PERMITTED"`** when the release matches. For a guided walkthrough, use the dashboard **Infrastructure** lab ([Getting started](#getting-started)).

---

### Tool Registration and Skill Scanning

Before deploying a tool or MCP server for agent use, submit its definition payload for a Skill Scan. Payloads that return `UNTRUSTED` are not permitted to execute in the enforcement pipeline.

```bash
curl -X POST https://api.kovera.tech/api/v1/skills/scan \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "toolName": "filesystem_read",
    "agentId": "agent-prod-001",
    "payload": "<tool definition or code payload as string>"
  }'
```

**Response:**

```json
{
  "verdict": "TRUSTED",
  "safety_score": 98,
  "static_findings": [],
  "scannedAt": "2026-03-26T12:00:00.000Z"
}
```

An `UNTRUSTED` verdict includes a `static_findings` array identifying detected signal categories. The category labels describe the class of threat detected. The detection logic itself is **Proprietary Sovereign Logic** and is intentionally not exposed — enforcement decisions are deterministic and fully auditable; the detection mechanism is not enumerable.

---

### Public sovereignty verification (receipt portal)

Operators and auditors verify **Kovera sovereignty receipts** and **Proof-of-Action bundles** at **[verify.kovera.tech](https://verify.kovera.tech)**.

| Input | Behavior |
|---|---|
| **`liability-receipt/v1`** JSON | Tier A — in-browser digest verify via **`@kovera/verify`** (also runnable from [`packages/verify/`](./packages/verify/)) |
| **Sovereignty receipt JSON** | Server-assisted checks via **`POST /api/v1/public/verify-receipt`** (HMAC / seals / optional Merkle). |
| **64-character hex `entryHash`** | Merkle continuation proof against the public anchor path. |
| **Proof-of-Action bundle JSON** | **Client-side only:** RS256 manifest JWS + **`file_integrity`** SHA-256. Public key from bundle metadata or **`GET /api/v1/public/bundle-verify-key`**. |

**Shared receipt links:** **`POST /api/v1/governance/mint-public-share-receipt`** (authenticated dashboard) mints a redacted JSON payload loaded by **`?receipt_id=`** on the verify portal.

**Guardian witness demo:** open [verify.kovera.tech](https://verify.kovera.tech) → **Independent Guardian witness demo**, or **`GET /api/v1/public/evidence/guardian-demo`**.

---

### Proof-of-Action export and verification loop

**Who may export:** dashboard users with **governance viewer** entitlement (Prisma **`governanceRole`** `OWNER` / `SECURITY_ADMIN` / `AUDITOR`, or legacy **`ADMIN`** / `GOVERNANCE_OFFICER` / `READ_ONLY`). This uses the **normal session JWT**—not **`INTERNAL_SERVICE_KEY`**.

**1) Identify the anchor** (one of):

- `entryHash` — 64-char hex ledger anchor
- `correlationId` — HITL correlation from **402** body
- `approvalRequestId` — `approval_request_id` from **402** (common after Infrastructure POS demo)

**2) Export (authenticated)**

```bash
curl -sS -X POST "https://api.kovera.tech/api/v1/governance/proof-bundle" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <dashboard-jwt>" \
  -d '{"approvalRequestId":"<from-402>"}'
```

**Auditor one-click report** (bundle + executive summary + `session_digest`):

```bash
curl -sS -X POST "https://api.kovera.tech/api/v1/governance/auditor-export" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <dashboard-jwt>" \
  -d '{"approvalRequestId":"<from-402>"}'
```

Optional body: `"mintPortalShare": false` to skip public share-receipt minting. Do not paste real JWTs or bundle JSON into tickets or public repos.

**3) Verify (zero-trust)**

1. Paste the full `{ "ok": true, "bundle": { ... } }` or bare bundle object into **`verify.kovera.tech`**.
2. Click **Validate** — **Verification dashboard** shows primary Aegis anchor vs MCP / forensic drill-down.
3. Read the **Enterprise Verification Guide** on [verify.kovera.tech](https://verify.kovera.tech/verification-guide-enterprise.html) for **Policy Drift** interpretation (also shipped as **`VERIFICATION_GUIDE_ENTERPRISE.md`** inside exported bundles).

**Policy drift:** `forensic/session_chain.json` → `policy_drift.policy_context_stable === false` means `policy_version_hash` changed between hops—correlate with change management, not automatic fraud.

---

### Operator dashboard workspaces

After login at [app.kovera.tech](https://app.kovera.tech), workspaces are addressable as **`https://app.kovera.tech/?tab=<workspaceId>`**.

| `tab` | How to use |
|---|---|
| `scan` / `history` | Upload or paste code for compliance scan; review prior runs. |
| `governance` | Sovereignty Protocol — policy strips, timeline, receipt actions. |
| `compliance` / `security` | Compliance metrics and audit exports (governance viewer; Okta SSO for CSV/JSON when enforced). |
| `kovera-vfp` / `verification-vault` | Simulate receipts, Trust Links, Evidence of Care wizard. |
| `evidence-locker` | Batch verify / seal evidence artefacts. |
| `command-center` / `interception-center` | Ledger summary, HITL queue, interception telemetry. |
| `escalations` / `aegis` / `precedents` / `sovereign` / `policy-simulator` | Tier-gated operations surfaces. |
| **`vanguard-infrastructure`** | **Start here:** POS + HITL demo → **402** → manager sign → **200 PERMITTED** → export Proof-of-Action → [verify.kovera.tech](https://verify.kovera.tech). |
| `vanguard-integrations` / `vanguard-consequences` | Integration previews and consequence modeling. |

**Infrastructure export:** buttons show **Generating verifiable proof…** while the API assembles artifacts; the verify portal opens via a one-shot handoff (`?from=infrastructure_demo`).

---

### Kovera MCP plugin

Package **`@kovera/mcp-server`** runs standalone against your Kovera tenant API. Local credentials default to **`~/.config/sentinul/`** unless **`KOVERA_MCP_DATA_DIR`** is set.

**Install and configure**

```bash
npm install -g @kovera/mcp-server
kovera-mcp setup    # writes config.json — set backendUrl to https://api.kovera.tech
kovera-mcp --check  # health check against your tenant
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "kovera": {
      "command": "kovera-mcp"
    }
  }
}
```

Use an absolute path to **`kovera-mcp`** if global npm `bin` is not on Claude’s PATH.

**MCP tools (stdio server)**

| Tool | Purpose |
|---|---|
| **`auditor_scan`** | Code compliance scan (local heuristics + authenticated backend when logged in). |
| **`auditor_fix_vulnerability`** | AI-assisted remediation (Pro; backend). |
| **`auditor_generate_report`** | Signed PDF reports (Pro). |
| **`auditor_analyze_entropy`** | Hardcoded secret / high-entropy detection. |
| **`auditor_login`** | Browser-friendly auth against configured API. |

**Environment / config (non-secret names only)**

| Variable | Purpose |
|---|---|
| **`API_BASE`** | Backend root or `.../api` (set by `kovera-mcp setup` or shell). |
| **`KOVERA_MCP_DATA_DIR`** | Relocate local credentials + file-backed ledger. |
| **`KOVERA_MCP_DEBUG`** | Verbose logging when `1`. |
| **`KOVERA_MCP_BRIDGE_KEY`** / **`INTERNAL_MCP_SECRET`** | Bridge to hosted **`/api/mcp/sse`** (server-side secret—never commit). |
| **`KOVERA_API_KEY`** / legacy **`SENTINUL_API_KEY`** | User API key after **`auditor_login`**. |

**Relationship to Proof-of-Action:** MCP tool invokes that flow through the cloud control plane produce ledger rows that appear in bundles exported via **`POST /api/v1/governance/proof-bundle`**.

---

### Live Telemetry Dashboard

The Sovereign Dashboard provides real-time visibility into all enforcement activity across every layer.

**Access:** [app.kovera.tech](https://app.kovera.tech) (primary dashboard) · [kovera.tech](https://kovera.tech) (marketing)

| Panel | Data Source | Purpose |
|---|---|---|
| Global Health Score (GHS) | `GET /api/v1/health/global` | Weighted score from Prisma `AuditLog` + signed precedents (public; no auth) |
| Live Pulse (REST) | `GET /api/v1/health/pulse` | Last 10 platform `AuditLog` rows with precedent joins (public; no auth) |
| Dashboard strip + Aegis timeline | `GET /api/v1/genesis/*` + `GET /api/aegis/ledger` | Live Genesis stats and hash-chained Aegis ledger (**JWT required**; `/api/v1/*` is Aegis-mediated) |
| Proxy Call Log | `GET /api/v1/genesis/proxy/calls` | Per-call inspection results and block phases |
| Proxy Stats | `GET /api/v1/genesis/proxy/stats` | Block rate, intent flag rate, routing violations |
| Governance health | `GET /api/v1/genesis/governance-health` | Recursive auditor autonomy / governance score |
| Response Alerts | `GET /api/v1/genesis/response-scan/alerts` | QUARANTINE and CRITICAL Response Binder findings |
| Chain Sequences | `GET /api/v1/genesis/chain/sequences` | Detected multi-turn attack sequences |
| Routing Anomalies | `GET /api/v1/genesis/routing/anomalies` | Model substitution violations and lock expirations |
| **Live Threat Feed** | `GET /api/v1/genesis/threats/stream` (SSE) | High-signal security events to the browser (**JWT** via `?access_token=` or session cookie; see [Live Threat Feed (SSE)](#live-threat-feed-sse)) |

**Live Pulse (REST) example:**

```bash
curl -sS "https://api.kovera.tech/api/v1/health/pulse"
```

**MCP / governance SSE:** real-time tool streams use `GET /api/mcp/sse` (MCP auth), not a separate `/api/v1/genesis/pulse` endpoint.

High-signal governance event types (ledger / exports) include:

- `PROXY_CALL_BLOCKED` (via proxy adapter + audit pipeline)
- `CHAIN_DETECTION_VIOLATION`
- `RESPONSE_BINDER_VIOLATION`
- `ROUTING_INTEGRITY_VIOLATION`
- `ROUTE_BLOCKED_BY_PERMISSION` / Aegis mediation denials
- `AGENT_QUARANTINED` (session quarantine)

---

### Web dashboard, MFA, and settings

The **Kovera dashboard** at [app.kovera.tech](https://app.kovera.tech) is the operator UI for login, Genesis telemetry, governance exports, and account controls.

| Area | How to use |
|---|---|
| **Login / signup** | Email + password at [app.kovera.tech](https://app.kovera.tech). Cloudflare Turnstile on production hosts. |
| **MFA (TOTP)** | Enable at **`/settings/mfa`** after login. |
| **Okta SSO** | **Sign in with Okta** when your tenant has SSO configured. |
| **Privacy & data** | **`/settings/privacy`** — GDPR/CCPA deletion scheduling. |
| **SIEM / telemetry** | **`/settings/siem`** — configure enterprise webhook forwarding (when entitled). |
| **Skill inventory** | **`/settings/skills`** — SBOM-style inventory and revoke trust by content hash. |
| **Share to Verify** | Receipt cards → **`POST /api/v1/governance/mint-public-share-receipt`** → link with **`?receipt_id=`** on verify portal. |
| **Proof-of-Action** | Infrastructure tab or **`POST /api/v1/governance/proof-bundle`** / **`auditor-export`** (governance viewer required). |

---

### Live Threat Feed (SSE)

The dashboard subscribes to **Server-Sent Events** for high-signal threat notifications (e.g. probes and enforcement-adjacent traffic after quiet-path filters).

- **Endpoint:** `GET /api/v1/genesis/threats/stream`
- **Auth:** Browsers cannot set `Authorization` on `EventSource`. The client passes the JWT as a query parameter: **`?access_token=<token>`** (the stream route also accepts `Authorization: Bearer` or the session cookie when cookie parsing applies).
- **Production gate:** This path is exempt from the generic “lab API” JWT check so the dedicated stream middleware can parse `access_token`; you still need a **valid JWT** from the same API’s `JWT_SECRET`.

**Manual check (replace token):**

```bash
curl -sS -N -H "Accept: text/event-stream" \
  "https://api.kovera.tech/api/v1/genesis/threats/stream?access_token=<JWT>"
```

Event stream payloads include a `CONNECTED` heartbeat and `THREAT_SIGNAL` JSON objects in the dashboard live feed.

---

## 5. API Reference

### Proxy Adapter

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/genesis/proxy/call` | Execute a guarded LLM call through all enforcement layers |
| `GET` | `/api/v1/genesis/proxy/stats` | Aggregate call statistics: block rate, flags, violations |
| `GET` | `/api/v1/genesis/proxy/calls` | Recent call log, newest-first (`?limit=&offset=`) |
| `POST` | `/api/v1/genesis/scan` | Non-LLM FDLP inspection of a `messages` array (same packs as proxy) |
| `GET` | `/api/v1/genesis/threats/stream` | SSE live threat feed; use `?access_token=` for browsers |

### Response Binder

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/genesis/response-scan` | Scan an LLM response for injection and hijacking signals |
| `GET` | `/api/v1/genesis/response-scan/stats` | Verdict breakdown and block rate |
| `GET` | `/api/v1/genesis/response-scan/alerts` | Recent QUARANTINE and CRITICAL findings |

### Routing Validator

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/genesis/routing/lock` | Issue a pre-call cryptographic model routing lock |
| `POST` | `/api/v1/genesis/routing/verify` | Verify post-response model identity against the lock |
| `GET` | `/api/v1/genesis/routing/stats` | Verification statistics and violation count |
| `GET` | `/api/v1/genesis/routing/anomalies` | Recent routing violations |

### Chain Detector

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/genesis/chain/event` | Record a behavioral event for a session |
| `GET` | `/api/v1/genesis/chain/sequences` | Detected chain attack sequences, newest-first |
| `GET` | `/api/v1/genesis/chain/stats` | Aggregate chain detection statistics |

### Identity and Permissions

| Method | Path | Access | Description |
|---|---|---|---|
| `POST` | `/api/v1/identity/mint` | Internal | Mint a task-scoped identity token |
| `POST` | `/api/v1/identity/verify` | Internal | Verify an identity token |
| `POST` | `/api/v1/permissions/request` | Internal | Request JIT permission for a resource |
| `POST` | `/api/v1/permissions/passport` | Internal | Issue a **delegated passport** (scoped role, constraints, e.g. `maxVoidAmount`) |
| `POST` | `/api/v1/permissions/revoke` | Internal | Snap-shut: immediately revoke a permission |
| `GET` | `/api/v1/permissions/active` | Internal | List active permissions |
| `POST` | `/api/v1/approvals/sign` | Internal | **HITL:** manager signs a pending `approval_request_id` (body: `manager_access_token`) |
| `POST` | `/api/v1/internal/vanguard/pos-delegation/invoke` | Internal | Lab **POS delegation** invoke; returns **402** + `approval_request_id` when step-up required |

> **Internal routes** require the `X-Internal-Service-Key` header ( **`INTERNAL_SERVICE_KEY`** ) and are not intended for browser exposure. The key is validated with a constant-time comparison to prevent timing-based enumeration. **`INTERNAL_SERVICE_KEY`** is **required** at server startup alongside `JWT_SECRET` and `ENCRYPTION_KEY`—it is the control-plane credential for mint, passport, approvals, and `/api/v1/internal/*` gates.

### Governance and Proof-of-Action

Mount prefix: **`/api/v1/governance`**. Requires **authenticated** session + **`requireGovernanceViewer`** unless noted.

| Method | Path | Body / query | Description |
|---|---|---|---|
| `POST` | `/proof-bundle` | `entryHash` **or** `correlationId` **or** `approvalRequestId`; optional `mintPortalShare` | Full Proof-of-Action JSON (`manifest`, `artifacts`, `artifact_bodies`, `proof_chain`). |
| `POST` | `/auditor-export` | Same | Bundle + **`auditor_report`** (executive summary, `session_digest`). |
| `POST` | `/verify-entry` | Ledger entry verification for dashboard drawer. |
| `POST` | `/sovereignty-receipt` | Issue/fetch sovereignty receipt JSON. |
| `POST` | `/mint-public-share-receipt` | `{ entryHash }` — redacted public share for verify portal (auth; not full bundle). |
| `GET` | `/share-receipt-status` | Sandbox share quota status. |
| `GET` | `/pending-approvals/queue` | Active HITL queue. |
| `POST` | `/pending-approvals/resolve` | Resolve pending approval (approver role). |
| `GET` | `/evidence-locker` | Evidence locker index. |
| `POST` | `/evidence-locker/verify-batch` | Batch integrity verify. |
| `POST` | `/evidence-locker/seal-now` | Seal artefacts. |
| `GET` | `/export-report` | PDF governance export. |
| `GET` | `/compliance-bundle.pdf` | Compliance PDF bundle. |
| `GET` | `/receipt` | Query sovereignty receipt by anchor metadata. |
| `GET` | `/verify/:entryHash` | Authenticated ledger verify (same data family as public demo verify). |

Errors: **`BUNDLE_INCOMPLETE`** (404) when HITL pending never received crypto release; **`HITL_ANCHOR_NOT_RESOLVED`** when correlators cannot find primary anchor.

Manifest signing uses deployment key material (public half available via **`GET /api/v1/public/bundle-verify-key`** only — never commit private PEMs).

### Open Evidence API (public)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/public/evidence/spec` | Machine-readable Open Evidence index |
| `GET` | `/api/v1/public/evidence/entry/:entryHash` | Redacted ledger row + verify hints |
| `GET` | `/api/v1/public/evidence/witness/:entryHash` | Witness cosign verification |
| `GET` | `/api/v1/public/evidence/guardian-demo` | Guardian witness demo |

### Public verification (unauthenticated)

Rate-limited public routes on **`https://api.kovera.tech`**:

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/public/verify-receipt` | Sovereignty receipt HMAC / seal verification; optional Merkle modes. |
| `GET` | `/api/v1/public/bundle-verify-key` | RS256 **public** SPKI PEM for browser manifest verification. |
| `GET` | `/api/v1/public/truth?entryHash=` | Public lineage snapshot for ledger anchor. |
| `GET` | `/api/v1/public/shared-receipt/:id` | Load redacted share payload for **`?receipt_id=`** portal links. |
| `GET` | `/api/v1/public/demo/verify/:entryHash` | Demo entry lookup. |
| `POST` | `/api/v1/public/scan-skill` | Teaser scan (heavily redacted; lead-gen). |

| `GET` | `/api/v1/public/liability-receipt/:receiptId` | Fetch **`liability-receipt/v1`** by id |
| `GET` | `/api/v1/public/apor/rgp-schema` | Agent Protocol of Record reference schema |
| `POST` | `/api/v1/public/intent-alignment/evaluate` | Structural Proof-of-Intent scoring (anonymous playground) |

**Zero-trust rule:** Proof-of-Action **manifest RS256** and **`file_integrity`** are verified in the browser at **[verify.kovera.tech](https://verify.kovera.tech)**. Offline **`liability-receipt/v1`** checks use **[`@kovera/verify`](./packages/verify/)** in this repository.

---

## 6. Security Mandate

### Zero-Trust by Architecture

Kovera operates on the principle that no agent, tool, or LLM provider is trusted by default. Trust is not established at connection time — it is re-evaluated at every layer, on every call.

The enforcement pipeline is:

**Fail-closed.** A system error in an enforcement component does not cause the call to proceed unexamined. Non-fatal bridge errors (e.g., neural mirror initialization failure) are logged at ERROR severity; the call continues with a degraded-mode record. The absence of a verdict is itself a recorded state, not a silent pass.

**Deterministic.** For any given input, the enforcement decision is identical on every invocation. There is no probabilistic acceptance threshold that can be gamed with repeated requests.

**Non-bypassable.** There is no runtime flag, request header, or body parameter that disables any enforcement layer. Security-relevant identity fields (`agentId`, cryptographic lock tokens) are never accepted from the request body — they are always derived server-side from `req.user.id` or authenticated session context.

### Immutable accountability (Merkle-chain audit)

Every enforcement decision is bound into the **Aegis audit ledger** using **per-entry hashing and signatures** and **Merkle-style chaining** (e.g. Vanguard / lab simulations expose roots for verification). That yields a **cryptographically verifiable history** in which the **agent request**, the **Kovera verdict**, and—when step-up applies—the **manager HITL approval** are linked in the same tamper-evident stream. **Altering a single log entry invalidates the chain** for downstream verification, which supports **forensic integrity** and regulatory-style audit narratives beyond a plain SQL append log.

**Proof-of-Action bundles** package that narrative for external auditors: primary **`aegis/1`** anchor, optional MCP witness + forensic session chain, and a signed manifest—verified offline or on **`verify.kovera.tech`** without exposing raw agent prompts.

### Sovereign Workflow

The Sovereign Workflow is the operational contract every deployment must honor:

1. No LLM call reaches a provider without passing all pre-call enforcement layers.
2. No LLM response reaches an agent without passing the Response Binder.
3. Every enforcement event is recorded, immutable, and available for audit in real-time.
4. An agent session accumulates behavioral state across turns. A pattern of individually sub-threshold events will collectively trigger Chain Detection and session quarantine.
5. API keys are secrets, not parameters. They are resolved server-side from environment variables. A caller cannot route a call to a provider using a key it controls via the request body.

### Protecting the Proprietary Moat

The detection logic within the Skill Scanner, Intent Binder, Chain Detector, and Response Binder constitutes **Proprietary Sovereign Logic**. The enforcement contracts — verdicts, block phases, audit trails, and SSE events — are fully observable. The detection logic is not.

This is intentional. An adversary who can enumerate detection thresholds can optimize attacks to stay below them. Black-box enforcement is the appropriate posture for a security-critical control plane. Observable inputs and outputs; opaque decision internals.

---

## 7. Configuration

### For dashboard users

No configuration required beyond your account at [app.kovera.tech](https://app.kovera.tech). Enable MFA at `/settings/mfa`. Governance exports require a **governance viewer** role (`OWNER`, `SECURITY_ADMIN`, `AUDITOR`, or legacy Admin / Governance Officer / Read Only).

### For API integrators

| What you need | How to get it |
|---|---|
| **Session JWT** | Log in to the dashboard; use session cookie or bearer token for `Authorization: Bearer <jwt>` |
| **Provider LLM key** | Pass as **`X-LLM-Api-Key`** header on Genesis proxy calls — never in JSON body |
| **Delegated passports** | Enterprise integration — contact Kovera for identity mint + passport APIs |
| **`INTERNAL_SERVICE_KEY`** | Enterprise control-plane integrations only — never embed in browser or mobile apps |

### FinTech FDLP (tenant operators)

Activate a named pack via dashboard or environment:

| Variable | Purpose |
|---|---|
| `KOVERA_FINTECH_POLICY_PACK` | Pack id (e.g. `customer_support_copilot`, `internal_ops_strict`) |
| `KOVERA_FDLP_ENABLED` | Set to `0` / `false` to force FDLP off |
| `KOVERA_FDLP_PROMPT_ACTION` | Override: `block` \| `redact` \| `log_only` |
| `KOVERA_FDLP_RESPONSE_ACTION` | Override: `block` \| `redact` \| `log_only` |

Legacy **`SENTINUL_*`** names are still honored with a deprecation warning.

### Kovera vs. legacy environment variables

Hosted SaaS tenants typically do not set these directly. Dedicated deployments prefer **`KOVERA_*`** over legacy **`SENTINUL_*`** names:

| Kovera (preferred) | Legacy (still honored) |
|---|---|
| `KOVERA_TIER` | `SENTINUL_TIER` |
| `KOVERA_API_KEY` | `SENTINUL_API_KEY` |
| `KOVERA_PASSPORT_SECRET` | `SENTINUL_PASSPORT_SECRET` |
| `KOVERA_FDLP_*` / `KOVERA_FINTECH_*` | `SENTINUL_FDLP_*` / `SENTINUL_FINTECH_*` |
| `KOVERA_BYOK_ID` | `SENTINUL_BYOK_ID` |

### Dedicated deployment secrets

Enterprise operators running a private Kovera instance require at minimum:

| Variable | Purpose |
|---|---|
| `JWT_SECRET` (64+ chars) | Signs session and identity JWTs |
| `INTERNAL_SERVICE_KEY` (32+ chars) | Guards internal control-plane routes |
| `ENCRYPTION_KEY` (32+ chars) | MFA and at-rest encryption |

Generate secure values:

```bash
node -e "const c=require('crypto'); console.log(c.randomBytes(64).toString('hex'));"
```

Optional: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `SIEM_ENDPOINT_URL`, `KOVERA_MERGE_ATTESTATION_*` for manifest signing. Contact **contact@kovera.tech** for dedicated deployment guides.

---

## 8. BYOK (Bring Your Own Key)

Enterprise operators on **dedicated deployments** can supply Customer-Managed Keys (CMK) for at-rest encryption of audit records. Set **`KOVERA_BYOK_ID`** (or legacy **`SENTINUL_BYOK_ID`**) or configure **`.sentinulrc`** on the server:

```yaml
vault:
  provider: local        # local | aws-kms | gcp-kms
  key_id: "cmk-prod-001"
```

The vault bridge fails loudly in production if CMK initialization fails — it does not silently fall back.

---

## Related documents in this repository

| Document | Purpose |
|---|---|
| [`liability-receipt-v1.md`](./liability-receipt-v1.md) | Normative **`liability-receipt/v1`** standard |
| [`packages/verify/README.md`](./packages/verify/README.md) | Offline verifier API |
| [`COMPETITIVE_MATRIX.md`](./COMPETITIVE_MATRIX.md) | Category positioning |
| [`SECURITY.md`](./SECURITY.md) | Vulnerability reporting |

**Report security issues privately** — see [SECURITY.md](./SECURITY.md). **Contact:** [contact@kovera.tech](mailto:contact@kovera.tech)

---

*Architected and Hardened in Los Angeles, California.*
*Beyond Guardrails. Real-Time Sovereignty.*
*Dedicated to the engineering spirit of Edward Vrona & the Hubble team.*
