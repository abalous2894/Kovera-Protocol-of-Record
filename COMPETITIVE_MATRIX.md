# Kovera Design Philosophy & Architecture Comparison

The landscape of autonomous agent governance is rapidly shifting toward cryptographic accountability. However, existing frameworks generally fall into two categories: passive post-hoc event streaming or disconnected identity credentials. 

The Kovera **Verified Autonomous Session (VAS)** framework and the accompanying `liability-receipt/v1` specification were designed specifically to bridge the execution-path gap required for institutional finance and enterprise compliance.

---

## Structural Comparison Matrix

| Framework / Specification | Structural Layer | Session-Bound Core | Enforcement Plane | Built-In HITL State | Primary Enterprise Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Kovera (`liability-receipt/v1`)** | **Inline Runtime Enforcement** | **Yes (Atomic Session)** | **Active Gateway Intercept** | **Yes (Deterministic 402/Release)** | **Enterprise Liability & Diligence Audit** |
| **AIGP** (AI Governance Proof) | Post-Action Telemetry | No (Discrete Events) | Passive Logging | No | Governance Analytics |
| **Agent Receipts** (W3C VC Type) | Decentralized Identity | No (Decoupled Attestation) | None (Verification Only) | No | Sovereign Attribute Verification |
| **Capsule Protocol** | Application SDK | Yes (Multi-section Record) | None (Requires SDK Integration) | No | Open-Source Developer Logging |
| **Project AIR** | Forensic Archival | No (Incident Capsules) | Post-Execution Tracing | No | Incident Response & Forensics |

---

## Why Alternative Approaches Fall Short in Enterprise Workflows

### 1. Loose Event Streams (e.g., AIGP) Are Insufficient for Enforcement
Passive logging architectures capture telemetry *after* an action has already occurred. For low-impact analytics, this is acceptable. For high-risk financial transactions—such as an automated payment void or privileged database configuration—passive streams provide zero protection against execution-path failures. Kovera mandates an inline intercept layer that evaluates policy *before* any external side effects are permitted to execute.

### 2. Decoupled Credentials (e.g., W3C Agent Receipts) Lack Session Context
Verifiable Credentials (VCs) excel at confirming static identities or isolated cryptographic assertions. However, they lack the holistic session context required by financial auditors. A standard bank audit does not just ask *who* the agent is; it requires an atomic, immutable package linking the exact incoming trigger, the specific policy boundaries enforced at that millisecond, the human-in-the-loop (HITL) authorization token, and the ultimate cryptographic ledger anchor. Disconnected credential graphs cannot guarantee this structural atomicity.

### 3. Pure Forensic Tooling (e.g., Project AIR) Solves for the Blast Radius, Not Prevention
Forensic-first tracking assumes system compromise or failure and optimizes for post-incident investigation. While valuable for security teams, it does not solve the compliance core: preventing unauthorized liability generation in real time. Kovera’s `liability-receipt/v1` acts as a preventative diligence artifact, guaranteeing that if an action is recorded on the ledger, it successfully survived the entire runtime policy gauntlet.
