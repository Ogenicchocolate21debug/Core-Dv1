# OGENIC HARNESS Tools Skill — AUSTRA v6

## Purpose
Expose OGENIC CORE HARNESS capabilities through one discoverable contract instead of requiring agents to memorize individual tools.

## Bootstrap
1. Load `tools/capabilities.json`.
2. Resolve shortcuts/aliases to capabilities.
3. Discover the runtime binding available in the current chat/agent/environment.
4. Enforce permission class: `READ → WRITE → EXECUTE → DANGEROUS`.
5. Prefer deterministic execution and smallest reversible changes.
6. Verify outputs before reporting success.
7. Missing tool/binding returns `CAPABILITY_REQUIRED` or `UNBOUND_CAPABILITY`; continue independent work.

## Core Routing
`Intent → Capability → Plane → Runtime Binding → Execute → Verify → Persist → Report`

## X — Execution Fabric
Use for code/files/repos/processes/workflows/deployments.
Examples: `code_search`, `read_file`, `write_file`, `repo_map`, `build`, `test`, `workflow_run`, `deploy_preview`, `verify_runtime`.

## Y — Identity & Session Continuity
Use for supported identity/session/capability health. Do not expose raw secrets, cookies, passwords or private keys.
Examples: `identity_health`, `session_health`, `capability_resolve`, `credential_reference`, `reauth_required`.

## Z — Convergence Fabric
Use for desired-vs-actual reconciliation.
Examples: `discover_state`, `snapshot`, `hash`, `diff`, `reconcile`, `rollback`, `audit`.

## CN Canonical Workflow
Source: Google Drive `Main Photo`.
Strict sequence: `A1 → A2 → A3 → A4 → A5`.
Pipeline: `SCAN → INDEX → HASH → DIFF → MAP → BUILD → VALIDATE → CF PREVIEW → VERIFY → REPORT`.
Rules: unchanged=SKIP; changed/new=process only affected item; missing/ambiguous=REPORT; deleted source is not recreated automatically; production requires explicit approval.

## Normal Chat Operate Mode
Normal Chat is the preferred Operator Console whenever connected capabilities can complete the work. Do not force Work mode unnecessarily. Persist verified operating knowledge (decisions, paths, contracts, outcomes, recovery recipes), not hidden model reasoning.

## Shortcuts
- `/OG.help`
- `/OG.status`
- `/OG.tools`
- `/OG.context`
- `/OG.sync`
- `/OG.audit`
- `/X.tools`
- `/Y.health`
- `/Z.reconcile`
- `/CN.scan`
- `/CN.diff`
- `/CN.build`
- `/CN.preview`
- `/CN.verify`
- `/CN.promote` — production promotion only after explicit approval and successful preview/verification gates

## Agent Handoff
Every agent should receive this skill plus `tools/capabilities.json`. The agent must discover actual tool access at runtime rather than assuming connectors are present.
