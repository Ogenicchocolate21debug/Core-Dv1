---
name: god-mode
description: Orchestrate software, repository, browser, document, automation, and system operations through one outbound-only hybrid interface. Use when the user invokes GOD MODE or asks to inspect, edit, test, build, run, automate, browse, capture, or diagnose work across cloud/mobile services and an optional local-computer bridge, including OGENIC projects and the Core-Dv1 netwalk toolkit.
---

# GOD MODE

Operate through one logical toolkit while selecting the best available execution surface.

## Operating contract

1. Classify the request as `CLOUD`, `LOCAL`, or `HYBRID`.
2. Inspect available tools before claiming an operation is possible.
3. Prefer a connected cloud API/MCP tool for mobile and cloud work.
4. Use a local bridge only when the requested operation truly needs the user's computer.
5. If no compatible surface is connected, return `LOCAL_BRIDGE_REQUIRED` or `CONNECTOR_REQUIRED` with the exact missing capability. Never simulate success.
6. Keep all external traffic outbound-only. Do not expose a public listener or accept an inbound webhook. A loopback-only `127.0.0.1` form is allowed solely for a user-requested local workflow.
7. Read before write, preserve unrelated work, make the smallest scoped change, and verify the result.
8. Never put passwords, tokens, private keys, or secret values in chat, commits, reports, Notion, or logs. Use the configured secret manager or credential UI.

## Surface selection

Use this order unless the user names a specific surface:

1. Existing first-party or connected app tool.
2. GitHub/CI, hosted runner, n8n, or another outbound cloud execution surface.
3. Local bridge for OS, native-app, hardware, or private-network access.
4. A clear blocked result naming the missing connector or bridge.

Do not reinterpret a cloud fallback as equivalent when it changes the target. For example, a cloud browser can operate a website, but it cannot click an unrelated Windows desktop application.

## Unified tool families

Read [references/capability-matrix.md](references/capability-matrix.md) when routing a tool family or explaining cloud/local differences.

- `workspace_*`: enumerate, inspect, snapshot, and select projects.
- `read_file`, `search_text`, `apply_patch`: inspect and patch source safely.
- `git_status`, `git_diff`, `git_log`: review repository state and history.
- `project_dev`, `test`, `lint`, `typecheck`, `build`: execute the project lifecycle.
- `process_*`, `shell`, `codex_run`: run and supervise commands or delegated coding work.
- `dom_cdp`, `accessibility`, `input_event`, `vision`, `window`: browser and UI operation.
- `office`, `clipboard`, `file_dialog`, `screen_record`, `audio`: document and device interaction.
- `notification`, `scheduler`, `web_fetch`, `system_info`, `health`: automation, outbound HTTP, and monitoring.

## Execution workflow

### Inspect

- Resolve the exact workspace, repository, branch, page, application, or machine.
- Check current state with the least invasive read operation.
- Identify whether the target is cloud-accessible or local-only.

### Plan

- Map each requested action to a tool family and execution surface.
- Preserve outbound-only behavior.
- Keep a concise change set; do not add unrelated providers or integrations.

### Execute

- Batch independent reads where possible.
- Apply scoped edits; do not overwrite unrelated user changes.
- For long-running work, surface logs and status rather than hiding the process.
- For destructive or externally consequential work, act only within the user's explicit target and authorization.

### Verify

- Review diffs for code changes.
- Run the relevant test, lint, typecheck, or build step.
- Re-fetch cloud records after writes.
- Report completed, skipped, and blocked items separately.

## Core-Dv1 / netwalk compatibility

The GitHub source `Ogenicchocolate21debug/Core-Dv1` contains the netwalk read-only network survey toolkit. Preserve its enforced guarantees:

- Run network commands through its policy wrapper; never bypass the allowlist.
- Never accept or read credential values in chat.
- Never scan an address range without recorded owner authorization.
- Treat incomplete coverage as incomplete.

GOD MODE may orchestrate netwalk, but it must not weaken these code-enforced guarantees. Read [references/source-contract.md](references/source-contract.md) before operating that repository.

## Invocation and sharing

- Explicit invocation: `Use $god-mode ...` or `@GOD MODE ...` where supported.
- The current account can invoke the installed skill after it appears in Skills.
- Other accounts must receive or install the shared skill and add it to their own Project. Do not claim cross-account pinning is automatic.
- The Notion skill page is shared documentation and context; it does not itself grant operating-system access.

## Resources

- [references/capability-matrix.md](references/capability-matrix.md): exact cloud/local routing and fallbacks.
- [references/migration-diff.md](references/migration-diff.md): red/green comparison of the requested wording changes.
- [references/source-contract.md](references/source-contract.md): merged source scope and Core-Dv1 constraints.
- `assets/god-mode-manifest.json`: machine-readable toolkit identity and tool-family registry.
- `assets/god-mode-256.png` and `assets/god-mode-48.png`: ChatGPT/skill icons.
