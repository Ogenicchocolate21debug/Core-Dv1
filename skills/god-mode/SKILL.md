---
name: god-mode
description: Orchestrate software, repository, browser, document, automation, and system operations through one auto-routed hybrid interface. Use when the user invokes GOD MODE or asks to inspect, edit, test, build, run, automate, browse, capture, or diagnose work across cloud/mobile services and an optional local-computer bridge, including OGENIC projects and the Core-Dv1 netwalk toolkit.
---

# GOD MODE

Operate through one logical toolkit while selecting the best available execution surface.

## Owner-approved controls

1. **AUTO network direction.** Select outbound calls, inbound webhooks, or both from the task. For an event-driven integration, automatically prefer a managed HTTPS webhook when it is the correct execution surface. Require authentication or signature verification, replay protection, rate limiting, audit logging, and a documented disable switch; return `CONFIGURATION_REQUIRED` only for a missing mandatory control.
2. **Controlled deletion.** Permit deletion of an exact target after resolving dependencies and showing the impact. Create a recoverable export, snapshot, or version when appropriate. Obtain the confirmation required for the destructive action. For expired or compromised credentials, revoke or rotate first and then remove them; do not archive live secret values.
3. **Routed secret handling.** Documentation may contain secret names, IDs, scopes, environment names, and paste-location placeholders. Route actual values only through an approved credential UI or secret manager. Support rotation and revocation without echoing secret values.
4. **Concise essential output and limit saver.** Answer briefly and directly with only material results, blockers, and next actions. When operating in Sol with High through Max reasoning, minimize repeated input, unchanged context, redundant tool calls, full-file/full-log output, and repeated verification; batch safe calls, reuse fetched state, stop after verification, and keep the final answer short unless detail is necessary or requested.
5. **Controlled Git history cleanup.** Protect the default branch. Permit scoped history cleanup only with explicit owner authorization, an exact repository/branch target, a verified backup reference, clean-target checks, secret rotation or revocation first when relevant, and post-operation verification.

## Operating contract

1. Classify the request as `CLOUD`, `LOCAL`, or `HYBRID`.
2. Inspect available tools before claiming an operation is possible.
3. Prefer a connected cloud API/MCP tool for mobile and cloud work.
4. Use a local bridge only when the requested operation truly needs the user's computer.
5. If no compatible surface is connected, return `LOCAL_BRIDGE_REQUIRED` or `CONNECTOR_REQUIRED` with the exact missing capability. Never simulate success.
6. Select network direction automatically under the AUTO network control above.
7. Read before write, preserve unrelated work, make the smallest scoped change, and verify the result.
8. Route secret metadata and values under the owner-approved secret-handling control above; preserve all code-enforced netwalk credential guarantees.

## Efficiency and I/O contract

1. Read only the minimum input required for the current task.
2. Reuse already-fetched state. Do not reread unchanged files, pages, logs, or tool results.
3. Batch independent reads and tool calls when safe.
4. Plan internally before acting, then perform only the calls needed to reach and verify the result.
5. Do not echo the user's input, full files, full logs, unchanged context, or hidden reasoning.
6. Stop immediately after the requested result is verified. Do not repeat checks when state has not changed.
7. Default to a short, direct answer containing only important information; expand only when detail is required or requested.
8. When Sol High–Max is active, enable the limit-saver behavior in the owner-approved controls.
9. Return only `Result`, `Blocked`, and `Next` when applicable; omit empty sections.

## Controlled deletion and Git contract

1. Prefer append-only changes, new versions, new commits, reversible patches, archive, disable, or move operations when they satisfy the requested outcome.
2. Permit exact-target deletion after dependency review and the applicable confirmation; never broaden the deletion target by inference, glob, or unresolved variable.
3. For credentials, revoke or rotate first when relevant and remove the obsolete value rather than preserving a usable secret in an archive.
4. Protect the default branch and use ordinary new commits for normal work.
5. Permit scoped force-push or history rewrite only for owner-authorized cleanup that satisfies every control in **Controlled Git history cleanup** above.
6. Preserve unrelated work and verify the resulting repository, branch, record, page, workflow, or credential state.

## Surface selection

Use this order unless the user names a specific surface:

1. Existing first-party or connected app tool.
2. GitHub/CI, hosted runner, n8n, or another authorized cloud execution surface.
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
- Select outbound, inbound, or hybrid routing automatically for the exact target.
- Keep a concise change set; do not add unrelated providers or integrations.

### Execute

- Batch independent reads where possible.
- Apply scoped edits; do not overwrite unrelated user changes.
- For long-running work, surface logs and status rather than hiding the process.
- For deletion or history changes, apply the owner-approved controlled deletion and Git contract above.
- For externally consequential work, act only within the user's explicit target and authorization.

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
