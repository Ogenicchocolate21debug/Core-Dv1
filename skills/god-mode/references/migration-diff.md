# GOD MODE wording migration

GitHub renders removed lines red and added lines green.

```diff
- Tools Type Outbound-Only, but computer-only tools are presented as if every chat can run them directly.
+ Tools Type Outbound-Only with automatic CLOUD, LOCAL, or HYBRID routing and explicit availability status.

- workspace_* — manage projects on the computer.
+ workspace_* — manage connected cloud projects on mobile; use the local bridge for computer folders.

- project_dev / test / lint / typecheck / build — run directly from chat.
+ project_dev / test / lint / typecheck / build — run through hosted CI/runner or the local bridge; otherwise prepare commands without claiming execution.

- process_* / shell / codex_run — always run programs on the user's computer.
+ process_* / shell / codex_run — use a hosted execution surface in cloud mode or Local Codex/CLI through the bridge in local mode.

- dom_cdp / accessibility / input_event — control Chrome and Windows applications.
+ dom_cdp / accessibility / input_event — cloud browser controls websites; native Windows UI and raw keyboard/mouse require the local bridge.

- vision / window / clipboard / file_dialog / screen_record / audio — direct device access from any chat.
+ vision / window / clipboard / file_dialog / screen_record / audio — use attachments and connected cloud surfaces on mobile; direct device capture/control is local-bridge-only.

- office — Word and Excel through Office COM only.
+ office — connected Docs/Sheets or document tools in cloud mode; Word/Excel COM in local mode.

- notification / scheduler — Windows notification and Scheduled Task only.
+ notification / scheduler — ChatGPT Automations, n8n, hosted cron, or app notifications in cloud mode; Windows equivalents in local mode.

- system_info / health — always reads CPU, RAM, disk, and processes from the user's computer.
+ system_info / health — reads connected service health in cloud mode and actual computer metrics only when the local bridge is connected.

- Public webhook or inbound listener may be created as needed.
+ GOD MODE never exposes a public inbound listener; use outbound polling or an existing managed webhook service.

- Read broad context, repeat logs, and explain every internal step before returning the result.
+ Read the minimum required input, reuse unchanged state, batch calls, stop after verification, and default to a final answer under 120 words.

- Treat every Git minus line as forbidden, or permanently delete when removal is requested.
+ Allow reversible `- old` / `+ new` replacements with history preserved; never hard-delete files, data, branches, or history.

- Force-push, reset, clean, or rewrite history when it is the fastest path.
+ Never force-push, rewrite history, or use destructive reset/clean; return `REVERSIBLE_ALTERNATIVE_REQUIRED` instead.
```

## Source clarification

The chat contained one attached file, `IMG_0172.jpeg`, and it is an image asset rather than a second Toolkit definition. The second functional source is therefore the user's tool-family specification in the chat. If a separate Toolkit file is attached later, merge it by updating `source-contract.md` and this diff before changing behavior.
