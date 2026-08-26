# GOD MODE capability matrix

| Tool family | Cloud / mobile route | Local-computer route | Honest fallback |
|---|---|---|---|
| `workspace_*` | GitHub, Library, Notion, Drive, or hosted workspace inventory and snapshots | Local bridge enumerates approved folders and snapshots | `CONNECTOR_REQUIRED` or `LOCAL_BRIDGE_REQUIRED` |
| `read_file` / `search_text` / `apply_patch` | Connected repository/workspace file APIs | Sandboxed local filesystem bridge | Return read-only guidance if no write surface exists |
| `git_status` / `git_diff` / `git_log` | GitHub commits, comparisons, pull requests, and branch state | Local Git CLI | Use GitHub state and say local uncommitted changes are unavailable |
| `project_dev` / `test` / `lint` / `typecheck` / `build` | CI workflow or hosted runner | Local process bridge | Prepare the command/workflow without claiming it ran |
| `process_*` / `shell` | Hosted runner, n8n execution, or sandbox when authorized | Local process bridge with stdout/stderr and stop control | `EXECUTION_SURFACE_REQUIRED` |
| `codex_run` | Current Codex work session or connected hosted coding run | Local Codex CLI through bridge | Continue directly in the current Codex session |
| `dom_cdp` | Authenticated cloud browser or browser connector | Chrome CDP on the local computer | Use public HTTP fetch for read-only pages; do not claim DOM control |
| `accessibility` | Web DOM/accessibility tree only | Microsoft UI Automation for Windows apps | State that native Windows control needs the local bridge |
| `input_event` | Browser click/type/scroll tool | Keyboard/mouse event bridge | Prefer DOM or accessibility targeting; raw input is last resort |
| `vision` | Uploaded images, browser screenshots, or connected media | Screen/window/region capture and OCR | Ask for an attachment when no capture surface exists |
| `window` | Browser tabs/pages where supported | Activate, move, resize, minimize, maximize, or close native windows | Native window control requires the local bridge |
| `office` | Connected Docs/Sheets or file-format tools | Word/Excel COM | Export/import an Office file through a connected cloud surface |
| `clipboard` | Chat attachment or explicit copy/paste handoff | Local text/image clipboard | Produce a copy-ready block; never claim clipboard access |
| `file_dialog` | Chat attachment picker or connected file selector | Native Open/Save dialog | Request attachment or destination path |
| `screen_record` | Browser trace or screenshot sequence when available | Local screen recorder | Capture screenshots; state that video recording is unavailable |
| `audio` | Uploaded audio or connected generation/transcription tool | Local microphone capture and playback | Ask for an upload; do not claim microphone access |
| `notification` | Chat/automation/app notification | Windows notification | Return the result in chat if no notifier is connected |
| `scheduler` | ChatGPT Automations, n8n schedule, or hosted cron | Windows Scheduled Task | Create a documented schedule plan only if no scheduler is connected |
| `web_fetch` | Outbound HTTP/web connector | Outbound local HTTP client | Respect allowlists, auth scope, and rate limits |
| `system_info` / `health` | Connected service status, CI, deployment, or monitoring APIs | Local CPU, RAM, disk, process, and bridge health | Never substitute cloud status for local computer health |

## Status vocabulary

- `READY_CLOUD`: callable through a connected cloud tool.
- `READY_LOCAL`: callable through the connected local bridge.
- `READY_HYBRID`: both routes are available.
- `CONNECTOR_REQUIRED`: a cloud account/app connection is missing.
- `LOCAL_BRIDGE_REQUIRED`: the operation needs the user's computer.
- `EXECUTION_SURFACE_REQUIRED`: code can be prepared but cannot currently run.
- `CONFIGURATION_REQUIRED`: a non-secret identifier, scope, or target is missing.
- `REVERSIBLE_ALTERNATIVE_REQUIRED`: the requested outcome appears to require permanent deletion; propose an archive, disable, move, or versioned replacement instead.

## Efficiency and persistence boundary

- Read the minimum required scope and reuse unchanged state.
- Batch independent calls, summarize large outputs, and stop after verification.
- Keep normal final answers under 120 words unless detail is requested.
- Prefer append-only or versioned changes.
- Allow `- old` / `+ new` in a Git diff only when the old version remains recoverable in history.
- Never hard-delete, force-push, rewrite history, or run destructive reset/clean operations.

## Outbound-only boundary

- Permit outbound HTTPS, MCP, API, Git, and authenticated connector calls.
- Do not bind a public port, expose a public webhook receiver, or accept unsolicited inbound traffic.
- A local `127.0.0.1` listener may be used only for a user-requested local workflow and must never bind to `0.0.0.0`.
- For event-driven systems, use polling, scheduled pulls, or an already-authorized managed webhook service; GOD MODE itself remains outbound-only.
