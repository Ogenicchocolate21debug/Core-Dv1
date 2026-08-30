---
name: ogenic-god-toolkit
description: One auto-routed OGENIC toolkit that analyzes each request and selects or chains Code Skill, Code System, Code Delivery, Code Website, and Scientific Agent Skills without requiring the user to choose a category.
---

# OGENIC GOD TOOLKIT

Use one entry point for OGENIC agent work. Analyze the request, inspect available execution surfaces, then automatically route to one or more of five capability groups.

## Capability groups

1. **Code Skill** — GOD MODE orchestration, request classification, tool discovery, sequencing and verification.
2. **Code System** — workspace, files, patching, Git, dev/test/lint/typecheck/build, shell/process/Codex and health.
3. **Code Delivery** — GitHub CI/CD, n8n, deploy, scheduler, authenticated webhook/outbound, connectors and deployment verification.
4. **Code Website** — browser/UI, DOM/accessibility/input/vision/window, website operation, Cloudflare and web deployment.
5. **Scientific Agent Skills** — route scientific/research tasks to the specialist library in `Ogenicchocolate21debug/scientific-agent-skills`.

## Auto-routing

- Never require the user to remember or select a group when intent is clear.
- Select the minimum groups needed; chain groups when dependencies cross categories.
- Use the existing GOD MODE operating, efficiency, secret-handling, Git, deletion and verification contracts from `../god-mode/SKILL.md`.
- Keep the scientific library as a referenced specialist source rather than copying all upstream skills into this directory.
- Read `BLUEPRINT.md` for routing examples, source-of-truth mapping and tool-creation instructions.

## Invocation

`Use $ogenic-god-toolkit ...` or `@OGENIC GOD TOOLKIT ...` where supported.
