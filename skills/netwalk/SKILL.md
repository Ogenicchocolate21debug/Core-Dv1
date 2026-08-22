---
name: netwalk
description: "Run a complete read-only network survey end to end: get access, crawl the topology, diagnose every device, draw the diagram and produce a deliverable report. Loops netwalk-login, netwalk-scan and netwalk-diag until the crawl runs dry or the engineer is satisfied, then finishes once with netwalk-map and netwalk-fullreport. Use when the user wants a whole network surveyed, audited or documented rather than one specific step - 'survey this site', 'audit my customer's network', 'document what is on this LAN'."
---

# netwalk

The umbrella workflow for the **netwalk** read-only network survey toolkit.
Toolkit lives at `{{TOOLKIT}}`.

Each stage is also a skill in its own right. Use this one when the user wants the whole job;
invoke a single stage directly when they want just that step.

```
        ┌─────────────────── repeat until the frontier is empty ───────────────────┐
        │                                                                          │
        ▼                                                                          │
  netwalk-login  ──►  netwalk-scan  ──►  netwalk-diag  ───────────────────────────┘
   get access          crawl a hop        read its health
   (form stays open)   find neighbours    export config, find faults
        ▲                    │
        └── new devices ─────┘   each round's discoveries go back on the same form

                    when the crawl runs dry, or the engineer says enough
                                          │
                                          ▼
                        netwalk-map  ──►  netwalk-fullreport
                          draw it           hand it over
```

`netwalk-login`, `netwalk-scan` and `netwalk-diag` are **one loop, not three phases**. Every hop turns up devices nobody
mentioned; those go straight back onto the credential form that is already open, the engineer answers
them at their own pace, and the crawl carries on. It ends when a round finds nothing the engineer has
not already ruled on — or when they decide the coverage is good enough. `map` and `fullreport` run
once at the end, over whatever the loop actually reached.

## The two promises

1. **Read-only.** Every command is checked against a per-vendor allowlist in
   `scripts/netwalk_policy.py` before it is sent. Config writes, counter clears, service restarts
   and reboots are refused by the tool, not by good intentions. Config is exported, never imported.
2. **Credentials never enter the conversation.** They are typed into a page served on the user's own
   `127.0.0.1`, stored in a private file, and read by the exec wrapper — never by you. The same page
   carries the *access* questions: which URL, which port, which jump host, which controller site. When
   you are blocked on how to reach something, put the question on the form with `--ask` and let the
   user answer it there, rather than asking across several conversational turns.

Both are enforced in code. Do not route around either. If a read-only command is wrongly blocked,
add it to the allowlist, run `python3 {{TOOLKIT}}/tests/test_policy.py`, and say you did.

## Stage 0 — scope it

Before running anything:

- **What is the target?** netwalk needs one device it can log into and crawls out from there. It is
  not a port scanner and will not sweep a range the user has not named.
- **Whose network is it?** For a customer site, confirm the user is authorised to log into this
  equipment today, and write what they say into `site.scope_note`. It appears in the report.
- **What is off limits?** Fragile boxes, maintenance windows, devices to leave alone. Record them
  under `coverage.not_covered` so the report does not imply they were checked.
- **What are we actually answering?** "Document the network" and "find why the Wi-Fi drops at 2pm"
  produce different scans. Ask.

Pick a site slug (`acme-hq`). Everything for the engagement lands in `~/.netwalk/sites/<slug>/` — outside the installed toolkit, so an upgrade cannot delete it.

## The loop, and how it ends

Stages 1 to 3 repeat. Do not run them once each and call the survey done: a crawl discovers devices
over minutes, each round turns up neighbours nobody mentioned, and those go back on the credential
form that is already open rather than into the conversation.

Two things end the loop, and only two:

- **the frontier is empty** — a round finds no device the engineer has not already ruled on, whether
  by giving a credential, saying "I don't know what this is", marking it out of scope, or deferring it
- **the engineer says the coverage is good enough** — a legitimate answer on a large site, and one you
  should offer explicitly rather than crawling on

Either way, write what was reached and what was not into `coverage.not_covered` before moving on.
Stages 4 and 5 run **once**, at the end, over whatever the loop actually reached.

## Stage 1 — access (`netwalk-login`)

Serve the credential form for the entry device. Never take a secret in the chat, not even offered, and
put any "how do I reach this" question on the same form with `--ask` instead of in the conversation.
Hand the `netwalk_cred.py request` command to the user to run in their own terminal (`!` prefix in
Claude Code) rather than running it as a background task — it waits on a human, and a reaped task
takes the one-time URL with it. Verify with `netwalk_exec.py probe` before moving on; an unverified
credential wastes the whole next stage.

## Stage 2 — crawl (`netwalk-scan`)

Run the vendor discovery pack, map the output into the scan record, then hop to every neighbour that
has not been visited and repeat until the frontier is empty. Each round, put **all** the newly
discovered devices on the login form at once (`--round N`) rather than asking about them one by one;
the user can answer "I don't know what this is" or "not ours" per device, and both are real results
that go in the report. Stop when a round produces nothing the user has not already ruled on. Re-run the map and report after each
batch so the user can correct a wrong assumption early. Devices you cannot reach stay in the record
as `reachable: false` with a reason.

## Stage 3 — diagnose (`netwalk-diag`)

Export config read-only and collect CPU, memory, storage, temperature, PoE, interface errors and
flap counts, throughput, sessions, services and logs. Turn observations into findings with evidence
and a recommendation a technician can act on. Divide counters by uptime before calling anything a
fault.

## Stage 4 — draw (`netwalk-map`)

Deterministic SVG from the record. One box per internet uplink, port labels on every link, dashed
for anything inferred. Fix the record, never the SVG.

## Stage 5 — deliver (`netwalk-fullreport`)

One self-contained HTML file. Produce the full copy for the user; produce `--public` as well when
the report is going to someone who should see the shape of the network but not a list of ways into
it. The renderer refuses to build a report from a record containing credential material.

## Stage 6 — close out

- Tell the user every file path you produced and which mode each report is.
- Say plainly what was **not** covered. A polished document should never imply a completeness the
  scan did not have.
- Offer to clear the credential store:
  `python3 {{TOOLKIT}}/scripts/netwalk_cred.py forget --site <slug>`
  If the credentials were sensitive, recommend rotating them — overwrite-then-delete is not a
  forensic wipe on modern storage.

## Layout on disk

```
~/.netwalk/sites/<slug>/
  scan-YYYY-MM-DD.json   the record - single source of truth, never overwritten
  evidence.jsonl         every command run, appended as it happens
  configs/<host>.conf    read-only config exports  (contain secrets - never into the report)
  map.svg
  report.html            full
  report-public.html     for the site owner
```

Records accumulate one per scan date, so two surveys of one site diff cleanly.

## Never

- Change anything on a surveyed device. Report the fix; the owner applies it.
- Accept a credential in the conversation, or open the credential store yourself.
- Scan outside the agreed scope.
- Present an incomplete crawl as complete.
