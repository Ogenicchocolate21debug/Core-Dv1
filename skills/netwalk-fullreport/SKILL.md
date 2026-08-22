---
name: netwalk-fullreport
description: "Turn a netwalk scan record into a single self-contained HTML network report a site owner can be handed. Includes summary, method and coverage, embedded topology diagram, device inventory, per-device interfaces/VLANs/wireless/services/health, findings with evidence and recommendations, and the full log of commands run. Has a --public mode that strips internal detail. Use when the user asks for a network report, audit document, site survey writeup or something to deliver to a client."
---

# netwalk-fullreport

Part of the **netwalk** read-only network survey toolkit. Toolkit lives at `{{TOOLKIT}}`.

This produces the thing that leaves the building. Treat it accordingly.

## Run it

```bash
T={{TOOLKIT}}
R=~/.netwalk/sites/acme-hq/scan-2026-08-22.json

python3 $T/scripts/netwalk_report.py $R -o ~/.netwalk/sites/acme-hq/report.html
python3 $T/scripts/netwalk_report.py $R -o ~/.netwalk/sites/acme-hq/report-public.html --public
```

One self-contained HTML file: diagram, CSS and all. No external requests, so it works offline, over
email, and from a USB stick. It follows the reader's light/dark setting and prints sensibly.

**The diagram is embedded at full size, not scaled to the column.** A 3000px site map squeezed into
a 1000px page is legible only as a shape — the hostnames, IP addresses and port names, which are the
whole reason to look at it, become unreadable. It scrolls sideways inside its own frame instead, and
the report offers a *Fit to width* toggle for readers who want the overview.

## Full vs public

| | Full | `--public` |
|---|---|---|
| Summary, topology, inventory, device detail | yes | yes |
| Findings marked `public_safe: true` | yes | yes |
| Findings marked `public_safe: false` | yes | **hidden** |
| Evidence excerpts under each finding | yes | hidden |
| Command log | yes | hidden |
| Scan date, engineer name | yes | hidden |
| Management-exposure detail | yes | hidden |

Ask which one they want when it is ambiguous, and default to **full** — the person who ran the scan
should see everything. Send `--public` when the recipient is a landlord, a tenant, a procurement
department, or anyone who should see the shape of the network but not a list of ways into it.

**`--public` is not redaction.** It hides sections; it does not sanitise text you wrote. If a
finding's title says "admin/admin still works on the core switch", `--public` will happily print it
when `public_safe` is `true`. Set the flag correctly at the finding level in `netwalk-diag`.

## The credential sweep

Before rendering, the record is swept for anything that looks like a secret — keys named
`password`, `token`, `secret`, `community`, `psk`, `key_path` and friends, plus values containing
private-key blocks, `password=` assignments, SNMP communities or Cisco `secret` hashes. If anything
matches, **the render is refused** with the exact JSON path.

If the user asks for the credentials so they can write up the site, that is a fair request and the
answer is not the report: `netwalk_cred.py export` writes them a separate 0600 access document, which
by default carries the addresses, accounts and routes in without any secret values. The report stays
clean either way.

When that fires, fix the record — do not weaken the check. A secret in a customer-facing report is
the one failure in this toolkit that cannot be walked back once the file is sent.

## Before you hand it over

Read the rendered report as the recipient, not as the person who made it:

1. **Is the coverage section honest?** `coverage.not_covered` becomes a visible "what this report
   does not cover" box. If it is empty, that is a claim of completeness — is it true? A missing
   subnet, a skipped RF survey, a device the user asked you not to touch all belong there.
2. **Does every finding have evidence and a real recommendation?** "Investigate further" is not a
   recommendation. Name the port, the setting, the next check.
3. **Is the severity defensible?** Everything marked high reads as noise; nothing marked high when
   the guest network is wide open is worse.
4. **Does the diagram match the tables?** Both come from the same record, so a mismatch means the
   record is internally inconsistent — usually an edge naming a `host_id` that no device uses.
5. **Would a stranger understand the entry point and the scope?** `site.scope_note` is what says you
   were authorised to be there.
6. **Anything in there you would not want forwarded?** Config exports, PSKs and password hashes stay
   on disk beside the record and never in the report.

## Regenerating

The record is the source of truth. Never hand-edit the HTML — change the record and re-render, or
the next run silently discards your edit. The renderer is deterministic, so two scans of one site
produce diffable reports and a changed report means a changed network.

## Telling the user what they got

Give them the paths, say which mode each file is, and say plainly what is missing. If the crawl
stopped early or three devices were unreachable, that goes in your message as well as in the
report — do not let a polished document imply a completeness the scan did not have.

**Say where the survey left its sensitive files, every time.** The full report renders a *Where this
survey left sensitive files* box in the Method section — the path to the credential store, the path
to the config exports, and the fact that netwalk deletes neither of them by itself. Repeat it in
your message rather than assuming they read that box:

- `~/.netwalk/creds/<slug>.json` — the credentials they typed into the login form, plain JSON,
  file-permission protected and **not encrypted**. It survives the engagement until someone runs
  `netwalk_cred.py forget --site <slug>`, on **every machine the survey ran from** — a survey driven
  from two boxes leaves two copies.
- `~/.netwalk/sites/<slug>/configs/` — full config exports, containing PSKs, SNMP communities and
  password hashes in clear text.

Then offer to clear the credential store there and then. If any of those credentials are sensitive,
say that deleting is not the same as rotating: the shred overwrites the file, which on an SSD or a
copy-on-write filesystem is not a guarantee. The box appears in the full copy only — a customer
reading the public copy has no business learning where the engineer keeps their passwords.

## Never

- Send or upload the report anywhere. Produce the file, hand over the path, let the user decide who
  sees it.
- Put credentials, config exports, PSKs or password hashes in it.
- Present a partial survey as a complete one.
