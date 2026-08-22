# netwalk

**A read-only network survey toolkit for Claude Code.** Point it at one device you can log into,
and it crawls the network hop by hop, reads the health of everything it finds, draws the topology,
and produces a report you can hand to the site owner.

Six skills. Use them separately, or run the whole thing as one workflow.

```
/netwalk              the whole survey, end to end
/netwalk-login        collect credentials through a local browser form, never through the chat
/netwalk-scan         crawl the topology from one entry device
/netwalk-diag         export config read-only, read health, work out what is wrong
/netwalk-map          draw the diagram
/netwalk-fullreport   produce the deliverable HTML report
```

Works on **Windows, macOS and Linux**.

---

## Two promises, both enforced in code

**1. It never changes anything.** Every command is checked against a per-vendor read-only allowlist
before it is sent. Config writes, `clear counters`, `dmesg -C`, `systemctl restart`, `reload`,
`configure terminal` and shell metacharacters are all refused by the tool — not by a prompt asking
the model nicely. Configuration is *exported* for reading; nothing is ever imported.

```
$ netwalk_exec.py check --vendor mikrotik --cmd '/interface print detail'
ALLOW [mikrotik] read-only

$ netwalk_exec.py check --vendor mikrotik --cmd '/interface print; /system reboot'
DENY  [mikrotik] contains command separator or redirection ';' - run one plain command at a time

$ netwalk_exec.py check --vendor cisco --cmd 'show running-config | redirect flash:x'
DENY  [cisco] pipes output into a file (matched /\|\s*(redirect|tee|append)\b/)
```

The allowlist lives in `scripts/netwalk_policy.py` and is covered by `tests/test_policy.py`
(250 cases). If you widen it, run the tests.

**2. Credentials never touch the conversation.** `/netwalk-login` serves a one-shot page on your own
`127.0.0.1` — random port, random URL token, JSON-only POST, cross-origin requests rejected. You
type the password into your browser; it is written straight to a private file on your disk
(`0600` on POSIX, an owner-only ACL via `icacls` on Windows) and the listener exits. The assistant
is told the *path*, never the value, and the report renderer refuses to build a document from a
record containing credential material.

---

## Install

```bash
git clone https://github.com/<you>/netwalk
cd netwalk
python3 install.py
```

That copies the runtime to `~/.claude/skills/netwalk/toolkit/` and writes the six skill folders with
the real absolute paths baked in. Then, in Claude Code:

```
/netwalk
```

Optional extras:

```bash
python3 install.py --check                          # environment report
python3 ~/.claude/skills/netwalk/toolkit/scripts/netwalk_logos.py fetch    # vendor logos
python3 ~/.claude/skills/netwalk/toolkit/tests/test_policy.py              # self-test
python3 install.py --uninstall
```

### Requirements

| | |
|---|---|
| Python | 3.9+, standard library only |
| SSH, key auth | any OpenSSH client — built in on Windows 10+, macOS and Linux |
| SSH, password auth | one of: `pip install paramiko` (any OS), `sshpass` (macOS/Linux), `plink` (Windows) |

`python3 install.py --check` tells you which of these you actually have. On Windows, use `python`
instead of `python3` if that is how your install is named.

---

## How a survey goes

```
netwalk-login  →  netwalk-scan  →  netwalk-diag  →  netwalk-map  →  netwalk-fullreport
  get access      crawl the LAN     read health      draw it         hand it over
```

**Scope first.** netwalk crawls outward from one device you name. It is not a port scanner and will
not sweep a range you did not ask for. For customer work it records what you were authorised to do,
and the report prints it.

**Then it crawls.** LLDP, CDP, MNDP, ARP, DHCP leases, routing tables and per-port MAC tables, one
hop at a time, until there are no unvisited neighbours left. A port that has learned several MAC
addresses but reports no LLDP neighbour is flagged as a *suspected unmanaged switch* — the thing
that is physically there and does not announce itself.

**Then it reads health.** CPU, memory, storage, temperature, PoE budget, interface errors and CRC,
**link-down counts**, throughput, session tables, running and failed services, and the logs. Every
finding carries the command output that produced it; counters are divided by uptime before anything
is called a fault.

**Then you get artefacts.** A deterministic SVG topology diagram — vendor logo, hostname, management
IP, model, OS version and a live CPU/RAM/storage chip per device, one box per internet uplink, port
labels on every link, dashed for anything inferred — and a single self-contained HTML report that
opens offline and follows the reader's light/dark setting.

### Supported gear

Read-only command packs ship for **MikroTik RouterOS**, **Cisco IOS / IOS-XE / NX-OS**,
**ArubaOS-CX**, **HP/HPE ProCurve & Comware**, **FortiOS**, **Junos**, **Linux** (incl. Proxmox,
OpenWrt, EdgeOS, UniFi, Synology DSM) and **Windows**. Anything else falls back to a strict
`show`/`display`/`get`/`print`-only profile, so an unknown vendor is safe by default rather than
unsupported.

---

## Layout

```
netwalk/
  install.py                     cross-platform installer
  skills/                        the six SKILL.md files
  scripts/
    netwalk_common.py            paths, file permissions, SSH transport detection
    netwalk_policy.py            the read-only gate           <- the safety guarantee
    netwalk_cred.py              local browser credential intake
    netwalk_exec.py              gated command runner + evidence log
    netwalk_map.py               topology SVG renderer
    netwalk_report.py            HTML report renderer + credential sweep
    netwalk_logos.py             optional vendor logo fetcher
    packs/*.txt                  per-vendor read-only command lists
  schema/netwalk-record.schema.json    the contract between collection and reporting
  tests/test_policy.py           250 allow/deny cases
  examples/example-scan.json     a complete record you can render without touching a network
```

Try it without a network:

```bash
python3 scripts/netwalk_report.py examples/example-scan.json -o /tmp/demo.html
python3 scripts/netwalk_map.py    examples/example-scan.json -o /tmp/demo.svg
```

### The scan record

One JSON file per site per scan date is the single source of truth. The diagram and the report are
both rendered from it, deterministically — so the same record always produces the same output, two
scans of one site diff cleanly, and a changed report means a changed network. Never hand-edit the
SVG or the HTML; fix the record and re-render.

Everything for a real engagement lands under `~/.netwalk/sites/<slug>/`, which is git-ignored:

```
~/.netwalk/sites/acme-hq/
  scan-2026-08-22.json     the record
  evidence.jsonl           every command that was run
  configs/gw01.conf        read-only config exports (these DO contain secrets - keep them local)
  map.svg
  report.html              full
  report-public.html       for the site owner
```

---

## Where credentials live, exactly

`~/.netwalk/creds/<site>.json`, outside the repository, `0600` / owner-only ACL. Override the
location with `NETWALK_HOME`.

```bash
netwalk_cred.py list   --site acme-hq     # which hosts have what kind of credential - never values
netwalk_cred.py probe  --site acme-hq     # via netwalk_exec.py: does the login actually work
netwalk_cred.py forget --site acme-hq     # overwrite and delete
```

`forget` overwrites before deleting, which is **not** a forensic wipe on an SSD or a copy-on-write
filesystem. If the credentials were sensitive, rotate them.

---

## Limits, stated plainly

- It reads what the devices tell it. A device that lies, or a vendor CLI that omits something, will
  produce an incomplete picture — which is why `coverage.not_covered` is a required part of every
  report rather than an afterthought.
- Inferred topology is inferred. Unmanaged switches are detected by a MAC-vs-LLDP mismatch and drawn
  dashed; they are never presented as confirmed.
- `--public` mode hides sections. It does not sanitise text you wrote into a finding.
- The read-only gate is a strong allowlist, not a formal proof. It is regression-tested, and it is
  the reason you should always go through `netwalk_exec.py` instead of SSHing to a surveyed device
  directly.
- Vendor brand marks are not distributed with this repository. `netwalk_logos.py fetch` pulls them
  from [Simple Icons](https://simpleicons.org) (CC0-1.0) on request; a vendor with no logo renders
  as a lettered chip. All trademarks belong to their owners.

## Legal

Only run netwalk against equipment you own or have written authorisation to access. Logging into
someone else's network without permission is a crime in most jurisdictions, and "it was read-only"
is not a defence.

MIT licensed. See `LICENSE`.
