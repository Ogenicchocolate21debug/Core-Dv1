# netwalk

***English** · [ภาษาไทย](README.th.md)*

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

## Three promises, all enforced in code

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
(397 cases, including every command in every shipped pack). If you widen it, run the tests.

**2. Credentials never touch the conversation.** `/netwalk-login` serves a one-shot page on your own
machine. You type the password into your browser; it is written straight to a private file on your
disk (`0600` on POSIX, an owner-only ACL via `icacls` on Windows) and the listener exits. The
assistant is told the *path*, never the value, and the report renderer refuses to build a document
from a record containing credential material.

**The form is not reachable from anywhere else on the network.** The listener binds to
`127.0.0.1` — the loopback interface — not to `0.0.0.0`, so the kernel never accepts a packet for
it from another host. A colleague on the same LAN, a guest on the Wi-Fi, or a device on the network
being surveyed cannot open the page even if they know the port:

```
$ netwalk_cred.py serve --site acme-hq ...
   http://127.0.0.1:62742/Mnoc4Wmy1w80_h6RBlJgXXMPBs7VLkCk

$ lsof -nP -iTCP:62742 -sTCP:LISTEN          # on the machine serving it
   Python  98900  TCP 127.0.0.1:62742 (LISTEN)      <- not *:62742

$ curl http://192.168.60.12:62742/            # from any other host
   (connection refused)
```

Four further things stand between the page and anyone who is not you:

| | |
|---|---|
| **random port** | chosen per run, never fixed |
| **random URL token** | the path (`/Mnoc4Wmy...`) must be known; without it the server answers nothing |
| **cross-origin POSTs rejected** | a page open in your browser from anywhere else cannot post to it — this is the attack that loopback binding alone does not stop |
| **JSON only, one shot** | `request` mode exits after the submit it was waiting for |

What this does **not** protect against, stated plainly: another process running as *you*, on your
own machine, can reach loopback. That is the same trust boundary as the `0600` credential file
itself. If your account is compromised, the form is not what saves you.

**3. It never sweeps a range nobody authorised.** netwalk crawls outward from a device you name, and
it will also sweep an address range — but only one written into the site's scope with the name of
the person who authorised it, which then appears in the report. The check is in code, and there is
no override flag:

```
$ netwalk_sweep.py hosts --site acme-hq --range 198.51.100.0/24
DENY  198.51.100.0/24 is outside the authorised scope for this site
      (authorised: 192.0.2.0/24). Ask the owner and authorise it - there is no override flag
```

A range outside the scope is refused. So is a *supernet* of an authorised range — authorising a /24
does not authorise the /23 that contains it. So is public address space without a second explicit
flag, because owning one address in a hosting provider's /24 does not make the other 253 yours to
probe. So is anything larger than a /16, and so is a projected probe count over the cap. Covered by
`tests/test_sweep.py` (81 cases), and the ones that matter are the refusals.

---

## Install

```bash
git clone https://github.com/ripmilla/netwalk
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

### On an AI agent that is not Claude Code

netwalk is two layers: **plain Python scripts that need no agent at all**, and a set of
instructions telling an agent how to drive them. Only the second layer is Claude-specific, and
`AGENTS.md` is the agent-agnostic form of exactly the same instructions. Porting is a one-liner:

```bash
git clone https://github.com/ripmilla/netwalk && cd /path/to/your/project

python3 /path/to/netwalk/install.py --agent cursor     # .cursor/rules/netwalk.mdc
python3 /path/to/netwalk/install.py --agent codex      # AGENTS.md
python3 /path/to/netwalk/install.py --agent gemini     # GEMINI.md
python3 /path/to/netwalk/install.py --agent cline      # .clinerules/netwalk.md
python3 /path/to/netwalk/install.py --agent copilot    # .github/copilot-instructions.md
python3 /path/to/netwalk/install.py --agent windsurf   # .windsurf/rules/netwalk.md
python3 /path/to/netwalk/install.py --agent continue   # .continue/rules/netwalk.md
python3 /path/to/netwalk/install.py --agent aider      # CONVENTIONS.md
python3 /path/to/netwalk/install.py --agent generic    # AGENTS.md, for anything else
```

| Agent | `--agent` | File it writes |
|---|---|---|
| Claude Code | *(default, no flag)* | `~/.claude/skills/netwalk-*/SKILL.md` |
| OpenAI Codex CLI, OpenCode, Amp, Jules | `codex` / `opencode` / `generic` | `AGENTS.md` |
| Cursor | `cursor` | `.cursor/rules/netwalk.mdc` |
| Windsurf | `windsurf` | `.windsurf/rules/netwalk.md` |
| Cline / Roo Code | `cline` | `.clinerules/netwalk.md` |
| GitHub Copilot | `copilot` | `.github/copilot-instructions.md` |
| Gemini CLI | `gemini` | `GEMINI.md` |
| Continue | `continue` | `.continue/rules/netwalk.md` |
| Aider | `aider` | `CONVENTIONS.md` |

The absolute path to your clone is substituted in, so every command in the file is copy-pasteable.
An instruction file that already exists is appended to, never overwritten.

**No agent at all?** Everything works from a terminal — `install.py --check`, then the commands in
the Quick reference at the top of `AGENTS.md`. The agent's job is to decide *what to run next* as a
crawl unfolds; the guarantees live in the scripts, not in the agent.

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

`login`, `scan` and `diag` are **one loop, not three phases**. Every hop turns up devices nobody
mentioned; those go straight back onto the credential form that is already open, the engineer answers
them at their own pace, and the crawl carries on. It ends when a round finds nothing the engineer has
not already ruled on — or when they decide the coverage is good enough. `map` and `fullreport` run
once at the end, over whatever the loop actually reached.

**Scope first.** netwalk crawls outward from one device you name. It will also sweep an address
range — but only one that has been authorised for that site by name, with the name of the person who
authorised it, which then appears in the report. The check is in code, not in a prompt, and there is
no override flag: a range outside the scope is refused, so is a supernet of an authorised range, so
is public address space without a second explicit flag, and so is anything larger than a /16.

**Then it crawls.** LLDP, CDP, MNDP, ARP, DHCP leases, routing tables and per-port MAC tables, one
hop at a time, until there are no unvisited neighbours left. A port that has learned several MAC
addresses but reports no LLDP neighbour is flagged as a *suspected unmanaged switch* — the thing
that is physically there and does not announce itself.

**Then it sweeps what the crawl cannot see.** A TCP-connect sweep of the authorised ranges finds the
static-address server, the forgotten printer and the second firewall — everything that never speaks
LLDP and never turns up in an ARP table. A *refused* connection counts as a host found, so a box with
every port closed still appears. Roughly 68 well-known TCP ports are checked by default, and the ones
that are a finding on their own — telnet, SMB, RDP, VNC, Redis, Winbox, a database on a user VLAN —
are flagged as such. It is blind to UDP and to hosts that drop rather than reject, and that
limitation is written into the report's coverage section automatically rather than left implied.

**Then it checks the configuration against vendor best practice.** Not from memory — the checklist
is data (`netwalk_audit.py guide`), so the same checks run on every site: telnet and clear-text
management left enabled, a firewall input chain with no catch-all drop, default SNMP communities,
RoMON and MAC-server wide open, root SSH login, no BPDU guard, an open or WEP SSID, a database
listening on a user VLAN. It reads the config exports **off the disk**, so a config full of PSKs
never passes through the model, and every check that could *not* run is reported by name rather
than counted as a pass.

**Then it reads health.** CPU, memory, storage, temperature, PoE budget, interface errors and CRC,
**link-down counts**, throughput, session tables, running and failed services, and the logs. Every
finding carries the command output that produced it; counters are divided by uptime before anything
is called a fault.

**Then you get artefacts.** A deterministic SVG topology diagram — vendor logo, hostname, management
IP, model, OS version and a live CPU/RAM/storage chip per device, one box per internet uplink, port
labels on every link, dashed for anything inferred — and a single self-contained HTML report that
opens offline and follows the reader's light/dark setting.

### Supported gear

Controller-managed estates are read from the controller in one pass rather than device by device:
**UniFi** (`netwalk_unifi.py`, both the UniFi OS Integration API and the legacy login) and
**TP-Link Omada** (`netwalk_omada.py`, both the Open API and the older session API).

Read-only command packs ship for **MikroTik RouterOS**, **Cisco IOS / IOS-XE / NX-OS**,
**ArubaOS-CX**, **HP/HPE ProCurve & Comware**, **FortiOS**, **Junos**, **Linux** (incl. Proxmox,
OpenWrt, EdgeOS, UniFi, Synology DSM) and **Windows**. Anything else falls back to a strict
`show`/`display`/`get`/`print`-only profile, so an unknown vendor is safe by default rather than
unsupported.

---

## What it checks, security-wise

Two different things, and they are worth keeping apart.

**Hardening — is the configuration against the vendor's own advice?** `netwalk_audit.py` holds the
checklist as data, so the same checks run on every site instead of depending on anyone remembering
them. 38 checks: MikroTik and Cisco and Linux properly, Aruba, HP, Fortinet and Windows with a
starter set that the docs do not dress up as more than it is.

```bash
netwalk_audit.py guide --vendor mikrotik              # the checklist itself, as a document
netwalk_audit.py run --site acme-hq --record scan.json [--dry-run]
```

Each check carries the evidence that decides it, why it matters, a fix a technician can apply, and
the vendor guidance it came from. A firewall input chain with no catch-all drop, telnet or a
clear-text API left enabled, default SNMP communities, RoMON and MAC-server open to the whole
broadcast domain, root SSH login, no BPDU guard, an open or WEP SSID, a database listening on a
user VLAN.

Three properties matter more than the check count:

- **It reads the configuration off the disk, not through the conversation.** The exports are already
  there because `netwalk_exec.py --out` put them there. The full text never enters an agent's
  context; the excerpt attached to a finding is one line and goes through the redactor first.
- **`NOT CHECKED` is part of the output.** A device with no export, a check whose command is missing
  from the pack, and every item that needs a human walking the building are listed by name and
  written into `coverage.not_covered`. Six findings with ten silent skips reads as a clean bill of
  health, which is worse than no security section at all.
- **A check that reads one setting says so.** `mt-dns-remote` fires on `allow-remote-requests=yes`,
  which says the resolver will answer, not that anything can reach it — so it is reported as
  *suspected*, with instructions to read the raw firewall before repeating it to a customer. At a
  real site the raw table already dropped UDP/53 and a pattern match would have overruled a
  verified conclusion.

**Exposure — what is actually listening?** The crawl finds what announces itself. An authorised
sweep finds the rest, and the two together are what makes an "unidentified device" finding possible
at all. See **Scope first** above for the gate; a refused connection counts as a host found, the
sweep is blind to UDP, and both facts are written into the report rather than left implied.

Findings from either default to `public_safe: false`. A hardening list is a route map.

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
    netwalk_sweep.py             authorised subnet sweep + well-known port scan
    netwalk_audit.py             vendor hardening catalogue + the checks that read it
    netwalk_logos.py             optional vendor logo fetcher
    packs/*.txt                  per-vendor read-only command lists
  schema/netwalk-record.schema.json    the contract between collection and reporting
  tests/                         651 cases (policy 397 · sweep 81 · audit 57 · redaction 28 · …)
  examples/example-scan.json     a complete record you can render without touching a network
  CHANGELOG.md                   what changed between versions, newest first
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

---

## Closing a survey out

A survey leaves more behind than the report, and the report is the only part anyone remembers. When
the job is done:

```bash
netwalk_cred.py stop   --site acme-hq                  # 1. stop the credential form
netwalk_cred.py forget --site acme-hq --with-configs   # 2. shred credentials AND config exports
```

**Nothing expires on its own.** There is no TTL on the credential store, nothing deletes it at the
end of a scan, and a survey driven from two machines leaves two copies — run the same command on
each. `forget` without `--with-configs` tells you how many exports are still on disk and how large
they are, rather than letting them sit there unmentioned.

What is left behind, and how bad each one is:

| | Where | Contains |
|---|---|---|
| **Credential store** | `~/.netwalk/creds/<site>.json` | the passwords and key paths you were given. Plain JSON, protected by file permissions, **not encrypted** |
| **Configuration exports** | `~/.netwalk/sites/<site>/configs/` | PSKs, SNMP community strings and password hashes in clear text. **Larger and more sensitive than the credential file**, and nothing else deletes them |
| Scan record, map, reports | `~/.netwalk/sites/<site>/` | the deliverable. No secrets — the renderer refuses to build a report from a record that has any |

The full report also prints a *Where this survey left sensitive files* box naming these paths, so
the person you hand it to learns what exists on your machine rather than finding out later. That box
is in the full copy only; a customer reading the `--public` copy has no business learning where the
engineer keeps their passwords.

**Deleting is not rotating.** `forget` overwrites before unlinking, which is **not** a forensic wipe
on an SSD or a copy-on-write filesystem. If any of those credentials matter, rotate them — and say
so to the site owner rather than assuming the delete was enough.

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

## Version history

`CHANGELOG.md` summarises each release; the commit history is the detailed record, and every
commit message explains why a change was made rather than restating the diff. On GitHub, the
**Blame** view on any file jumps straight from a line to the commit that explains it.

```bash
git log --oneline v0.1.0..v0.2.0      # what changed between releases
git log -p --follow scripts/netwalk_policy.py    # one file's whole history
```

## Legal

Only run netwalk against equipment you own or have written authorisation to access. Logging into
someone else's network without permission is a crime in most jurisdictions, and "it was read-only"
is not a defence.

MIT licensed. See `LICENSE`.
