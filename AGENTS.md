# netwalk — instructions for AI coding agents

netwalk is a **read-only network survey toolkit**. This file is the agent-agnostic form of the
same instructions that ship as Claude Code skills under `skills/`. Any agent that reads a project
instruction file (`AGENTS.md`, `GEMINI.md`, `.cursor/rules`, `.clinerules`, `CONVENTIONS.md` …)
can work from this.

Replace `<TOOLKIT>` below with wherever you cloned this repository.

---

## The three promises, and why they are not optional

**1. netwalk never changes a device.** Every command is checked against a per-vendor read-only
allowlist in `scripts/netwalk_policy.py` *before it is sent*. Config writes, counter clears,
service restarts, reboots and command smuggling are refused by the tool, not by your good
intentions. Never SSH to a surveyed device directly — always go through
`scripts/netwalk_exec.py`, so the guarantee holds and the command lands in the evidence log.

**2. Credentials never enter the conversation.** They are typed into a page served on the user's
own `127.0.0.1` by `scripts/netwalk_cred.py`, stored in a private file, and read by the exec
wrapper — never by you. Do not ask for a password in chat, do not accept one if offered, and never
open `~/.netwalk/creds/*.json`. You do not need the value; you pass a site slug and a host id.

**3. netwalk never sweeps a range nobody authorised.** The address sweep in
`scripts/netwalk_sweep.py` refuses any range that is not written into the site's `scope.json` with
the name of the person who authorised it. A supernet of an authorised range is refused, public
address space needs a second explicit flag, anything larger than a /16 is refused outright, and
there is no `--force`. Crawling from a device the user gave you a credential for is one thing;
probing addresses nobody named is another, and in several places netwalk gets used it is an offence.

If a read-only command is wrongly blocked, add it to the allowlist, run
`python3 <TOOLKIT>/tests/test_policy.py`, and say that you did. Never route around the wrapper.
The same rule applies to the sweep gate: get the authorisation, do not edit the scope file yourself.

---

## Quick reference

```bash
python3 <TOOLKIT>/install.py --check          # environment report
python3 <TOOLKIT>/tests/test_policy.py        # 254 read-only cases
python3 <TOOLKIT>/tests/test_sweep.py         # 81 sweep-scope cases
python3 <TOOLKIT>/scripts/netwalk_cred.py  serve  --site S --host 'id,ip,vendor,note'
python3 <TOOLKIT>/scripts/netwalk_cred.py  add    --site S --host '...' --ask 'HOST|key|Label|hint'
python3 <TOOLKIT>/scripts/netwalk_cred.py  answers --site S
python3 <TOOLKIT>/scripts/netwalk_exec.py  probe  --site S --host H
python3 <TOOLKIT>/scripts/netwalk_exec.py  run    --site S --host H --cmd-file packs/<vendor>.discovery.txt
python3 <TOOLKIT>/scripts/netwalk_unifi.py collect --site S --host H --out unifi.json
python3 <TOOLKIT>/scripts/netwalk_omada.py info    --site S --host H
python3 <TOOLKIT>/scripts/netwalk_sweep.py authorize --site S --range 10.2.30.0/24 --authorized-by 'who said yes'
python3 <TOOLKIT>/scripts/netwalk_sweep.py hosts   --site S --range 10.2.30.0/24
python3 <TOOLKIT>/scripts/netwalk_sweep.py ports   --site S --target 10.2.30.99
python3 <TOOLKIT>/scripts/netwalk_sweep.py record  --site S --record record.json
python3 <TOOLKIT>/scripts/netwalk_map.py    record.json -o map.svg
python3 <TOOLKIT>/scripts/netwalk_report.py record.json -o report.html [--public]
```

Engagement data lives in `$NETWALK_HOME/sites/<slug>/` (default `~/.netwalk/sites/`), outside the
toolkit, so an upgrade cannot delete a customer's scan history.

---


## `netwalk`

> Run a complete read-only network survey end to end: get access, crawl the topology, diagnose every device, draw the diagram and produce a deliverable report. Loops netwalk-login, netwalk-scan and netwalk-diag until the crawl runs dry or the engineer is satisfied, then finishes once with netwalk-map and netwalk-fullreport. Use when the user wants a whole network surveyed, audited or documented rather than one specific step - 'survey this site', 'audit my customer's network', 'document what is on this LAN'.

## netwalk

The umbrella workflow for the **netwalk** read-only network survey toolkit.
Toolkit lives at `<TOOLKIT>`.

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

### The three promises

1. **Read-only.** Every command is checked against a per-vendor allowlist in
   `scripts/netwalk_policy.py` before it is sent. Config writes, counter clears, service restarts
   and reboots are refused by the tool, not by good intentions. Config is exported, never imported.
2. **Credentials never enter the conversation.** They are typed into a page served on the user's own
   `127.0.0.1`, stored in a private file, and read by the exec wrapper — never by you. The same page
   carries the *access* questions: which URL, which port, which jump host, which controller site. When
   you are blocked on how to reach something, put the question on the form with `--ask` and let the
   user answer it there, rather than asking across several conversational turns.
3. **No unauthorised sweeping.** `netwalk_sweep.py` refuses any address range that is not in
   the site's `scope.json` with the name of whoever authorised it. There is no override flag.
   Crawling from a device you were given a credential for is not the same as probing addresses
   nobody named.

All three are enforced in code. Do not route around any of them. If a read-only command is wrongly blocked,
add it to the allowlist, run `python3 <TOOLKIT>/tests/test_policy.py`, and say you did.

### Stage 0 — scope it

Before running anything:

- **What is the target?** netwalk needs one device it can log into and crawls out from there. It can
  also sweep an address range, but only after the owner has authorised that range by name
  (`netwalk_sweep.py authorize`) — the gate is enforced in code and has no override.
- **Whose network is it?** For a customer site, confirm the user is authorised to log into this
  equipment today, and write what they say into `site.scope_note`. It appears in the report.
- **What is off limits?** Fragile boxes, maintenance windows, devices to leave alone. Record them
  under `coverage.not_covered` so the report does not imply they were checked.
- **What are we actually answering?** "Document the network" and "find why the Wi-Fi drops at 2pm"
  produce different scans. Ask.

Pick a site slug (`acme-hq`). Everything for the engagement lands in `~/.netwalk/sites/<slug>/` — outside the installed toolkit, so an upgrade cannot delete it.

### The loop, and how it ends

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

### Stage 1 — access (`netwalk-login`)

Serve the credential form for the entry device. Never take a secret in the chat, not even offered, and
put any "how do I reach this" question on the same form with `--ask` instead of in the conversation.
Hand the `netwalk_cred.py request` command to the user to run in their own terminal (`!` prefix in
Claude Code) rather than running it as a background task — it waits on a human, and a reaped task
takes the one-time URL with it. Verify with `netwalk_exec.py probe` before moving on; an unverified
credential wastes the whole next stage.

### Stage 2 — crawl (`netwalk-scan`)

Run the vendor discovery pack, map the output into the scan record, then hop to every neighbour that
has not been visited and repeat until the frontier is empty. Each round, put **all** the newly
discovered devices on the login form at once (`--round N`) rather than asking about them one by one;
the user can answer "I don't know what this is" or "not ours" per device, and both are real results
that go in the report. Stop when a round produces nothing the user has not already ruled on. Re-run the map and report after each
batch so the user can correct a wrong assumption early. Devices you cannot reach stay in the record
as `reachable: false` with a reason.

**Sweep the subnets the crawl walked through**, once the owner has authorised them by name. The
crawl only finds what announces itself; a sweep finds the static-address server and the forgotten
printer, and it is usually where the surprises are:

```bash
python3 <TOOLKIT>/scripts/netwalk_sweep.py authorize --site <slug> --range 10.2.30.0/24 \
  --authorized-by "who said yes, and when"
python3 <TOOLKIT>/scripts/netwalk_sweep.py hosts  --site <slug> --range 10.2.30.0/24
python3 <TOOLKIT>/scripts/netwalk_sweep.py ports  --site <slug> --target 10.2.30.99
python3 <TOOLKIT>/scripts/netwalk_sweep.py record --site <slug> --record <record>.json
```

Everything that answers and is not already a device goes back onto the login form — it is another
round of the same loop, not a separate exercise. The sweep is TCP-only and therefore blind to UDP
and to hosts that drop rather than reject; `record` writes that into `coverage.not_covered`.

### Stage 3 — diagnose (`netwalk-diag`)

Export config read-only and collect CPU, memory, storage, temperature, PoE, interface errors and
flap counts, throughput, sessions, services and logs. Turn observations into findings with evidence
and a recommendation a technician can act on. Divide counters by uptime before calling anything a
fault.

### Stage 4 — draw (`netwalk-map`)

Deterministic SVG from the record. One box per internet uplink, port labels on every link, dashed
for anything inferred. Fix the record, never the SVG.

### Stage 5 — deliver (`netwalk-fullreport`)

One self-contained HTML file. Produce the full copy for the user; produce `--public` as well when
the report is going to someone who should see the shape of the network but not a list of ways into
it. The renderer refuses to build a report from a record containing credential material.

### Stage 6 — close out

- Tell the user every file path you produced and which mode each report is.
- Say plainly what was **not** covered. A polished document should never imply a completeness the
  scan did not have.
- Offer to clear the credential store:
  `python3 <TOOLKIT>/scripts/netwalk_cred.py forget --site <slug> --with-configs`
  — **on every machine the survey ran from.** Nothing expires on its own, and `--with-configs`
  is what removes the configuration exports, which hold PSKs and password hashes and are the
  more dangerous of the two. Without the flag the command tells you how many are still there.
  If the credentials were sensitive, recommend rotating them — overwrite-then-delete is not a
  forensic wipe on modern storage.

### Layout on disk

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

### Never

- Change anything on a surveyed device. Report the fix; the owner applies it.
- Accept a credential in the conversation, or open the credential store yourself.
- Scan or sweep outside the agreed scope. A range the owner has not authorised by name is refused
  by `netwalk_sweep.py`, and that refusal is the correct answer, not an obstacle.
- Present an incomplete crawl as complete.


## `netwalk-login`

> Collect device credentials for a netwalk survey through a local browser form instead of the chat. Serves a one-shot page on 127.0.0.1 where the user types usernames, passwords, SSH key PATHS or API tokens; the values are written to a private file on their machine and the assistant never sees them. Use when a scan needs to log into a device and there is no working credential yet, when a hop fails authentication, or when the user asks how to give access without pasting secrets.

## netwalk-login

Part of the **netwalk** read-only network survey toolkit. Toolkit lives at `<TOOLKIT>`.

### The two rules

**1. Never accept a credential in the conversation.** Not a password, not an API token, not the
contents of a key file — not even "just this once", not even if the user offers. Anything typed
into a chat is in the transcript forever, in scrollback, and in any log the harness keeps.

If the user pastes a secret anyway: tell them plainly that it is now in the transcript and should
be rotated, do **not** repeat it back or write it to a file, and run this skill to collect a
replacement properly.

A **path** to a key file (`~/.ssh/id_ed25519`, `C:\Users\me\.ssh\id_rsa`) is not a secret and is
fine to discuss. The key's *contents* never are.

**2. Anything you need to know about *how to reach* a device goes on the form too.**

Not because it is secret — a port, a URL, a jump host, a UniFi site id, a VDOM name are not
secrets — but because the person who knows the answer is the one sitting at the browser, and
drip-feeding them questions one conversational turn at a time turns a survey into an
interrogation. Put every open question on the form, let them answer in one pass, and read the
answers back with `answers`.

Every card already carries an **Access details** section (management URL, SSH jump host,
site/tenant id). For anything beyond that, attach your own question with `--ask`:

```bash
--ask 'unifi-ctrl|reach_how|How do you normally reach this controller? URL and port|https://192.0.2.10:8443'
--ask '*|window|When can we reboot, if it comes to that?|'
```

Format is `HOST|key|Label|placeholder`, repeatable; `*` puts the question on every card. Answers
come back through `answers --site <slug>`, which prints access details and question answers and
never prints a secret. A device set to **Skip** still records its answers — "why can't we get in"
is often the most useful thing on the page.

### How it works

`netwalk_cred.py request` starts a throwaway HTTP listener on `127.0.0.1` with a random port and a
random URL token, opens the user's browser at it, and serves a form listing exactly the devices you
name. When the user hits Save, the browser POSTs back to that same local process, which writes
`~/.netwalk/creds/<site>.json` — `0600` on macOS/Linux, an owner-only ACL via `icacls` on Windows —
and exits. Nothing is transmitted off the machine and nothing passes through you.

### Steps

1. **Work out which devices need access.** Usually this is the list `netwalk-scan` just discovered
   and could not log into, plus the entry point if this is the start of a survey. You need, per
   device: a stable id (hostname or IP), the IP, and the vendor if you know it.

2. **Pick a site slug** — short, lowercase, no spaces (`acme-hq`, `branch-02`). Everything else in
   netwalk keys off it. Reuse the existing slug if the site has been scanned before; running the
   form again updates devices in place and leaves the rest alone.

3. **Serve the form — and leave it up for the whole survey.**

   `serve` keeps the page alive instead of exiting on the first submit. The user fills in what they
   know now, presses Save, and leaves the tab open; as the crawl finds more devices you push them
   into the same page with `add`, and they appear within a few seconds without the URL changing.
   Only the cards the user actually edited are re-sent, so saving again never re-transmits a
   credential that is already stored.

   ```bash
   python3 <TOOLKIT>/scripts/netwalk_cred.py serve --site acme-hq \
     --host 'gw01,192.0.2.1,mikrotik,entry point'

   # later, mid-crawl, as neighbours turn up:
   python3 <TOOLKIT>/scripts/netwalk_cred.py add --site acme-hq \
     --host 'sw-core,192.0.2.2,cisco,found via LLDP on gw01 ether8' \
     --ask 'sw-core|why|What does this switch feed?|'

   python3 <TOOLKIT>/scripts/netwalk_cred.py url  --site acme-hq   # re-share the link
   python3 <TOOLKIT>/scripts/netwalk_cred.py stop --site acme-hq   # when the survey is done
   ```

   Start `serve` once, at the beginning. Do not stop and restart it to add a device — the URL is
   regenerated every time and the user loses the tab they had open.

   The one-shot form is still there as `request` for a single question, but `serve` is the default
   for a survey.

4. **Or, for a single question, serve it once:**

   ```bash
   python3 <TOOLKIT>/scripts/netwalk_cred.py request \
     --site acme-hq \
     --host 'gw01,192.0.2.1,mikrotik,entry point - user has this one' \
     --host 'sw-core,192.0.2.2,cisco' \
     --host 'ap-01,192.0.2.11,ubiquiti,found via LLDP'
   ```

   Each `--host` is `id[,ip[,vendor[,note]]]`. The note is shown on the card — use it to remind the
   user *why* you are asking for this device. Add `--no-open` if a browser should not be launched,
   `--timeout 1800` for a long session.

   The command prints `NETWALK_LOGIN_URL <url>` and then blocks. **Tell the user the URL** in case
   the browser did not open, and say plainly that you cannot see what they type.

   **Prefer handing this command to the user to run in their own terminal.** It waits on a human at
   a keyboard, which can be minutes, and an agent background task is the wrong place for that — it
   gets reaped, it hits a timeout, and when it dies the URL dies with it because the port and token
   are fresh on every run. In Claude Code the user can run it inline by prefixing `!`:

   ```
   ! python3 <TOOLKIT>/scripts/netwalk_cred.py request --site acme-hq --host 'gw01,192.0.2.1,mikrotik' --timeout 0
   ```

   `--timeout 0` waits until they stop it with Ctrl-C. Then continue from step 5 — `list` and
   `probe` tell you it worked without you ever seeing a value. Run it yourself only when the user
   is clearly at the keyboard and expecting it right now.

5. **Wait.** `request` exits by itself on save; `serve` keeps going. On success it prints `SAVED n host(s)` and the protection
   that was applied. If it prints a `WARNING` that the file could not be locked down (a Windows box
   with no `icacls`, an exotic filesystem), pass that warning on to the user verbatim — do not
   quietly accept it — and offer to `forget` the store as soon as the survey is finished.

6. **Confirm without looking.** `list` prints which hosts have which *kind* of credential and never
   a value:

   ```bash
   python3 <TOOLKIT>/scripts/netwalk_cred.py list --site acme-hq
   ```

7. **Read the non-secret answers back:**

   ```bash
   python3 <TOOLKIT>/scripts/netwalk_cred.py answers --site acme-hq
   ```

   This prints IP, port, vendor, username, management URL, jump host, tenant and every question
   answer. It is the one command in this skill you are meant to read the output of.

8. **Prove each login works before handing back to the scan:**

   ```bash
   python3 <TOOLKIT>/scripts/netwalk_exec.py probe --site acme-hq --host gw01
   ```

   `REACHABLE` means the credential is good and the vendor profile matched. `FAILED` prints the SSH
   error — read it before re-asking. `Permission denied` is a wrong credential; `Connection refused`
   or a timeout is a reachability problem and asking for a new password will not fix it.

### Choosing the auth method on the form

| Method | Use when | Notes |
|---|---|---|
| SSH key file | there is a key on this machine | Give the **path**. Best option — no secret is stored by netwalk at all. |
| SSH password | the device only does passwords | Needs a helper: `paramiko` (any OS), `sshpass` (macOS/Linux) or `plink` (Windows). Run the preflight below if unsure. |
| SSH key + password | key login plus an enable/secondary password | e.g. Cisco `enable` |
| API token | the vendor is driven over HTTP, not SSH — UniFi and Omada controllers | netwalk stores it; you drive the API yourself. `netwalk_exec.py` only speaks SSH. |
| I know what it is, no login | they can identify it but cannot give access | Fill in what it is, its role, what it is for and who owns it. The device is then documented in the report as a known device that was not surveyed - far more useful than a blank, and it gets a proper `role` on the diagram |
| Skip | you do not have access and are not getting it | The device stays in the record as `reachable: false` with a reason. Any questions on that card are still saved, and an existing credential is left alone — use `forget` to remove one. That is a legitimate result: say so in the report rather than leaving a gap. |

#### Controller credentials

| Controller | Username field | API token field | Where the user finds it |
|---|---|---|---|
| UniFi (Network 9+) | — | API key | Control Plane → Admins → API keys |
| UniFi (older) | local admin | — | use the password field |
| Omada (Open API) | **client_id** | **client_secret** | Settings → Platform Integration → Open API |
| Omada (older) | controller admin | — | use the password field |

Put the controller's address in **Management URL** (`https://omada.example.com:8043`) — a controller
almost never answers on the port its devices use, and the port box defaults to SSH. Put the site id
in **Site / tenant** if they know it; both adapters will list the sites otherwise.

Environment check when password auth is in play:

```bash
python3 <TOOLKIT>/scripts/netwalk_common.py
```

### Giving the engineer something to document from

The customer report never contains a credential — the report renderer refuses to build from a record
that has any in it. But the engineer who ran the scan usually does need a site access document, and
that is a different file for a different audience:

```bash
# what a site document actually needs: which device, which address, which account,
# which route in - and no secret values at all
python3 <TOOLKIT>/scripts/netwalk_cred.py export --site acme-hq --out ~/Documents/acme-access.md

# only if they genuinely need the values, and only with both flags
python3 <TOOLKIT>/scripts/netwalk_cred.py export --site acme-hq --out ~/Documents/acme-secrets.md \
  --with-secrets --i-understand-this-file-contains-passwords
```

Both are written 0600. `export` refuses to write anywhere under the site folder, because that folder
holds the artefacts that get handed to the customer. Offer the default form; mention `--with-secrets`
only if they ask for the values, and say plainly that it puts live passwords on disk.

**Do not read either file.** You do not need to — you produced it for the user, not for yourself.

### Cleaning up

Offer this at the end of every engagement, especially for someone else's network:

```bash
python3 <TOOLKIT>/scripts/netwalk_cred.py forget --site acme-hq            # whole site
python3 <TOOLKIT>/scripts/netwalk_cred.py forget --site acme-hq --with-configs   # AND the config exports
python3 <TOOLKIT>/scripts/netwalk_cred.py forget --site acme-hq --host ap-01
```

The file is overwritten before deletion, which is not a forensic wipe on an SSD or a
copy-on-write filesystem. If the credentials were sensitive, tell the user to rotate them.

### Hard boundaries

- Never `cat`, `Read`, `type` or otherwise open `~/.netwalk/creds/*.json`. You do not need the
  values — `netwalk_exec.py` reads them for you. Opening it puts the secret in your context and
  therefore in the transcript.
- Never echo a credential into a scan record, a report, a diagram, a commit, or a note.
- Never write credentials to a password manager, a cloud service, or a repo on the user's behalf.
- If a `--json` run of `netwalk_exec.py` ever surfaces something secret-looking in device output,
  that is device config, not the vault — still keep it out of the report. `netwalk_report.py`
  refuses to render a record containing credential material, but do not rely on that as your
  first line of defence.

Next: `netwalk-scan` to crawl, or `netwalk-diag` if you already have the topology.


## `netwalk-scan`

> Discover and map a network read-only, starting from one device the user names. Crawls outward hop by hop using LLDP, CDP, MNDP, ARP, DHCP leases, routing and MAC tables across MikroTik, Cisco, Aruba, HP, Fortinet, Juniper, Ubiquiti, Linux and Windows, and writes a structured scan record. Use when the user asks to scan, survey, crawl, inventory, audit or 'see everything on' a network or a site, theirs or a customer's.

## netwalk-scan

Part of the **netwalk** read-only network survey toolkit. Toolkit lives at `<TOOLKIT>`.

The goal is a complete, honest picture of the target network — and honesty includes writing down
what you could not reach. A survey that quietly stops at the first ring of neighbours and presents
itself as complete is worse than one that says "6 of 9 devices reached, here is why".

### Read-only, and it is enforced

Every command goes through `netwalk_exec.py`, which checks it against a per-vendor read-only
allowlist before it leaves the machine. Config writes, counter clears, service restarts, reboots
and shell metacharacters are refused by the tool. You never SSH to a surveyed device directly —
always go through the wrapper, so the guarantee holds and every command lands in the evidence log.

If the gate blocks something you believe is genuinely read-only, do not work around it. Either pick
a different command, or add it to the allowlist in `scripts/netwalk_policy.py`, run
`python3 <TOOLKIT>/tests/test_policy.py`, and note the change. Never bypass the wrapper.

### Before you touch anything

Ask, and do not guess:

1. **What is the target?** An entry device (IP), a subnet, a site name, "my whole office"? You need
   at least one device you can log into — netwalk crawls *from* a device. It can also sweep an
   address range, but only one the owner has explicitly authorised; see **Sweeping a range** below.
2. **Whose network is it?** If it is a customer's, confirm the user is authorised to log into this
   equipment today. Record what they say in `site.scope_note` — it goes in the report.
3. **Anything off limits?** Production boxes that must not even be logged into, a maintenance
   window, a device that falls over when you open a session. Respect it and record it under
   `coverage.not_covered`.
4. **How far?** Default is exhaustive: keep hopping until every reachable neighbour has been
   visited. On a big site, say up front roughly how many hops that might be and check in.

Pick a site slug (`acme-hq`). Everything for the engagement lands in `~/.netwalk/sites/<slug>/` — outside the installed toolkit, so an upgrade cannot delete it.

### The shape of the whole thing

The crawl and the login form are one loop, not two phases. Every hop turns up devices nobody
mentioned, and the person who knows what they are is at the browser, not in the conversation:

```
scan a device  ──►  new neighbours discovered
      ▲                      │
      │                      ▼
      │            put them ALL on the login form  (netwalk_cred.py request --round N)
      │            each card: credential, or "I don't know", or "not ours"
      │                      │
      └──────  read the answers back (answers) ──┘   log into what you were given
```

**Never drop a discovered host because you do not recognise it.** It is tempting to filter an ARP
table down to the entries whose OUI looks like infrastructure and quietly skip the rest. Do not:
an unrecognised MAC is not evidence that a device is uninteresting, it is evidence that *you* cannot
identify it — which is precisely the question the form exists to ask. This has already gone wrong
once in the field: a hypervisor was left off the form because its OUI was not in a lookup table,
and it was the single most important host on that VLAN.

If a subnet has more hosts than one page can sensibly carry, put the infrastructure-looking ones on
first, then **say in the same message exactly how many you left off and on what basis**, and offer
to add them. Silent filtering and honest triage look identical in the output; only one of them is.

Start `netwalk_cred.py serve` once at the beginning and leave it running for the whole survey. Each
round, push that round's discoveries into the open page with `add` — the user keeps one tab, keeps
one URL, and fills things in at their own pace while the crawl carries on. Never stop and restart
the form to add a device: the URL changes and the user loses the page they had open.
Cards the user has already answered are marked as such and carry their previous answer; new ones
are badged **NEW this round**. Pass `--round N` so the header says which pass this is.

Three answers are not credentials and all three are useful:

| The user picks | What it means | What you do |
|---|---|---|
| **I don't know what this device is** | it is on their network and they cannot identify it | record `reachable: false`, `unreachable_reason: "the site owner could not identify this device"`, and raise it as a finding — an unidentified device is one of the more valuable things a survey turns up |
| **Not ours / out of scope** | someone else's equipment | never connect. `netwalk_exec.py` refuses this one in code, so you cannot do it by accident. Keep it on the diagram as a boundary device |
| **Skip for now** | ask again later | record it, carry on, and put it back on the form next round |

Read every answer back with `answers`, which prints IP, port, username, management URL, jump host,
tenant and any question you attached — and no secret:

```bash
python3 <TOOLKIT>/scripts/netwalk_cred.py answers --site acme-hq
```

Keep going until a round turns up no device the user has not already ruled on. That is the
termination condition — not "enough devices", and not "the first ring of neighbours".

### The loop

For each device, in this order:

1. **Get in.** No credential yet → hand off to `netwalk-login`. Confirm with:
   `python3 <TOOLKIT>/scripts/netwalk_exec.py probe --site <slug> --host <id>`

2. **Identify the vendor** before running anything else. The probe output usually tells you.
   Wrong vendor means wrong commands and a pile of syntax errors that look like access problems.

3. **Run the discovery pack** for that vendor:

   ```bash
   python3 <TOOLKIT>/scripts/netwalk_exec.py run \
     --site acme-hq --host gw01 \
     --cmd-file <TOOLKIT>/scripts/packs/mikrotik.discovery.txt \
     --evidence ~/.netwalk/sites/acme-hq/evidence.jsonl
   ```

   Packs exist for `mikrotik`, `cisco`, `aruba`, `hp`, `fortinet`, `linux`, `windows`.

   **Controller-managed estates do not get crawled device by device.** UniFi and Omada both know
   every device they adopted, so read the controller once instead of SSHing into a hundred APs:

   ```bash
   python3 <TOOLKIT>/scripts/netwalk_unifi.py collect --site acme-hq --host unifi-controller --out unifi.json
   python3 <TOOLKIT>/scripts/netwalk_omada.py info    --site acme-hq --host omada-controller
   python3 <TOOLKIT>/scripts/netwalk_omada.py collect --site acme-hq --host omada-controller --out omada.json
   ```

   Run Omada's `info` first: it hits `/api/info`, which needs no credential, so it separates "wrong
   address" from "wrong credential" - the two failures that look identical from the outside. Both
   adapters take `--via user@host` when the controller only answers from inside the site. For a vendor
   with no pack, use the `unknown` profile (`show`/`display`/`get`/`print` only) and add commands
   one at a time with `--cmd`, checking each with `netwalk_exec.py check --vendor ... --cmd ...`.
   Some commands in a pack will not exist on a given model — a failed command is normal, not a
   reason to stop.

   For a **config export**, always add `--out <file>`. That writes the full text to a 0600 file
   and prints only a summary — a config is full of PSKs, community strings and password hashes, and
   anything printed reaches you, the model API and the transcript. Secret-shaped values in printed
   output are masked as `<redacted>` as a backstop, but `--out` is the actual control.

4. **Map the output into the scan record**, `~/.netwalk/sites/<slug>/scan-<YYYY-MM-DD>.json`, against
   `<TOOLKIT>/schema/netwalk-record.schema.json`. Per device, capture at minimum:

   - identity: hostname, model, serial, OS + version, uptime, role
   - every interface: name, description, admin/link state, speed, IPs, VLAN/PVID, error and drop
     counters, **link-down count** (the best cable-fault signal there is), and the **MAC/CAM table
     learned on that port**
   - the device's **own** neighbour table (`/ip neighbor print detail`, `show lldp neighbors detail`
     …). Run it *on* each device — do not just record what its parent saw about it. Skipping this
     is how phantom topology gets into diagrams.
   - ARP table, DHCP leases, VLANs with tagged/untagged ports, routing table
   - for APs: every SSID with its security mode, VLAN, band/channel/width and client count
   - for Linux/Windows: running and failed services, listening sockets

5. **Hop.** For every neighbour not yet visited, resolve its vendor and credential and repeat.
   Try the credential that worked on the previous hop first — one account per site is the common
   case. If it fails, that one device goes to `netwalk-login`; do not stall the whole crawl.
   Keep going until the frontier is empty. A neighbour found at hop 4 gets visited at hop 5.

6. **Record dead ends honestly.** Unreachable, no CLI, credential refused, user said don't:
   `reachable: false` plus a real `unreachable_reason`, and move on.

   Before writing a device off, collect the open questions and send them back through
   `netwalk-login` in one batch — the credential form takes `--ask`, so "which port is the
   controller on", "is there a jump host", "what is this device on ether16" are all questions the
   user answers in the browser in one pass. Asking them one at a time in the chat is the slow way,
   and the answers are not secrets so `answers` reads them straight back.

### Sweeping a range

The crawl finds the managed estate — whatever speaks LLDP, appears in an ARP table, or holds a DHCP
lease. It misses the printer nobody remembers, the old server on a static address, the second
firewall someone left plugged in. A sweep is the other half of the picture, and on most sites it is
where the surprises are.

**It cannot run until the owner has authorised the range, by name.** That is enforced in code:

```bash
python3 <TOOLKIT>/scripts/netwalk_sweep.py authorize --site acme-hq \
  --range 10.2.30.0/24 --range 10.2.40.0/24 \
  --authorized-by "Khun Somchai, IT manager, by phone 2026-08-22" \
  --exclude 10.2.30.99          # a box he asked us to leave alone
```

The name goes in `scope.json` and comes out again in the report. There is no `--force`: a range
outside the scope is refused, a supernet of an authorised range is refused, public address space
needs a second explicit flag, and anything larger than a /16 is refused outright. If you find
yourself wanting to get past the gate, the answer is to ask the owner, not to edit the file.

```bash
# which addresses answer at all - TCP connect to a few common ports, plus one ping
python3 <TOOLKIT>/scripts/netwalk_sweep.py hosts --site acme-hq --range 10.2.30.0/24

# what those addresses are listening on - ~68 well-known TCP ports by default
python3 <TOOLKIT>/scripts/netwalk_sweep.py ports --site acme-hq --target 10.2.30.99 \
  --profile standard            # or --profile quick, or --ports 22,80,8000-8010

# fold the results into the scan record and list what is not in devices[] yet
python3 <TOOLKIT>/scripts/netwalk_sweep.py record --site acme-hq \
  --record ~/.netwalk/sites/acme-hq/scan-2026-08-22.json
```

Three things to know before you read the output:

- **A refused connection proves a host is there**, exactly as well as an open one does. A box with
  every port closed still appears in the results, and that is deliberate.
- **The sweep is blind to UDP.** SNMP, DNS over UDP, IPMI, syslog and IKE do not show up at all, and
  neither does a host whose firewall drops instead of rejecting. `record` writes that limitation
  into `coverage.not_covered` for you. Do not let the report imply the list is exhaustive.
- **Ports carry a `risk` note when finding them open is a finding by itself** — telnet, SMB, RDP,
  VNC, Redis, Winbox, a database answering on a user VLAN. `ports` prints them; you still have to
  write them into `findings[]` with the port as evidence.

**Where the sweep runs from matters.** By default it runs from your machine, so it only sees what
your machine can route to — a management VLAN you are not on will look empty rather than absent:

| Situation | What to use |
|---|---|
| you are on the LAN, or on a VPN into it | the default, no extra flags |
| the range is only reachable from inside the site | `--via user@linux-host` — an `ssh -D` SOCKS tunnel through a Linux box you already have a credential for |
| the only way in is a MikroTik | RouterOS refuses dynamic forwarding, so `--via` cannot work. Run the sweep on the router instead: `netwalk_exec.py run --cmd '/tool ip-scan address-range=10.2.30.0/24 duration=30s'` — the allowlist requires `duration=`, so it cannot run unbounded |

Every address that answers and is not already in `devices[]` goes on the credential form, including —
especially — the ones you cannot identify. `record` prints that list for you. The rule from the
crawl applies unchanged here: an unrecognised host is not evidence the host is dull.

### Deriving topology

`topology_edges` is what the diagram is drawn from, so build it deliberately rather than dumping
every neighbour sighting:

- One entry per **physical link**, not per protocol. If A sees B over both CDP and LLDP, that is one
  edge. Record the port on each end — a diagram without port labels cannot be used to trace a cable.
- A discovery frame arriving on a *bridge* or *VLAN* interface tells you the device is somewhere in
  that broadcast domain, not that it is directly attached. Prefer the physical port when one is named.
- **Suspected unmanaged switch**: one physical port that has learned 2+ MAC addresses but reports 0
  or 1 LLDP/CDP neighbours. A dumb switch floods discovery frames instead of terminating them, so
  the two managed devices see each other directly and the thing between them is invisible. Add it as
  a device with `role: "unmanaged-switch"`, `reachable: false`, and edges marked
  `discovered_via: "inferred"`. Say it is inferred; never draw it as if you logged into it.
- **WAN links**: one entry in `wan_links` per internet uplink, with ISP, interface, IP, speed and
  whether it is primary or backup. Never merge several uplinks into a single "INTERNET" cloud —
  which link is which is exactly what someone reads the diagram to find out.

### Keep the artefacts fresh as you go

After each hop or small batch, re-run the map and report rather than waiting for the crawl to end:

```bash
python3 <TOOLKIT>/scripts/netwalk_map.py    ~/.netwalk/sites/acme-hq/scan-2026-08-22.json -o ~/.netwalk/sites/acme-hq/map.svg
python3 <TOOLKIT>/scripts/netwalk_report.py ~/.netwalk/sites/acme-hq/scan-2026-08-22.json -o ~/.netwalk/sites/acme-hq/report.html
```

A partial map beats no map, and the user can correct a wrong assumption at hop 2 instead of hop 9.

### Fill in coverage before you finish

`coverage.not_covered` is not optional. Write down anything a reader could reasonably assume was
checked and was not: subnets never entered, a Wi-Fi RF survey that did not happen, a device the user
asked you to leave alone, a vendor whose CLI you could only partly read. This is the section that
keeps the report honest.

### Never

- Change configuration. Report the fix; the site owner applies it.
- Sweep a range that is not in `scope.json`, or hop into a device outside the agreed scope. If the
  gate refuses a range, get the owner's authorisation and record it — never route around it.
- Put a credential anywhere in the scan record.
- Present an incomplete crawl as complete.

Next: `netwalk-diag` for health and root cause, `netwalk-map` for the diagram,
`netwalk-fullreport` for the deliverable.


## `netwalk-diag`

> Read a network device or Linux/Windows server end to end and work out what is wrong with it. Exports config read-only, collects CPU, memory, storage, temperature, PoE, interface counters, error and flap counts, throughput, sessions, services and logs, then reasons from that evidence to concrete findings with severity and recommendations. Use when the user asks what is wrong with a device or site, wants a health check, or has a symptom (slow, dropping, rebooting, flapping) to chase.

## netwalk-diag

Part of the **netwalk** read-only network survey toolkit. Toolkit lives at `<TOOLKIT>`.

`netwalk-scan` answers *what is out there*. This skill answers *what is wrong with it*.

### Read-only, and it is enforced

Config is **exported**, never imported or edited. Not one command changes device state — that
includes `clear counters`, `dmesg -C`, `systemctl restart` and `debug`, all of which the gate
refuses. If a device needs a change, that is a finding with a recommendation, and the site owner
decides. Run everything through `netwalk_exec.py` so the guarantee holds and the command lands in
the evidence log.

### 1. Collect

Assumes a credential exists (`netwalk-login`) and the vendor is known.

```bash
T=<TOOLKIT>
python3 $T/scripts/netwalk_exec.py run --site acme-hq --host gw01 \
  --cmd-file $T/scripts/packs/mikrotik.config.txt \
  --out ~/.netwalk/sites/acme-hq/configs/gw01.conf \
  --evidence ~/.netwalk/sites/acme-hq/evidence.jsonl

python3 $T/scripts/netwalk_exec.py run --site acme-hq --host gw01 \
  --cmd-file $T/scripts/packs/mikrotik.health.txt \
  --evidence ~/.netwalk/sites/acme-hq/evidence.jsonl
```

Packs: `mikrotik`, `cisco`, `aruba`, `hp`, `fortinet`, `linux`, `windows`, each with a
`.config.txt`, a `.health.txt` and a `.security.txt`. Record the exported config path in
`config_export_path` — relative to the site folder, never pasted into the report.

Run the security pack too, and run it with `--out` — it deliberately pulls the parts of the
configuration that hold community strings and key material, so its output must land on disk
rather than in the conversation:

```bash
python3 $T/scripts/netwalk_exec.py run --site acme-hq --host gw01 \
  --cmd-file $T/scripts/packs/mikrotik.security.txt \
  --out ~/.netwalk/sites/acme-hq/configs/gw01.security.txt \
  --evidence ~/.netwalk/sites/acme-hq/evidence.jsonl
```

**Always use `--out` for a config export.** With `--out` the full text is written straight to a
0600 file and only a one-line summary is printed. Without it, the whole config comes back through
you — and a vendor config is packed with PSKs, SNMP communities, RADIUS secrets, password hashes and
container environment variables. Anything that reaches you is transmitted to a model API and written
into the session transcript, and neither can be un-sent.

`netwalk_exec.py` masks secret-shaped values in whatever it prints (`<redacted>`), so an accidental
read is survivable — but that is a safety net, not the control. The control is `--out`.

Record the export path in `config_export_path`. Never `cat` it, never paste it into the record, and
warn the user before they forward it to anyone.

#### What to pull, whatever the vendor

| Area | What matters | Why |
|---|---|---|
| CPU | current load, and *which process* if the vendor shows it | 90% CPU on one control-plane process is a very different fault from 90% forwarding load |
| Memory | used vs total, and free trend if available | small routers OOM quietly and reboot |
| Storage | free space, and flash write counts on RouterOS | a full disk stops logging first and routing second |
| Temperature / fan / PSU | current reading, thresholds | the cause behind "it reboots in the afternoon" |
| Interfaces | rx/tx errors, CRC, drops, **link-down count**, duplex mismatch, SFP dBm | the single richest source of real faults |
| Throughput | per-interface bps at sample time | tells you whether "slow" is saturation or something else |
| Sessions | conntrack/session count vs max | a firewall at its session ceiling drops new flows while looking idle |
| PoE | used vs budget | an AP that reboots under load is often a PoE budget problem |
| Logs | errors, auth failures, link flaps, resets, DHCP exhaustion | the timeline that connects the rest |
| Services (servers) | running / failed / restart counts, listening sockets | a service that restarts 40 times an hour is not "running" |

For Linux/Windows also take failed units, `journalctl -p err`, disk health and the process list.

### 2. Analyse — evidence first

Every finding needs the observation that produced it. No evidence, no finding: write it as a
question for the user instead.

Read the numbers before reaching for a story:

- **Correlate before concluding.** "CPU is 95%" is an observation. "CPU is 95% because the firewall
  is doing connection tracking for 60k sessions on a box rated for 20k" is a finding. If you cannot
  bridge the two, mark `confidence: "suspected"` and say what would settle it.
- **Counters are cumulative.** 5,000 CRC errors over 400 days of uptime is noise; 5,000 since a
  reboot yesterday is a bad cable. Always divide by uptime before calling something a fault.
- **Link-down counts beat error counters** for finding a flapping port, and a flapping access port
  with a phone or AP on it explains a lot of "the network is slow" tickets.
- **Duplex mismatch** shows as late collisions and CRC on one side only.
- **Match the symptom.** If the user reported something specific, say explicitly whether the data
  supports it. "You reported afternoon slowness; the WAN interface is at 94% of 100M every day from
  13:00" is useful. So is "nothing in this data explains it, here is what to capture next."
- **Do not invent severity.** `critical` = it is broken or actively unsafe now. `high` = it will
  break or is exploitable. `medium` = real risk, not urgent. `low`/`info` = hygiene.

### 2b. Hardening — run the catalogue, do not rely on remembering

Health is about what is broken. Hardening is about what is configured against the vendor's own
advice, and it is not left to memory: `netwalk_audit.py` holds the checklist as data, so the same
checks run on every site whether or not anyone thought of them.

```bash
python3 $T/scripts/netwalk_audit.py guide --vendor mikrotik      # the checklist itself
python3 $T/scripts/netwalk_audit.py run --site acme-hq \
  --record ~/.netwalk/sites/acme-hq/scan-2026-08-22.json --dry-run
```

`run` reads the config exports **off the disk** and writes findings into `findings[]`. The config
text never passes through you; the excerpt attached to each finding is one line, redacted. Drop
`--dry-run` to write.

Three things about the output matter more than the findings themselves:

- **`NOT CHECKED` is part of the result.** A device with no export on disk, a check whose command is
  missing from the pack output, and every manual item are all listed by name and written into
  `coverage.not_covered`. Repeat them in the report. A hardening section that shows six findings and
  hides that ten checks never ran is worse than no hardening section.
- **A `config_absent` check is `confidence: "suspected"`.** It fires on the *absence* of a line, and
  absence can mean "not configured" or "not in the part of the config we pulled". Read it before
  you put it in front of a customer.
- **Every finding is `public_safe: false` by default.** A hardening list is a route map. Promote one
  to the public copy only deliberately.

The catalogue does not replace judgement. Anything you spot that it has no check for still belongs
in `findings[]` with `category: "security"` — and if it is a class of problem rather than a one-off,
add a check to `netwalk_audit.py`, run `python3 $T/tests/test_audit.py`, and it is closed for every
future site instead of just this one.

#### The baseline

Checks come from the vendor's own hardening guidance plus what actually goes wrong on sites, and
each check names the guidance it came from. Where a vendor publishes no guidance worth citing, the
check says it is common practice rather than dressing itself up as a standard.


### 3. Write findings into the record

Append to `findings[]` in the scan record (schema: `<TOOLKIT>/schema/netwalk-record.schema.json`):

```json
{
  "id": "F7", "severity": "high", "category": "availability", "host_id": "sw-core",
  "title": "Port Gi1/0/12 has flapped 214 times since the last reboot",
  "detail": "214 link-downs over 26 days of uptime, roughly 8 a day, on the port feeding AP-FL2. Every flap drops that AP's clients.",
  "evidence": [
    {"source": "show interfaces Gi1/0/12", "excerpt": "214 interface resets", "observed_at": "2026-08-22T10:14:00+07:00"},
    {"source": "show version | include uptime", "excerpt": "uptime is 26 days"}
  ],
  "confidence": "confirmed",
  "recommendation": "Replace the patch lead and re-seat both ends, then re-check the counter after a week. If it keeps climbing, move the AP to a different port to isolate port vs cable.",
  "public_safe": true
}
```

Make the recommendation something a technician can act on — which port, which cable, what to check
afterwards. "Investigate the interface" is not a recommendation.

Health numbers go in `devices[].health`, log lines worth keeping in `devices[].log_excerpts`.

### 4. Report back

Summarise for the user: what is broken now, what will break, what is only untidy — and say plainly
what the data does *not* explain. Then `netwalk-fullreport` turns it into the deliverable.

### Never

- Fix anything. Not even "while I'm in here" — an undocumented change during a survey is the worst
  kind of change.
- Clear a counter or a log. That destroys the evidence the next engineer needs.
- Report a finding you cannot point at evidence for.
- Copy a config export, PSK, community string or password hash into the report.


## `netwalk-map`

> Draw a network topology diagram from a netwalk scan record. Produces a self-contained SVG with a vendor logo, hostname, management IP, model, OS version and live CPU/RAM/storage/temperature per device, one box per internet uplink, and port labels on every link. Use when the user asks for a network diagram, topology map or visual of a scanned site, or wants the picture refreshed after more devices were found.

## netwalk-map

Part of the **netwalk** read-only network survey toolkit. Toolkit lives at `<TOOLKIT>`.

### Run it

```bash
python3 <TOOLKIT>/scripts/netwalk_map.py ~/.netwalk/sites/acme-hq/scan-2026-08-22.json \
  -o ~/.netwalk/sites/acme-hq/map.svg \
  [--public] [--title "Acme HQ — after the switch swap"] [--top-down] [--no-group-aps]
```

Output is one self-contained SVG: no external fonts, no scripts, no network requests. It opens in a
browser, drops into a document, and follows the reader's light/dark setting. `netwalk-fullreport`
embeds the same renderer, so the diagram in the report and the standalone file never drift apart.

`--public` drops the scan date and the unreachable-device count from the caption.

### The record is the source of truth

The renderer draws only what the record says. **Never hand-edit the SVG** — fix the record and
re-render, or the diagram and the report start telling different stories and the next scan silently
reverts your edit.

Layout is deterministic and reads **left to right**, the way a packet travels: internet uplinks in
a column on the left, then the gateway, then each layer of switching, then the edge. Devices are
ranked by BFS depth from the gateway and ordered inside each rank to minimise crossings. A rank with
more devices than fit in one column wraps into another column rather than running off the page.
Same record in, same SVG out — so two scans of one site diff cleanly and a changed diagram means a
changed network.

`--top-down` stacks it vertically instead, which suits a shallow network or a portrait page.

### What the record needs for a good diagram

| Field | Effect if missing |
|---|---|
| `devices[].vendor` | falls back to a lettered chip instead of a logo |
| `devices[].hostname`, `mgmt_ip` | the box is hard to identify |
| `devices[].model`, `os_version` | the version line is empty — and version is what people read a diagram for at upgrade time |
| `devices[].role` | everything lands in one flat rank and the layout stops meaning anything |
| `devices[].health` | no CPU/RAM/storage/temperature chips |
| `topology_edges[].a_port` / `b_port` | links have no port labels, so nobody can trace a cable from the picture |
| `wan_links[]` | no uplink boxes at all |

Chips turn red past CPU 80%, RAM 85%, storage 85%, 65 °C — so an overloaded box is visible in the
picture, not just in a table.

### Access points are grouped per switch

A site with a hundred APs draws a hundred boxes and a comb of a hundred lines: accurate, unreadable,
and not what anyone opens a diagram for. Every AP whose only uplink is one switch is collapsed into
a single node on that switch showing **how many APs, the address range they occupy, the model mix,
and how many are up versus down**. The per-device detail is still in the report's inventory table —
only the picture groups them.

An AP with more than one uplink (a mesh AP, or one with a second cable) is never collapsed: its
extra link is exactly the thing a diagram exists to show. Pass `--no-group-aps` to draw every access
point separately.

### Conventions worth keeping

- **One box per internet uplink.** Primary and backup are separate boxes with ISP, IP and speed.
  Never merge them into a single "INTERNET" cloud — which link is which is the whole point.
- **Dashed = inferred.** Any edge with `discovered_via: "inferred"` is drawn dashed, and inferred
  devices (a suspected unmanaged switch) get a dashed red outline. Do not promote a guess to a solid
  line to make the picture tidier.
- **Unreachable devices still appear**, dashed, with the reason on the box. A device you could not
  log into is part of the network and leaving it out makes the map a lie.
- **`role` drives the layers**, left to right: `gateway`/`router`/`firewall` →
  `l3-switch`/`controller` → `switch` → `ap`/`server`/`nas`/`nvr` → everything else.
- **Port names sit above a link, the link's own label below it.** A short run between two adjacent
  ranks would otherwise print the port name straight through the speed label.

### Internet uplinks carry the operator's mark

Each WAN box shows the ISP's own wordmark next to its name, matched from `wan_links[].isp` against
`assets/logos/isp-<slug>.svg`. Common Thai operators resolve through an alias table, so "AIS Fibre",
"True Online" and "3BB Fiber" all find the right mark. An operator with no file gets a lettered chip
— never a blank.

```bash
python3 <TOOLKIT>/scripts/netwalk_logos.py isp                       # the built-in set
python3 <TOOLKIT>/scripts/netwalk_logos.py isp "Fibre Co" --colour '#009688'
```

Get the real operator names from the device rather than guessing: on RouterOS the PPPoE client
interfaces usually carry them as comments (`/interface pppoe-client print detail`), which also gives
you the contracted speed. Read that, put it in `wan_links[].isp` and `link_speed`, and keep the PPPoE
account names out of the record — those are credentials.

### Logos

`<TOOLKIT>/assets/logos/<vendor>.svg`, 24×24 viewBox, one path or text element, monochrome so it
can inherit the theme colour. Omada devices come back as `vendor: "tplink"`, which the fetched logo set already covers.
To add a vendor, drop in `<vendor>.svg` matching the `vendor` string
in the record (or add an alias in `LOGO_ALIAS` in `netwalk_map.py`). No logo is not an error — the
device gets a lettered chip.

### If it looks wrong

- **Boxes overlapping or the picture is enormous** — usually many devices in one rank because
  `role` is missing or everything is `unknown`. Fix the roles.
- **Very tall (left to right) or very wide (top down)** — one rank holds far more devices than the
  others. Check the AP grouping did what you expected, then consider the other orientation.
- **A device floating with no links** — no `topology_edges` entry references it. Either you did not
  derive the edge, or it genuinely is not connected to anything you scanned; say which.
- **Wrong parent** — a discovery frame seen on a bridge/VLAN interface was recorded as a direct
  link. Prefer the physical port when the neighbour output names one.
- **Text clipped** — long hostnames are truncated on purpose to keep boxes uniform; the full name is
  in the report's inventory table.


## `netwalk-fullreport`

> Turn a netwalk scan record into a single self-contained HTML network report a site owner can be handed. Includes summary, method and coverage, embedded topology diagram, device inventory, per-device interfaces/VLANs/wireless/services/health, findings with evidence and recommendations, and the full log of commands run. Has a --public mode that strips internal detail. Use when the user asks for a network report, audit document, site survey writeup or something to deliver to a client.

## netwalk-fullreport

Part of the **netwalk** read-only network survey toolkit. Toolkit lives at `<TOOLKIT>`.

This produces the thing that leaves the building. Treat it accordingly.

### Run it

```bash
T=<TOOLKIT>
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

### Full vs public

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

### The credential sweep

Before rendering, the record is swept for anything that looks like a secret — keys named
`password`, `token`, `secret`, `community`, `psk`, `key_path` and friends, plus values containing
private-key blocks, `password=` assignments, community strings under any prefix, or Cisco `secret`
hashes. If anything matches, **the render is refused** with the exact JSON path.

**This guarantee has failed once, so do not treat it as the only line of defence.** The pattern for
community strings was anchored on the word `snmp`, an evidence excerpt read `trap-community: <value>`,
and the report rendered and was delivered with the string in it. The pattern is fixed and tested in
both directions now, but the lesson stands: the sweep catches shapes it knows. **Read the evidence
excerpts you write.** An excerpt exists to show the one line that proves a finding — if that line
happens to carry a value as well as a fact, cut the value out before it reaches the record.

If the user asks for the credentials so they can write up the site, that is a fair request and the
answer is not the report: `netwalk_cred.py export` writes them a separate 0600 access document, which
by default carries the addresses, accounts and routes in without any secret values. The report stays
clean either way.

When that fires, fix the record — do not weaken the check. A secret in a customer-facing report is
the one failure in this toolkit that cannot be walked back once the file is sent.

### Before you hand it over

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

### Regenerating

The record is the source of truth. Never hand-edit the HTML — change the record and re-render, or
the next run silently discards your edit. The renderer is deterministic, so two scans of one site
produce diffable reports and a changed report means a changed network.

### Telling the user what they got

Give them the paths, say which mode each file is, and say plainly what is missing. If the crawl
stopped early or three devices were unreachable, that goes in your message as well as in the
report — do not let a polished document imply a completeness the scan did not have.

**Say where the survey left its sensitive files, every time.** The full report renders a *Where this
survey left sensitive files* box in the Method section — the path to the credential store, the path
to the config exports, and the fact that netwalk deletes neither of them by itself. Repeat it in
your message rather than assuming they read that box:

- `~/.netwalk/creds/<slug>.json` — the credentials they typed into the login form, plain JSON,
  file-permission protected and **not encrypted**. It survives the engagement until someone runs
  `netwalk_cred.py forget --site <slug> --with-configs`, on **every machine the survey ran from** — a survey driven
  from two boxes leaves two copies.
- `~/.netwalk/sites/<slug>/configs/` — full config exports, containing PSKs, SNMP communities and
  password hashes in clear text.

Then offer to clear the credential store there and then. If any of those credentials are sensitive,
say that deleting is not the same as rotating: the shred overwrites the file, which on an SSD or a
copy-on-write filesystem is not a guarantee. The box appears in the full copy only — a customer
reading the public copy has no business learning where the engineer keeps their passwords.

### Never

- Send or upload the report anywhere. Produce the file, hand over the path, let the user decide who
  sees it.
- Put credentials, config exports, PSKs or password hashes in it.
- Present a partial survey as a complete one.
