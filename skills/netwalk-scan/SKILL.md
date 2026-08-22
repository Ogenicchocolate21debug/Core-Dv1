---
name: netwalk-scan
description: "Discover and map a network read-only, starting from one device the user names. Crawls outward hop by hop using LLDP, CDP, MNDP, ARP, DHCP leases, routing and MAC tables across MikroTik, Cisco, Aruba, HP, Fortinet, Juniper, Ubiquiti, Linux and Windows, and writes a structured scan record. Use when the user asks to scan, survey, crawl, inventory, audit or 'see everything on' a network or a site, theirs or a customer's."
---

# netwalk-scan

Part of the **netwalk** read-only network survey toolkit. Toolkit lives at `{{TOOLKIT}}`.

The goal is a complete, honest picture of the target network — and honesty includes writing down
what you could not reach. A survey that quietly stops at the first ring of neighbours and presents
itself as complete is worse than one that says "6 of 9 devices reached, here is why".

## Read-only, and it is enforced

Every command goes through `netwalk_exec.py`, which checks it against a per-vendor read-only
allowlist before it leaves the machine. Config writes, counter clears, service restarts, reboots
and shell metacharacters are refused by the tool. You never SSH to a surveyed device directly —
always go through the wrapper, so the guarantee holds and every command lands in the evidence log.

If the gate blocks something you believe is genuinely read-only, do not work around it. Either pick
a different command, or add it to the allowlist in `scripts/netwalk_policy.py`, run
`python3 {{TOOLKIT}}/tests/test_policy.py`, and note the change. Never bypass the wrapper.

## Before you touch anything

Ask, and do not guess:

1. **What is the target?** An entry device (IP), a subnet, a site name, "my whole office"? You need
   at least one device you can log into. netwalk crawls *from* a device; it is not a port scanner
   and does not sweep ranges the user has not named.
2. **Whose network is it?** If it is a customer's, confirm the user is authorised to log into this
   equipment today. Record what they say in `site.scope_note` — it goes in the report.
3. **Anything off limits?** Production boxes that must not even be logged into, a maintenance
   window, a device that falls over when you open a session. Respect it and record it under
   `coverage.not_covered`.
4. **How far?** Default is exhaustive: keep hopping until every reachable neighbour has been
   visited. On a big site, say up front roughly how many hops that might be and check in.

Pick a site slug (`acme-hq`). Everything for the engagement lands in `~/.netwalk/sites/<slug>/` — outside the installed toolkit, so an upgrade cannot delete it.

## The shape of the whole thing

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

Run the form once per round with **every** device discovered in that round, not one at a time.
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
python3 {{TOOLKIT}}/scripts/netwalk_cred.py answers --site acme-hq
```

Keep going until a round turns up no device the user has not already ruled on. That is the
termination condition — not "enough devices", and not "the first ring of neighbours".

## The loop

For each device, in this order:

1. **Get in.** No credential yet → hand off to `netwalk-login`. Confirm with:
   `python3 {{TOOLKIT}}/scripts/netwalk_exec.py probe --site <slug> --host <id>`

2. **Identify the vendor** before running anything else. The probe output usually tells you.
   Wrong vendor means wrong commands and a pile of syntax errors that look like access problems.

3. **Run the discovery pack** for that vendor:

   ```bash
   python3 {{TOOLKIT}}/scripts/netwalk_exec.py run \
     --site acme-hq --host gw01 \
     --cmd-file {{TOOLKIT}}/scripts/packs/mikrotik.discovery.txt \
     --evidence ~/.netwalk/sites/acme-hq/evidence.jsonl
   ```

   Packs exist for `mikrotik`, `cisco`, `aruba`, `hp`, `fortinet`, `linux`, `windows`. For a vendor
   with no pack, use the `unknown` profile (`show`/`display`/`get`/`print` only) and add commands
   one at a time with `--cmd`, checking each with `netwalk_exec.py check --vendor ... --cmd ...`.
   Some commands in a pack will not exist on a given model — a failed command is normal, not a
   reason to stop.

   For a **config export**, always add `--out <file>`. That writes the full text to a 0600 file
   and prints only a summary — a config is full of PSKs, community strings and password hashes, and
   anything printed reaches you, the model API and the transcript. Secret-shaped values in printed
   output are masked as `<redacted>` as a backstop, but `--out` is the actual control.

4. **Map the output into the scan record**, `~/.netwalk/sites/<slug>/scan-<YYYY-MM-DD>.json`, against
   `{{TOOLKIT}}/schema/netwalk-record.schema.json`. Per device, capture at minimum:

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

## Deriving topology

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

## Keep the artefacts fresh as you go

After each hop or small batch, re-run the map and report rather than waiting for the crawl to end:

```bash
python3 {{TOOLKIT}}/scripts/netwalk_map.py    ~/.netwalk/sites/acme-hq/scan-2026-08-22.json -o ~/.netwalk/sites/acme-hq/map.svg
python3 {{TOOLKIT}}/scripts/netwalk_report.py ~/.netwalk/sites/acme-hq/scan-2026-08-22.json -o ~/.netwalk/sites/acme-hq/report.html
```

A partial map beats no map, and the user can correct a wrong assumption at hop 2 instead of hop 9.

## Fill in coverage before you finish

`coverage.not_covered` is not optional. Write down anything a reader could reasonably assume was
checked and was not: subnets never entered, a Wi-Fi RF survey that did not happen, a device the user
asked you to leave alone, a vendor whose CLI you could only partly read. This is the section that
keeps the report honest.

## Never

- Change configuration. Report the fix; the site owner applies it.
- Scan an address range the user did not name, or hop into a device outside the agreed scope.
- Put a credential anywhere in the scan record.
- Present an incomplete crawl as complete.

Next: `netwalk-diag` for health and root cause, `netwalk-map` for the diagram,
`netwalk-fullreport` for the deliverable.
