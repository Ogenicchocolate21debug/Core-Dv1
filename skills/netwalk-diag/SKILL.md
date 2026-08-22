---
name: netwalk-diag
description: "Read a network device or Linux/Windows server end to end and work out what is wrong with it. Exports config read-only, collects CPU, memory, storage, temperature, PoE, interface counters, error and flap counts, throughput, sessions, services and logs, then reasons from that evidence to concrete findings with severity and recommendations. Use when the user asks what is wrong with a device or site, wants a health check, or has a symptom (slow, dropping, rebooting, flapping) to chase."
---

# netwalk-diag

Part of the **netwalk** read-only network survey toolkit. Toolkit lives at `{{TOOLKIT}}`.

`netwalk-scan` answers *what is out there*. This skill answers *what is wrong with it*.

## Read-only, and it is enforced

Config is **exported**, never imported or edited. Not one command changes device state — that
includes `clear counters`, `dmesg -C`, `systemctl restart` and `debug`, all of which the gate
refuses. If a device needs a change, that is a finding with a recommendation, and the site owner
decides. Run everything through `netwalk_exec.py` so the guarantee holds and the command lands in
the evidence log.

## 1. Collect

Assumes a credential exists (`netwalk-login`) and the vendor is known.

```bash
T={{TOOLKIT}}
python3 $T/scripts/netwalk_exec.py run --site acme-hq --host gw01 \
  --cmd-file $T/scripts/packs/mikrotik.config.txt \
  --out ~/.netwalk/sites/acme-hq/configs/gw01.conf \
  --evidence ~/.netwalk/sites/acme-hq/evidence.jsonl

python3 $T/scripts/netwalk_exec.py run --site acme-hq --host gw01 \
  --cmd-file $T/scripts/packs/mikrotik.health.txt \
  --evidence ~/.netwalk/sites/acme-hq/evidence.jsonl
```

Packs: `mikrotik`, `cisco`, `aruba`, `hp`, `fortinet`, `linux`, `windows`, each with a
`.config.txt` and a `.health.txt`. Record the exported config path in `config_export_path` —
relative to the site folder, never pasted into the report.

**Always use `--out` for a config export.** With `--out` the full text is written straight to a
0600 file and only a one-line summary is printed. Without it, the whole config comes back through
you — and a vendor config is packed with PSKs, SNMP communities, RADIUS secrets, password hashes and
container environment variables. Anything that reaches you is transmitted to a model API and written
into the session transcript, and neither can be un-sent.

`netwalk_exec.py` masks secret-shaped values in whatever it prints (`<redacted>`), so an accidental
read is survivable — but that is a safety net, not the control. The control is `--out`.

Record the export path in `config_export_path`. Never `cat` it, never paste it into the record, and
warn the user before they forward it to anyone.

### What to pull, whatever the vendor

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

## 2. Analyse — evidence first

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

Security observations belong here too — management services answering on a WAN interface, default
or shared accounts, SNMP v1/v2c with a guessable community, an open or WEP SSID, a guest network
with no client isolation, unsupported firmware with known CVEs. Record them as findings with
`category: "security"`; mark anything you would not want in a customer-facing copy
`public_safe: false`.

## 3. Write findings into the record

Append to `findings[]` in the scan record (schema: `{{TOOLKIT}}/schema/netwalk-record.schema.json`):

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

## 4. Report back

Summarise for the user: what is broken now, what will break, what is only untidy — and say plainly
what the data does *not* explain. Then `netwalk-fullreport` turns it into the deliverable.

## Never

- Fix anything. Not even "while I'm in here" — an undocumented change during a survey is the worst
  kind of change.
- Clear a counter or a log. That destroys the evidence the next engineer needs.
- Report a finding you cannot point at evidence for.
- Copy a config export, PSK, community string or password hash into the report.
