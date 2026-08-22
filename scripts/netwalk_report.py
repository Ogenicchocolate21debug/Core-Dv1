#!/usr/bin/env python3
"""Render a netwalk scan record into one self-contained HTML report.

  netwalk_report.py record.json -o report.html [--public] [--title "..."]

The report is deterministic: the same record always produces the same HTML, so two
scans of one site diff cleanly. Nothing is fetched at view time - the diagram, the
CSS and the fonts stack are all inline, so the file survives being emailed to a site
owner who opens it offline.

Before rendering, the record is swept for credential material. If anything that
looks like a secret is in there the render is REFUSED, because this is the file that
leaves the building.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netwalk_map  # noqa: E402
import netwalk_common as C  # noqa: E402

# ------------------------------------------------------------- secret sweep

FORBIDDEN_KEYS = re.compile(
    r"(pass(word|phrase)?|secret|token|api[_-]?key|private[_-]?key|key[_-]?path|"
    r"credential|psk|pre[_-]?shared|community|shared[_-]?key|wpa[_-]?key|auth[_-]?key|"
    r"enable[_-]?pass|bind[_-]?dn|client[_-]?secret)", re.I)

SECRET_VALUE_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bssh-(rsa|ed25519|dss)\s+AAAA[0-9A-Za-z+/=]{40,}"), "ssh key blob"),
    (re.compile(r"(?i)\bpassword\s*[:=]\s*\S+"), "an inline password= assignment"),
    (re.compile(r"(?i)\bwpa[-_ ]?(psk|passphrase)\s*[:=]\s*\S+"), "a wireless pre-shared key"),
    (re.compile(r"(?i)\bsnmp[- ]?community\s*[:=]?\s*\S+"), "an SNMP community string"),
    (re.compile(r"(?i)\bsecret\s+\d?\s*\$?\d?\$\S+"), "a Cisco enable secret hash"),
]


def sweep(node, path: str = "$") -> list[str]:
    """Walk the record and report anything that must not reach a customer."""
    hits: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            here = f"{path}.{k}"
            if FORBIDDEN_KEYS.search(str(k)) and v not in (None, "", [], {}):
                hits.append(f"{here}  (key name looks like a secret)")
            hits += sweep(v, here)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            hits += sweep(v, f"{path}[{i}]")
    elif isinstance(node, str):
        for pat, what in SECRET_VALUE_PATTERNS:
            if pat.search(node):
                hits.append(f"{path}  (value contains {what})")
                break
    return hits


# ------------------------------------------------------------------ helpers

def esc(v) -> str:
    return html.escape("" if v is None else str(v))


def num(v, unit: str = "", digits: int = 0) -> str:
    if v is None:
        return "—"
    try:
        f = float(v)
    except (TypeError, ValueError):
        return esc(v)
    return f"{f:,.{digits}f}{unit}"


def mb(v) -> str:
    if v is None:
        return "—"
    v = float(v)
    return f"{v/1024:.1f} GB" if v >= 1024 else f"{v:.0f} MB"


def bps(v) -> str:
    if v is None:
        return "—"
    v = float(v)
    for lim, suf in ((1e9, "Gbps"), (1e6, "Mbps"), (1e3, "kbps")):
        if v >= lim:
            return f"{v/lim:.1f} {suf}"
    return f"{v:.0f} bps"


def pct(used, total):
    if not total:
        return None
    return 100.0 * float(used) / float(total)


def table(headers: list[str], rows: list[list[str]], empty: str = "nothing recorded") -> str:
    if not rows:
        return f'<p class="empty">{esc(empty)}</p>'
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# -------------------------------------------------------------------- pieces

def sec_summary(rec: dict, findings: list[dict], public: bool) -> str:
    devs = rec.get("devices", [])
    reach = [d for d in devs if d.get("reachable")]
    counts = Counter(f.get("severity", "info") for f in findings)
    roles = Counter(d.get("role", "unknown") for d in devs)

    stats = [("Devices found", str(len(devs))),
             ("Reached and read", str(len(reach))),
             ("Links mapped", str(len(rec.get("topology_edges", [])))),
             ("Internet uplinks", str(len(rec.get("wan_links", []))))]
    if findings:
        stats.append(("Findings", str(len(findings))))
    cards = "".join(f'<div class="stat"><div class="k">{esc(v)}</div>'
                    f'<div class="l">{esc(k)}</div></div>' for k, v in stats)

    sev = "".join(
        f'<span class="pill sev-{s}">{counts[s]} {s}</span>'
        for s in ("critical", "high", "medium", "low", "info") if counts[s])
    mix = ", ".join(f"{n}× {r}" for r, n in roles.most_common())

    top = [f for f in findings if f.get("severity") in ("critical", "high")][:5]
    if top:
        lead = ("<p>The findings that would change something if acted on this week:</p><ol class=\"lead\">"
                + "".join(f'<li><b>{esc(f.get("title"))}</b>'
                          f'{" — " + esc(f.get("host_id")) if f.get("host_id") else ""}</li>'
                          for f in top) + "</ol>")
    elif findings:
        lead = "<p>Nothing critical or high severity was found. The remaining items are listed below.</p>"
    else:
        lead = "<p>No findings were recorded for this scan.</p>"

    return f"""<section id="summary"><h2>Summary</h2>
<div class="stats">{cards}</div>
{f'<p class="pills">{sev}</p>' if sev else ''}
<p class="muted">Device mix: {esc(mix) or '—'}</p>
{lead}</section>"""


def sec_method(rec: dict, public: bool) -> str:
    site = rec.get("site", {})
    cov = rec.get("coverage") or {}
    ep = rec.get("entry_point") or {}
    rows = []
    if site.get("customer"):
        rows.append(("Customer", esc(site["customer"])))
    if site.get("address"):
        rows.append(("Site", esc(site["address"])))
    if site.get("engineer") and not public:
        rows.append(("Engineer", esc(site["engineer"])))
    if rec.get("scanned_at") and not public:
        rows.append(("Scanned", esc(rec["scanned_at"])))
    if ep.get("host_id"):
        rows.append(("Entry point", f'{esc(ep["host_id"])} ({esc(ep.get("ip",""))}, via {esc(ep.get("how","ssh"))})'))
    if site.get("scope_note"):
        rows.append(("Authorised scope", esc(site["scope_note"])))
    meta = "".join(f'<div class="kv"><dt>{k}</dt><dd>{v}</dd></div>' for k, v in rows)

    gaps = cov.get("not_covered") or []
    gap_html = ""
    if gaps or cov.get("stopped_early"):
        items = list(gaps)
        if cov.get("stopped_early"):
            items.insert(0, f"The crawl stopped before it ran out of neighbours: "
                            f"{cov.get('stopped_reason') or 'reason not recorded'}")
        gap_html = ('<div class="callout"><h3>What this report does not cover</h3><ul>'
                    + "".join(f"<li>{esc(g)}</li>" for g in items) + "</ul></div>")

    return f"""<section id="method"><h2>How this was produced</h2>
<dl class="meta">{meta}</dl>
<div class="callout ok"><h3>Read-only, enforced in code</h3>
<p>Every command in this survey was checked against a read-only allowlist before it was sent,
and anything that writes configuration, clears a counter, or restarts a service was refused by
the tool rather than by convention. No device configuration was changed. Configuration was
<i>exported</i> for reading; nothing was imported.</p></div>
{sec_artefacts(rec, public)}
{gap_html}</section>"""


def sec_artefacts(rec: dict, public: bool) -> str:
    """Where the sensitive by-products of this survey are sitting, on whose machine.

    The report is the thing people keep; the credential store and the config exports are
    the things they forget. A survey that hands over a polished document and leaves a
    plaintext credential file on an engineer's laptop, unmentioned, has moved the risk
    rather than reported it. Paths only - never a value, and never in the public copy.
    """
    if public:
        return ""
    slug = C.slugify(str((rec.get("site") or {}).get("id") or "")) if rec.get("site") else ""
    if not slug:
        return ""
    creds = C.creds_dir() / f"{slug}.json"
    exports = [d for d in (rec.get("devices") or []) if d.get("config_export_path")]
    lines = [
        f"<li><b>Credentials</b> — <code>{esc(creds)}</code>. Plain JSON, readable only by "
        f"the account that ran the survey. netwalk never deletes this on its own: remove it "
        f"with <code>netwalk_cred.py forget --site {esc(slug)}</code> when the engagement is "
        f"over. Deletion overwrites the file first, which is not a forensic wipe on an SSD — "
        f"if any of these credentials matter, rotate them rather than trusting the delete.</li>",
    ]
    if exports:
        lines.append(
            f"<li><b>Configuration exports</b> — {len(exports)} file(s) under "
            f"<code>{esc(C.site_dir(slug) / 'configs')}</code>. These contain PSKs, SNMP "
            f"communities and password hashes in clear text. They are deliberately not part "
            f"of this report; do not forward them.</li>")
    return ('<div class="callout"><h3>Where this survey left sensitive files</h3>'
            '<p>On the machine that ran the survey, not on your equipment:</p><ul>'
            + "".join(lines) + "</ul></div>")


def sec_diagram(rec: dict, public: bool) -> str:
    try:
        svg = netwalk_map.render(rec, public=public, standalone=False)
    except Exception as e:  # noqa: BLE001
        return f'<section id="diagram"><h2>Topology</h2><p class="empty">diagram failed: {esc(e)}</p></section>'
    return f"""<section id="diagram"><h2>Topology</h2>
<p class="muted">Reads left to right, the way traffic travels. Solid links were seen by LLDP, CDP or
MNDP; dashed links are inferred — something is physically there that does not announce itself.
Access points are grouped per switch, with their count and address range; every one of them is
listed individually in the inventory below.</p>
<div class="diagbar">
  <button type="button" id="diagopen">Open full size &#8599;</button>
  <span class="hint">Scaled to the page. Click the diagram to open it full size in a new tab.</span>
</div>
<div class="scroll diagram fit" id="diagwrap" title="Click to open full size in a new tab">{svg}</div>
<script>
(function(){{
  var w=document.getElementById('diagwrap'), b=document.getElementById('diagopen');
  if(!w||!b) return;
  var svg=w.querySelector('svg');
  function openFull(){{
    if(!svg) return;
    // about:blank is same-origin, so this works from a file:// copy of the report and
    // from a mail client temp folder. A blob: URL does not, reliably.
    var t=window.open('','_blank');
    if(!t){{ alert('The browser blocked the new tab. Allow pop-ups for this page.'); return; }}
    var title=(document.title||'network diagram').replace(/[<>]/g,'');
    t.document.write('<!doctype html><html><head><meta charset="utf-8"><title>'+title+
      '</title><style>html,body{{margin:0;background:#fff}}'+
      '@media(prefers-color-scheme:dark){{html,body{{background:#0e1116}}}}'+
      'svg{{display:block;margin:0 auto}}</style></head><body>'+
      svg.outerHTML+'</body></html>');
    t.document.close();
  }}
  b.addEventListener('click', openFull);
  w.addEventListener('click', openFull);
}})();
</script>
</section>"""


def sec_inventory(rec: dict) -> str:
    rows = []
    for d in sorted(rec.get("devices", []), key=lambda d: (netwalk_map.ROLE_RANK.get(d.get("role", "unknown"), 9),
                                                           d.get("host_id", ""))):
        h = d.get("health") or {}
        cpu = f'{h["cpu_load_pct"]:g}%' if h.get("cpu_load_pct") is not None else "—"
        p = pct(h.get("memory_used_mb") if h.get("memory_used_mb") is not None
                else (h["memory_total_mb"] - h["memory_free_mb"]) if h.get("memory_total_mb") and h.get("memory_free_mb") is not None else None,
                h.get("memory_total_mb"))
        mem = f"{p:.0f}%" if p is not None else "—"
        state = ('<span class="ok-dot">reached</span>' if d.get("reachable")
                 else f'<span class="bad-dot">{esc(d.get("unreachable_reason") or "not reached")}</span>')
        rows.append([
            f'<b>{esc(d.get("hostname") or d.get("host_id"))}</b>',
            f'<code>{esc(d.get("mgmt_ip") or "—")}</code>',
            esc(d.get("vendor") or "—"),
            esc(d.get("model") or "—"),
            esc(d.get("os_version") or d.get("firmware") or "—"),
            esc(netwalk_map.ROLE_LABEL.get(d.get("role", "unknown"), d.get("role", "—")).title()),
            esc(d.get("uptime") or "—"), cpu, mem, state,
        ])
    return (f'<section id="inventory"><h2>Device inventory</h2>'
            + table(["Host", "Management IP", "Vendor", "Model", "Version", "Role",
                     "Uptime", "CPU", "RAM", "Status"], rows, "no devices in this record")
            + "</section>")


def device_block(d: dict, public: bool) -> str:
    parts = []
    hid = d.get("hostname") or d.get("host_id")
    sub = " · ".join(x for x in [d.get("mgmt_ip"), d.get("vendor"), d.get("model"),
                                 d.get("os_version") or d.get("firmware")] if x)
    parts.append(f'<h3 id="dev-{esc(d.get("host_id"))}">{esc(hid)}'
                 f'<span class="hsub">{esc(sub)}</span></h3>')

    h = d.get("health") or {}
    if h:
        cells = []
        if h.get("cpu_load_pct") is not None:
            cells.append(("CPU", f'{h["cpu_load_pct"]:g}%', float(h["cpu_load_pct"]) >= 80))
        used = h.get("memory_used_mb")
        if used is None and h.get("memory_total_mb") and h.get("memory_free_mb") is not None:
            used = h["memory_total_mb"] - h["memory_free_mb"]
        p = pct(used, h.get("memory_total_mb"))
        if p is not None:
            cells.append(("Memory", f'{p:.0f}% of {mb(h["memory_total_mb"])}', p >= 85))
        if h.get("storage_total_mb") and h.get("storage_free_mb") is not None:
            sp = 100 * (1 - h["storage_free_mb"] / h["storage_total_mb"])
            cells.append(("Storage", f'{sp:.0f}% of {mb(h["storage_total_mb"])}', sp >= 85))
        if h.get("temperature_c") is not None:
            cells.append(("Temperature", f'{h["temperature_c"]:g} °C', float(h["temperature_c"]) >= 65))
        if h.get("poe_budget_w"):
            pp = pct(h.get("poe_used_w"), h["poe_budget_w"]) or 0
            cells.append(("PoE", f'{num(h.get("poe_used_w"),"W")} of {num(h["poe_budget_w"],"W")}', pp >= 85))
        if h.get("session_count") is not None:
            sp = pct(h["session_count"], h.get("session_max"))
            cells.append(("Sessions", f'{num(h["session_count"])}'
                                      + (f' of {num(h["session_max"])}' if h.get("session_max") else ""),
                          bool(sp and sp >= 80)))
        if cells:
            parts.append('<div class="stats small">' + "".join(
                f'<div class="stat{" hot" if hot else ""}"><div class="k">{esc(v)}</div>'
                f'<div class="l">{esc(k)}</div></div>' for k, v, hot in cells) + "</div>")

    ifaces = d.get("interfaces") or []
    if ifaces:
        rows = []
        for i in ifaces:
            link = ('<span class="ok-dot">up</span>' if i.get("link_up")
                    else '<span class="bad-dot">down</span>' if i.get("link_up") is False
                    else "—")
            if i.get("admin_up") is False:
                link = '<span class="muted">disabled</span>'
            errs = sum(float(i.get(k) or 0) for k in ("rx_errors", "tx_errors", "crc_errors"))
            errcell = f'<b class="bad">{num(errs)}</b>' if errs else "0"
            flaps = i.get("link_downs")
            flapcell = f'<b class="bad">{flaps}</b>' if flaps and int(flaps) > 3 else (str(flaps) if flaps is not None else "—")
            macs = i.get("mac_table") or []
            rows.append([f'<code>{esc(i.get("name"))}</code>', esc(i.get("alias") or "—"), link,
                         esc(i.get("speed") or "—"),
                         ", ".join(esc(x) for x in (i.get("ips") or [])) or "—",
                         bps(i.get("rx_bps")), bps(i.get("tx_bps")), errcell, flapcell,
                         str(len(macs)) if macs else "—"])
        parts.append("<h4>Interfaces</h4>" + table(
            ["Port", "Description", "Link", "Speed", "IP", "Rx", "Tx", "Errors", "Flaps", "MACs"], rows))

    vlans = d.get("vlans") or []
    if vlans:
        rows = [[str(v.get("id", "—")), esc(v.get("name") or "—"), esc(v.get("subnet") or "—"),
                 ", ".join(esc(p) for p in (v.get("tagged_ports") or [])) or "—",
                 ", ".join(esc(p) for p in (v.get("untagged_ports") or [])) or "—"] for v in vlans]
        parts.append("<h4>VLANs</h4>" + table(["ID", "Name", "Subnet", "Tagged", "Untagged"], rows))

    wl = d.get("wireless_networks") or []
    if wl:
        rows = []
        for w in wl:
            secu = w.get("security") or "unknown"
            secc = f'<b class="bad">{esc(secu)}</b>' if secu in ("open", "wep", "wpa-personal") else esc(secu)
            iso = w.get("client_isolation")
            isoc = ("—" if iso is None else
                    '<span class="ok-dot">on</span>' if iso else '<b class="bad">off</b>')
            rows.append([f'<b>{esc(w.get("ssid"))}</b>', esc(w.get("band") or "—"),
                         esc(w.get("channel") or "—"), esc(w.get("width") or "—"), secc,
                         str(w.get("vlan") if w.get("vlan") is not None else "—"),
                         str(w.get("clients") if w.get("clients") is not None else "—"),
                         "yes" if w.get("guest") else "—", isoc])
        parts.append("<h4>Wireless</h4>" + table(
            ["SSID", "Band", "Channel", "Width", "Security", "VLAN", "Clients", "Guest", "Isolation"], rows))

    svcs = d.get("services") or []
    if svcs:
        rows = []
        for s in svcs:
            st = s.get("state", "unknown")
            stc = (f'<span class="ok-dot">{esc(st)}</span>' if st == "running"
                   else f'<b class="bad">{esc(st)}</b>' if st in ("failed", "degraded") else esc(st))
            rows.append([f'<code>{esc(s.get("name"))}</code>', stc,
                         "yes" if s.get("enabled") else "—",
                         str(s.get("restarts") if s.get("restarts") is not None else "—"),
                         ", ".join(esc(x) for x in (s.get("listen") or [])) or "—",
                         esc(s.get("note") or "")])
        parts.append("<h4>Services</h4>" + table(
            ["Service", "State", "Enabled", "Restarts", "Listening on", "Note"], rows))

    logs = d.get("log_excerpts") or []
    if logs:
        rows = [[esc(l.get("at") or "—"), esc(l.get("severity") or "—"), esc(l.get("topic") or "—"),
                 f'<code>{esc(l.get("message"))}</code>',
                 str(l.get("count")) if l.get("count") else "—"] for l in logs[:80]]
        parts.append("<h4>Log excerpts</h4>" + table(["When", "Severity", "Topic", "Message", "Repeats"], rows))

    exp = d.get("mgmt_exposure") or {}
    if exp and not public:
        bits = []
        if exp.get("services"):
            bits.append("Answering: " + ", ".join(f"<code>{esc(s)}</code>" for s in exp["services"]))
        if exp.get("reachable_from_wan"):
            bits.append('<b class="bad">Reachable from the internet: '
                        + ", ".join(esc(s) for s in exp["reachable_from_wan"]) + "</b>")
        if exp.get("note"):
            bits.append(esc(exp["note"]))
        parts.append("<h4>Management exposure</h4><p>" + "<br>".join(bits) + "</p>")

    if d.get("config_export_path"):
        parts.append(f'<p class="muted">Configuration exported to '
                     f'<code>{esc(d["config_export_path"])}</code> (read-only dump, kept with the scan record).</p>')
    return '<article class="device">' + "".join(parts) + "</article>"


def sec_devices(rec: dict, public: bool) -> str:
    devs = [d for d in rec.get("devices", []) if d.get("reachable")]
    if not devs:
        return ""
    devs.sort(key=lambda d: (netwalk_map.ROLE_RANK.get(d.get("role", "unknown"), 9), d.get("host_id", "")))
    return ('<section id="devices"><h2>Device detail</h2>'
            + "".join(device_block(d, public) for d in devs) + "</section>")


def sec_findings(findings: list[dict], public: bool) -> str:
    if not findings:
        return ('<section id="findings"><h2>Findings</h2>'
                '<p class="empty">No findings were recorded.</p></section>')
    out = []
    for f in findings:
        sev = f.get("severity", "info")
        conf = f.get("confidence")
        ev = f.get("evidence") or []
        ev_html = ""
        if ev and not public:
            ev_html = ('<details class="evidence"><summary>Evidence '
                       f'({len(ev)})</summary><dl>'
                       + "".join(f'<dt><code>{esc(e.get("source"))}</code></dt>'
                                 f'<dd><pre>{esc(e.get("excerpt") or "")}</pre></dd>' for e in ev)
                       + "</dl></details>")
        out.append(f"""<article class="finding sev-{esc(sev)}">
<header><span class="pill sev-{esc(sev)}">{esc(sev)}</span>
{f'<span class="pill cat">{esc(f.get("category"))}</span>' if f.get("category") else ''}
{f'<span class="pill conf">{esc(conf)}</span>' if conf else ''}
<h3>{esc(f.get("title"))}</h3>
{f'<p class="where">on <code>{esc(f.get("host_id"))}</code></p>' if f.get("host_id") else ''}</header>
{f'<p>{esc(f.get("detail"))}</p>' if f.get("detail") else ''}
{ev_html}
{f'<p class="rec"><b>Recommended:</b> {esc(f.get("recommendation"))}</p>' if f.get("recommendation") else ''}
</article>""")
    note = ('<p class="muted">Every recommendation below is a proposal. netwalk did not apply '
            'any of them — the site owner decides what changes and when.</p>')
    return f'<section id="findings"><h2>Findings and recommendations</h2>{note}{"".join(out)}</section>'


def _ip_key(host: dict):
    """Sort addresses numerically. String order puts .140 before .99 and looks broken."""
    import ipaddress  # noqa: PLC0415
    try:
        ip = ipaddress.ip_address(str(host.get("ip")))
        return (0, ip.version, ip.packed, "")
    except ValueError:
        return (1, 0, b"", str(host.get("ip")))


def _count(n, noun: str) -> str:
    n = n or 0
    return f"{num(n)} {noun}{'' if n == 1 else 'es' if noun.endswith('ss') else 's'}"


def sec_sweeps(rec: dict, public: bool) -> str:
    """What answered on the ranges the owner authorised - and what the method cannot see.

    The blind spots are printed next to the results on purpose. A list of open ports with
    no caveat reads as "this is everything that is open", which is never true of a TCP
    connect sweep.
    """
    sweeps = rec.get("sweeps") or []
    if not sweeps or public:
        # A per-address list of open ports is a shopping list. The public copy says a
        # sweep happened, in Method; it does not print the results.
        return ""
    blocks = []
    for s in sweeps:
        hosts = s.get("hosts") or []
        rows = []
        for h in sorted(hosts, key=_ip_key):
            ports = h.get("open_ports") or []
            rows.append([
                f'<code>{esc(h.get("ip"))}</code>',
                esc(", ".join(str(p) for p in ports) or "—"),
                esc(", ".join(h.get("services") or []) or "—"),
                "in the inventory" if h.get("in_record") else
                '<b class="bad">not identified</b>',
            ])
        unknown = sum(1 for h in hosts if not h.get("in_record"))
        head = (f'<h3>{esc(s.get("range"))}</h3>'
                f'<p class="muted">{esc(s.get("method") or "tcp-connect")}'
                f'{" through " + esc(s.get("via")) if s.get("via") else ""} · '
                f'{_count(s.get("addresses_probed"), "address")} probed · '
                f'{num(s.get("hosts_found"))} answered'
                f'{" · " + str(unknown) + " not in the inventory" if unknown else ""}</p>')
        auth = s.get("authorized_by")
        auth_html = (f'<p class="muted">Authorised by: {esc(auth)}</p>' if auth else
                     '<p class="muted"><b class="bad">No authorisation was recorded for this '
                     'sweep.</b></p>')
        blind = s.get("not_visible") or []
        blind_html = (f'<p class="muted">Not visible to this method: '
                      f'{esc(", ".join(blind))}.</p>' if blind else "")
        blocks.append(head + auth_html +
                      table(["Address", "Open TCP ports", "Services", "Known?"], rows,
                            "nothing on this range answered") + blind_html)
    intro = ('<p class="muted">A sweep only covers ranges the site owner explicitly '
             'authorised, and it opens a TCP connection and closes it again — nothing is '
             'sent to any service.</p>')
    return f'<section id="sweeps"><h2>Address sweep</h2>{intro}{"".join(blocks)}</section>'


def sec_evidence(rec: dict) -> str:
    log = rec.get("evidence_log") or []
    if not log:
        return ""
    rows = [[esc(e.get("at")), f'<code>{esc(e.get("host_id"))}</code>',
             f'<code>{esc(e.get("command"))}</code>',
             ('<b class="bad">blocked</b>' if e.get("blocked")
              else str(e.get("exit_code")) if e.get("exit_code") is not None else "—"),
             num(e.get("bytes_out"))] for e in log]
    return ('<section id="evidence"><h2>Command log</h2>'
            '<p class="muted">Everything netwalk ran on your equipment, in order. '
            'If a command is not in this list, it was not run.</p>'
            + table(["When", "Host", "Command", "Exit", "Bytes"], rows) + "</section>")


# ---------------------------------------------------------------------- CSS

CSS = """
:root{--bg:#f7f8fa;--card:#fff;--ink:#12151a;--muted:#5f6874;--line:#e1e6ec;
--accent:#1f6feb;--ok:#0f7b45;--okbg:#e9f7ef;--bad:#c0392b;--badbg:#fdecea;
--warn:#8a5a00;--warnbg:#fff6e5;--chip:#eef1f5;--code:#f2f4f7;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0e1116;--card:#161b22;
--ink:#e6eaf0;--muted:#98a4b3;--line:#252c36;--accent:#5b9dff;--ok:#4ade80;--okbg:#122a1d;
--bad:#ff7b6b;--badbg:#331a17;--warn:#ffd479;--warnbg:#2c2410;--chip:#212932;--code:#1b2129}}
:root[data-theme=dark]{--bg:#0e1116;--card:#161b22;--ink:#e6eaf0;--muted:#98a4b3;--line:#252c36;
--accent:#5b9dff;--ok:#4ade80;--okbg:#122a1d;--bad:#ff7b6b;--badbg:#331a17;--warn:#ffd479;
--warnbg:#2c2410;--chip:#212932;--code:#1b2129}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15.5px/1.62 var(--sans)}
.wrap{max-width:1120px;margin:0 auto;padding:32px 20px 80px}
header.cover{border-bottom:2px solid var(--line);padding-bottom:22px;margin-bottom:30px}
header.cover .eyebrow{font:600 11px var(--sans);letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin:0 0 6px}
header.cover h1{font-size:clamp(26px,4vw,38px);line-height:1.15;margin:0 0 8px;letter-spacing:-.02em}
header.cover p{margin:0;color:var(--muted)}
nav.toc{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 34px}
nav.toc a{font-size:13px;padding:6px 12px;border:1px solid var(--line);border-radius:99px;
background:var(--card);color:var(--ink);text-decoration:none}
nav.toc a:hover{border-color:var(--accent);color:var(--accent)}
section{margin:0 0 44px}
h2{font-size:22px;margin:0 0 14px;padding-bottom:8px;border-bottom:1px solid var(--line);letter-spacing:-.01em}
h3{font-size:17px;margin:26px 0 8px}
h4{font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:20px 0 8px}
p{margin:0 0 12px}
.muted{color:var(--muted)}
.empty{color:var(--muted);font-style:italic}
code{font:.88em var(--mono);background:var(--code);padding:1px 5px;border-radius:4px}
pre{font:12.5px/1.5 var(--mono);background:var(--code);padding:10px 12px;border-radius:8px;
overflow-x:auto;margin:4px 0 10px;white-space:pre-wrap;word-break:break-word}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:12px;margin:0 0 18px}
.stats.small{grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:8px;margin:10px 0 4px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.stat .k{font:600 20px var(--sans);letter-spacing:-.02em}
.stats.small .stat .k{font-size:15px}
.stat .l{font-size:12px;color:var(--muted);margin-top:2px}
.stat.hot{border-color:var(--bad);background:var(--badbg)}
.stat.hot .k{color:var(--bad)}
.pills{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 12px}
.pill{display:inline-block;font:600 11px var(--sans);padding:3px 9px;border-radius:99px;
background:var(--chip);color:var(--muted);letter-spacing:.02em}
.pill.sev-critical,.pill.sev-high{background:var(--badbg);color:var(--bad)}
.pill.sev-medium{background:var(--warnbg);color:var(--warn)}
.pill.sev-low,.pill.sev-info{background:var(--chip);color:var(--muted)}
ol.lead{margin:6px 0 0;padding-left:22px}
ol.lead li{margin:0 0 5px}
dl.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px 22px;margin:0 0 18px}
.kv dt{font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.kv dd{margin:2px 0 0}
.callout{border:1px solid var(--line);border-left:3px solid var(--warn);background:var(--warnbg);
border-radius:0 10px 10px 0;padding:12px 16px;margin:0 0 16px}
.callout.ok{border-left-color:var(--ok);background:var(--okbg)}
.callout h3{margin:0 0 6px;font-size:14px}
.callout p,.callout ul{margin:0;font-size:14px}
.callout ul{padding-left:20px}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--line);
border-radius:10px;background:var(--card);margin:0 0 14px}
.scroll.diagram{padding:14px}
/* Never shrink the diagram to fit the column. A site map squeezed from 3000px to
   1000px is legible only as a shape - the hostnames, IPs and port names, which are
   the entire reason to look at it, become unreadable. It renders at full size and
   scrolls inside its own box instead. */
/* margin:0, not auto: centring an over-wide child inside a scroll box pushes its
   left edge out of reach, and the left edge is where the diagram starts. */
.scroll.diagram{cursor:zoom-in}
.scroll.diagram svg{max-width:none;width:auto;height:auto;display:block;margin:0}
/* Fitted is the default inside the report: the page should read as a page. Full size
   lives one click away in its own tab, where it has room to be legible. */
.scroll.diagram.fit{overflow-x:hidden}
.scroll.diagram.fit svg{max-width:100%;height:auto;margin:0 auto}
.diagbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:0 0 10px}
.diagbar button{font:600 12.5px var(--sans);padding:6px 12px;border-radius:99px;
border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer}
.diagbar button:hover{border-color:var(--accent);color:var(--accent)}
.diagbar .hint{font-size:12.5px;color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{text-align:left;font:600 11.5px var(--sans);text-transform:uppercase;letter-spacing:.05em;
color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
.ok-dot::before,.bad-dot::before{content:"\\25CF";margin-right:5px}
.ok-dot{color:var(--ok)}.bad-dot{color:var(--bad)}
b.bad,.bad{color:var(--bad)}
article.device{border:1px solid var(--line);border-radius:12px;background:var(--card);
padding:4px 18px 18px;margin:0 0 18px}
article.device h3{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px}
.hsub{font:400 13px var(--mono);color:var(--muted)}
article.finding{border:1px solid var(--line);border-left:3px solid var(--muted);border-radius:0 12px 12px 0;
background:var(--card);padding:14px 18px;margin:0 0 12px}
article.finding.sev-critical,article.finding.sev-high{border-left-color:var(--bad)}
article.finding.sev-medium{border-left-color:var(--warn)}
article.finding header{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:0 0 6px}
article.finding h3{margin:0;font-size:16px;flex:1 1 260px}
.where{margin:0;font-size:13px;color:var(--muted)}
.rec{margin:8px 0 0;padding:9px 12px;background:var(--chip);border-radius:8px;font-size:14px}
details.evidence{margin:8px 0 0}
details.evidence summary{cursor:pointer;font-size:13px;color:var(--muted)}
details.evidence dl{margin:8px 0 0}
details.evidence dt{font-size:12.5px;margin:8px 0 2px}
footer{border-top:1px solid var(--line);padding-top:16px;color:var(--muted);font-size:13px}
@media print{body{background:#fff}nav.toc{display:none}.scroll{overflow:visible}
section{break-inside:avoid}article.finding,article.device{break-inside:avoid}}
"""


def render(rec: dict, public: bool = False, title: str | None = None) -> str:
    site = rec.get("site", {})
    findings = [f for f in (rec.get("findings") or [])
                if not (public and f.get("public_safe") is False)]
    findings.sort(key=lambda f: (SEV_ORDER.get(f.get("severity", "info"), 9), f.get("host_id") or ""))

    name = title or site.get("name") or site.get("id") or "Network survey"
    parts = [sec_summary(rec, findings, public), sec_method(rec, public),
             sec_diagram(rec, public), sec_inventory(rec),
             sec_devices(rec, public), sec_sweeps(rec, public),
             sec_findings(findings, public)]
    if not public:
        parts.append(sec_evidence(rec))

    toc = [("summary", "Summary"), ("method", "Method"), ("diagram", "Topology"),
           ("inventory", "Inventory"), ("devices", "Device detail")]
    if rec.get("sweeps") and not public:
        toc.append(("sweeps", "Address sweep"))
    toc.append(("findings", "Findings"))
    if not public and rec.get("evidence_log"):
        toc.append(("evidence", "Command log"))
    nav = "".join(f'<a href="#{i}">{esc(t)}</a>' for i, t in toc)

    stamp = "" if public else f' · {esc(rec.get("scanned_at",""))}'
    mode = "Public copy — hardening detail and the command log are omitted." if public else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(name)} — network survey</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<header class="cover">
  <p class="eyebrow">Network survey{stamp}</p>
  <h1>{esc(name)}</h1>
  <p>{esc(site.get("customer") or "")}{" · " if site.get("customer") and site.get("address") else ""}{esc(site.get("address") or "")}</p>
  {f'<p class="muted">{esc(mode)}</p>' if mode else ''}
</header>
<nav class="toc">{nav}</nav>
{"".join(parts)}
<footer><p>Produced by <b>netwalk</b> — a read-only network survey toolkit.
No configuration on any surveyed device was modified.</p></footer>
</div>
</body>
</html>"""


def main() -> int:
    ap = argparse.ArgumentParser(prog="netwalk_report.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("record")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--public", action="store_true",
                    help="copy for the site owner: no command log, no scan date, "
                         "no findings marked public_safe=false")
    ap.add_argument("--title")
    args = ap.parse_args()

    with open(args.record, encoding="utf-8") as fh:
        rec = json.load(fh)

    leaks = sweep(rec)
    if leaks:
        print("REFUSING TO RENDER - the scan record contains credential material.\n"
              "This file is meant to leave the building; fix the record first.\n",
              file=sys.stderr)
        for h in leaks[:25]:
            print(f"  {h}", file=sys.stderr)
        if len(leaks) > 25:
            print(f"  ... and {len(leaks)-25} more", file=sys.stderr)
        return 5

    html_out = render(rec, public=args.public, title=args.title)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html_out)
    print(f"wrote {args.out} ({len(html_out):,} bytes, "
          f"{len(rec.get('devices', []))} device(s), "
          f"{len(rec.get('findings') or [])} finding(s)"
          f"{', PUBLIC copy' if args.public else ''})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
