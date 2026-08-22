#!/usr/bin/env python3
"""Render a netwalk scan record into a network diagram (SVG).

  netwalk_map.py record.json -o map.svg [--public] [--title "..."]

Layout is layered and deterministic: WAN links on top, then devices ranked by their
BFS depth from the gateway, ordered inside each rank by a barycentre pass so links
cross as little as possible. Same record in -> same SVG out, so a diff between two
scans is a diff of the network, not of the renderer's mood.

Every node carries what an engineer actually needs on a diagram: vendor logo,
hostname, management IP, model, OS version, and a live resource chip (CPU / RAM /
uptime). Links carry the port on each end and how they were discovered.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from collections import defaultdict, deque

HERE = os.path.dirname(os.path.abspath(__file__))
LOGO_DIR = os.path.join(os.path.dirname(HERE), "assets", "logos")

NODE_W, NODE_H = 216, 96
COL_GAP, ROW_GAP = 46, 108
PAD = 40
WAN_W, WAN_H = 200, 78

ROLE_RANK = {
    "gateway": 0, "router": 0, "firewall": 0,
    "l3-switch": 1, "controller": 1,
    "switch": 2, "unmanaged-switch": 2,
    "ap": 3, "server": 3, "nas": 3, "nvr": 3,
    "printer": 4, "ups": 4, "client": 4, "unknown": 4,
}
ROLE_LABEL = {
    "gateway": "GATEWAY", "router": "ROUTER", "firewall": "FIREWALL",
    "l3-switch": "L3 SWITCH", "switch": "SWITCH", "unmanaged-switch": "UNMANAGED?",
    "ap": "AP", "controller": "CONTROLLER", "server": "SERVER", "nas": "NAS",
    "nvr": "NVR", "printer": "PRINTER", "ups": "UPS", "client": "CLIENT", "unknown": "DEVICE",
}
LOGO_ALIAS = {
    "routeros": "mikrotik", "unifi": "ubiquiti", "edgeos": "ubiquiti", "ubnt": "ubiquiti",
    "hpe": "hp", "procurve": "hp", "aruba-cx": "aruba", "arubaos": "aruba",
    "ios": "cisco", "nx-os": "cisco", "meraki": "cisco", "dsm": "synology",
}


def esc(s) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def clip(s, n: int) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


# Rough advance widths. There is no text-measurement API when generating SVG offline,
# so these are per-character averages calibrated against the fonts in CSS. Counting
# characters instead is what let a GATEWAY badge sit on top of a hostname.
def text_w(s: str, px: float, mono: bool = False, tracking: float = 0.0) -> float:
    return len(str(s)) * (px * (0.60 if mono else 0.54) + tracking)


def fit(s: str, px: float, limit: float, mono: bool = False, tracking: float = 0.0) -> str:
    s = str(s or "")
    if text_w(s, px, mono, tracking) <= limit:
        return s
    per = px * (0.60 if mono else 0.54) + tracking
    return s[:max(3, int(limit / per) - 1)] + "\u2026"


# ------------------------------------------------------------------ logos

_logo_cache: dict[str, str | None] = {}


def logo_group(vendor: str | None, x: float, y: float, size: int = 26) -> str:
    key = LOGO_ALIAS.get((vendor or "").lower().strip(), (vendor or "").lower().strip())
    if key not in _logo_cache:
        path = os.path.join(LOGO_DIR, f"{key}.svg")
        inner = None
        if os.path.exists(path):
            raw = open(path, encoding="utf-8").read()
            m = re.search(r"<svg[^>]*viewBox=[\"']([^\"']+)[\"'][^>]*>(.*)</svg>", raw, re.S)
            if m:
                vb = [float(v) for v in m.group(1).split()]
                body = re.sub(r"<title>.*?</title>", "", m.group(2), flags=re.S).strip()
                inner = json.dumps([vb, body])
        _logo_cache[key] = inner
    packed = _logo_cache[key]
    if not packed:
        # No logo on file: a lettered chip beats a blank space.
        initial = (vendor or "?")[:1].upper()
        return (f'<g><rect class="logo-fallback" x="{x}" y="{y}" width="{size}" height="{size}" rx="6"/>'
                f'<text class="logo-initial" x="{x + size/2}" y="{y + size*0.72}">{esc(initial)}</text></g>')
    vb, body = json.loads(packed)
    scale = size / max(vb[2], vb[3])
    tx = x - vb[0] * scale
    ty = y - vb[1] * scale
    return f'<g class="logo" transform="translate({tx:.2f},{ty:.2f}) scale({scale:.4f})">{body}</g>'


# ------------------------------------------------------------------ layout

def build_layout(record: dict) -> tuple[list[dict], list[dict], dict]:
    devices = [d for d in record.get("devices", []) if d.get("host_id")]
    by_id = {d["host_id"]: d for d in devices}
    edges = [e for e in record.get("topology_edges", [])
             if e.get("a_host") in by_id and e.get("b_host") in by_id and e["a_host"] != e["b_host"]]

    adj = defaultdict(set)
    for e in edges:
        adj[e["a_host"]].add(e["b_host"])
        adj[e["b_host"]].add(e["a_host"])

    roots = [d["host_id"] for d in devices if d.get("role") in ("gateway", "router", "firewall")]
    entry = (record.get("entry_point") or {}).get("host_id")
    if entry in by_id and entry not in roots:
        roots.insert(0, entry)
    if not roots and devices:
        roots = [devices[0]["host_id"]]

    depth: dict[str, int] = {}
    q = deque()
    for r in roots:
        depth[r] = 0
        q.append(r)
    while q:
        cur = q.popleft()
        for nb in sorted(adj[cur]):
            if nb not in depth:
                depth[nb] = depth[cur] + 1
                q.append(nb)
    for d in devices:  # islands: fall back to what the role implies
        depth.setdefault(d["host_id"], ROLE_RANK.get(d.get("role", "unknown"), 4))

    rows: dict[int, list[str]] = defaultdict(list)
    for d in sorted(devices, key=lambda d: (depth[d["host_id"]], d["host_id"])):
        rows[depth[d["host_id"]]].append(d["host_id"])

    # barycentre passes - cheap, deterministic, and enough for site-sized graphs
    order = {hid: i for r in rows.values() for i, hid in enumerate(r)}
    for _ in range(4):
        for rank in sorted(rows):
            def bary(hid: str) -> tuple[float, str]:
                peers = [order[n] for n in adj[hid] if depth.get(n) == rank - 1]
                return ((sum(peers) / len(peers)) if peers else order[hid], hid)
            rows[rank].sort(key=bary)
            for i, hid in enumerate(rows[rank]):
                order[hid] = i

    width = max((len(r) for r in rows.values()), default=1) * (NODE_W + COL_GAP) - COL_GAP
    wans = record.get("wan_links") or []
    wan_top = PAD + (WAN_H + 44 if wans else 0)

    pos: dict[str, tuple[float, float]] = {}
    for rank in sorted(rows):
        row = rows[rank]
        row_w = len(row) * (NODE_W + COL_GAP) - COL_GAP
        x0 = PAD + (width - row_w) / 2
        for i, hid in enumerate(row):
            pos[hid] = (x0 + i * (NODE_W + COL_GAP), wan_top + rank * (NODE_H + ROW_GAP))

    height = wan_top + (max(rows) + 1) * (NODE_H + ROW_GAP) - ROW_GAP + PAD if rows else wan_top + PAD
    geom = {"width": width + 2 * PAD, "height": height, "pos": pos, "wan_top": wan_top,
            "content_w": width, "by_id": by_id, "rows": rows, "depth": depth}
    return devices, edges, geom


# ------------------------------------------------------------------ drawing

def node_svg(dev: dict, x: float, y: float, public: bool) -> str:
    hid = dev.get("hostname") or dev.get("host_id")
    role = dev.get("role", "unknown")
    unreachable = not dev.get("reachable", True)
    cls = "node unreachable" if unreachable else "node"
    h = dev.get("health") or {}

    chips = []
    if h.get("cpu_load_pct") is not None:
        chips.append(("CPU", f"{h['cpu_load_pct']:g}%", float(h["cpu_load_pct"]) >= 80))
    if h.get("memory_total_mb"):
        used = h.get("memory_used_mb")
        if used is None and h.get("memory_free_mb") is not None:
            used = h["memory_total_mb"] - h["memory_free_mb"]
        if used is not None:
            pct = 100.0 * used / h["memory_total_mb"]
            chips.append(("RAM", f"{pct:.0f}%", pct >= 85))
    if h.get("storage_total_mb") and h.get("storage_free_mb") is not None:
        pct = 100.0 * (1 - h["storage_free_mb"] / h["storage_total_mb"])
        chips.append(("DSK", f"{pct:.0f}%", pct >= 85))
    if h.get("temperature_c") is not None:
        chips.append(("TMP", f"{h['temperature_c']:g}°", float(h["temperature_c"]) >= 65))
    if not chips and dev.get("uptime"):
        chips.append(("UP", clip(dev["uptime"], 12), False))

    role_label = ROLE_LABEL.get(role, role.upper())
    # the role badge is right-aligned in the same band as the hostname, so measure it
    # and give the hostname whatever is actually left over
    role_w = text_w(role_label, 9, tracking=0.9)
    name_budget = NODE_W - 48 - 12 - role_w - 10
    parts = [f'<g class="{cls}" transform="translate({x:.1f},{y:.1f})">',
             f'<rect class="box" width="{NODE_W}" height="{NODE_H}" rx="10"/>',
             logo_group(dev.get("vendor"), 12, 12, 26),
             f'<text class="hostname" x="48" y="26">{esc(fit(hid, 14, name_budget))}</text>',
             f'<text class="role" x="{NODE_W - 12}" y="17">{esc(role_label)}</text>']

    ip = dev.get("mgmt_ip") or ""
    parts.append(f'<text class="ip" x="48" y="41">{esc(clip(ip, 19))}</text>')

    model = " ".join(p for p in [dev.get("model"), dev.get("os_version") or dev.get("firmware")] if p)
    parts.append(f'<text class="model" x="12" y="60">{esc(fit(model, 11, NODE_W - 24))}</text>')

    if unreachable:
        parts.append(f'<text class="warn" x="12" y="80">'
                     f'{esc(fit(dev.get("unreachable_reason") or "not reachable", 11, NODE_W - 24))}</text>')
    else:
        cx = 12
        for label, val, hot in chips[:4]:
            w = 14 + 6.3 * len(label) + 7.2 * len(val)
            parts.append(f'<g class="chip{" hot" if hot else ""}" transform="translate({cx:.1f},68)">'
                         f'<rect width="{w:.1f}" height="18" rx="5"/>'
                         f'<text x="7" y="13">{esc(label)}</text>'
                         f'<text class="v" x="{w - 7:.1f}" y="13">{esc(val)}</text></g>')
            cx += w + 6
    parts.append("</g>")
    return "".join(parts)


def wan_svg(wans: list[dict], geom: dict) -> str:
    if not wans:
        return ""
    total = len(wans) * (WAN_W + COL_GAP) - COL_GAP
    x0 = PAD + (geom["content_w"] - total) / 2
    out = []
    for i, w in enumerate(wans):
        x = x0 + i * (WAN_W + COL_GAP)
        lines = [w.get("isp") or "Internet uplink",
                 w.get("ip") or "", " · ".join(p for p in [w.get("link_speed"), w.get("type"), w.get("role")] if p)]
        out.append(f'<g class="wan" transform="translate({x:.1f},{PAD})">'
                   f'<rect width="{WAN_W}" height="{WAN_H}" rx="10"/>'
                   f'<text class="wan-title" x="14" y="24">{esc(clip(lines[0], 22))}</text>'
                   f'<text class="wan-ip" x="14" y="44">{esc(clip(lines[1], 24))}</text>'
                   f'<text class="wan-meta" x="14" y="62">{esc(clip(lines[2], 28))}</text></g>')
        host = w.get("on_host")
        if host in geom["pos"]:
            hx, hy = geom["pos"][host]
            sx, sy = x + WAN_W / 2, PAD + WAN_H
            ex, ey = hx + NODE_W / 2, hy
            mid = (sy + ey) / 2
            out.append(f'<path class="link wan-link" d="M{sx:.1f},{sy:.1f} V{mid:.1f} H{ex:.1f} V{ey:.1f}"/>')
    return "".join(out)


def plan_edges(edges: list[dict], geom: dict) -> list[dict]:
    """Give every link its own exit point, entry point and horizontal lane.

    Without this, four links leaving one switch all start from the same pixel and
    their port labels print on top of each other - which is exactly the part of a
    diagram an engineer needs to read.
    """
    pos, depth = geom["pos"], geom["depth"]
    plans = []
    for e in edges:
        a, b = e["a_host"], e["b_host"]
        if a not in pos or b not in pos:
            continue
        ap, bp = e.get("a_port"), e.get("b_port")
        if depth.get(a, 0) > depth.get(b, 0):
            a, b, ap, bp = b, a, bp, ap
        plans.append({"a": a, "b": b, "ap": ap, "bp": bp, "e": e,
                      "sibling": depth.get(a, 0) == depth.get(b, 0)})

    def slot(n: int, i: int) -> float:
        return NODE_W * (i + 1) / (n + 1)

    out_groups: dict[str, list[dict]] = defaultdict(list)
    in_groups: dict[str, list[dict]] = defaultdict(list)
    for p in plans:
        out_groups[p["a"]].append(p)
        in_groups[p["b"]].append(p)
    for host, group in out_groups.items():
        group.sort(key=lambda p: pos[p["b"]][0])
        for i, p in enumerate(group):
            p["sx"] = pos[host][0] + slot(len(group), i)
            p["lane"] = i
            p["lanes"] = len(group)
    for host, group in in_groups.items():
        group.sort(key=lambda p: pos[p["a"]][0])
        for i, p in enumerate(group):
            p["ex"] = pos[host][0] + slot(len(group), i)
    return plans


def edge_svg(p: dict, geom: dict) -> str:
    pos = geom["pos"]
    ax, ay = pos[p["a"]]
    bx, by = pos[p["b"]]
    e = p["e"]
    cls = "link inferred" if e.get("discovered_via") == "inferred" else "link"

    if p["sibling"]:
        sy = ey = ay + NODE_H / 2
        if bx >= ax:
            sx, ex = ax + NODE_W, bx
        else:
            sx, ex = ax, bx + NODE_W
        d = f"M{sx:.1f},{sy:.1f} H{ex:.1f}"
        lx, ly = (sx + ex) / 2, sy - 7
        pa = (sx + (4 if ex > sx else -34), sy - 7)
        pb = (ex + (-34 if ex > sx else 4), ey - 7)
    else:
        sx, sy = p.get("sx", ax + NODE_W / 2), ay + NODE_H
        ex, ey = p.get("ex", bx + NODE_W / 2), by
        # stagger the horizontal run so parallel links do not sit on one line
        spread = min(ROW_GAP - 34, 18 * max(p.get("lanes", 1) - 1, 0))
        base = sy + (ROW_GAP - spread) / 2
        mid = base + spread * (p.get("lane", 0) / max(p.get("lanes", 1) - 1, 1) if p.get("lanes", 1) > 1 else 0)
        d = (f"M{sx:.1f},{sy:.1f} V{mid:.1f} H{ex:.1f} V{ey:.1f}" if abs(ex - sx) > 1
             else f"M{sx:.1f},{sy:.1f} V{ey:.1f}")
        lx, ly = (sx + ex) / 2, mid - 5
        # stagger each label with its lane, or two links leaving adjacent ports
        # print their port names on top of one another
        lane = p.get("lane", 0)
        pa = (sx + 4, sy + 13 + lane * 11)
        pb = (ex + 4, ey - 6)

    out = [f'<path class="{cls}" d="{d}"/>']
    if p["ap"]:
        out.append(f'<text class="port" x="{pa[0]:.1f}" y="{pa[1]:.1f}">'
                   f'{esc(fit(p["ap"], 9.5, 96, mono=True))}</text>')
    if p["bp"]:
        out.append(f'<text class="port" x="{pb[0]:.1f}" y="{pb[1]:.1f}">'
                   f'{esc(fit(p["bp"], 9.5, 96, mono=True))}</text>')
    label = " · ".join(x for x in [e.get("speed"), e.get("note")] if x)
    if label:
        out.append(f'<text class="linklabel" x="{lx:.1f}" y="{ly:.1f}">{esc(clip(label, 24))}</text>')
    return "".join(out)


CSS = """
.bg{fill:var(--nw-bg)}
.node .box{fill:var(--nw-card);stroke:var(--nw-line);stroke-width:1.5}
.node.unreachable .box{stroke:var(--nw-bad);stroke-dasharray:5 4}
.hostname{font:600 14px var(--nw-sans);fill:var(--nw-ink)}
.ip{font:12px var(--nw-mono);fill:var(--nw-accent)}
.model{font:11px var(--nw-sans);fill:var(--nw-muted)}
.role{font:600 9px var(--nw-sans);fill:var(--nw-muted);text-anchor:end;letter-spacing:.08em}
.warn{font:11px var(--nw-sans);fill:var(--nw-bad)}
.chip rect{fill:var(--nw-chip)}
.chip text{font:600 9.5px var(--nw-sans);fill:var(--nw-muted)}
.chip text.v{font:600 10px var(--nw-mono);fill:var(--nw-ink);text-anchor:end}
.chip.hot rect{fill:var(--nw-badbg)}
.chip.hot text,.chip.hot text.v{fill:var(--nw-bad)}
.logo{fill:var(--nw-logo)}
.logo-fallback{fill:var(--nw-chip)}
.logo-initial{font:600 14px var(--nw-sans);fill:var(--nw-muted);text-anchor:middle}
.link{fill:none;stroke:var(--nw-line-strong);stroke-width:1.6}
.link.inferred{stroke-dasharray:4 4;stroke:var(--nw-muted)}
.wan-link{stroke:var(--nw-accent)}
.wan rect{fill:var(--nw-wan);stroke:var(--nw-accent);stroke-width:1.5}
.wan-title{font:600 13px var(--nw-sans);fill:var(--nw-ink)}
.wan-ip{font:12px var(--nw-mono);fill:var(--nw-accent)}
.wan-meta{font:10.5px var(--nw-sans);fill:var(--nw-muted)}
.port{font:9.5px var(--nw-mono);fill:var(--nw-muted)}
.linklabel{font:9.5px var(--nw-sans);fill:var(--nw-muted);text-anchor:middle}
.caption{font:11px var(--nw-sans);fill:var(--nw-muted)}
"""

TOKENS_LIGHT = """--nw-bg:#ffffff;--nw-card:#ffffff;--nw-line:#d8dee6;--nw-line-strong:#9aa6b4;
--nw-ink:#12151a;--nw-muted:#66707d;--nw-accent:#1f6feb;--nw-chip:#eef1f5;
--nw-bad:#c0392b;--nw-badbg:#fdeceb;--nw-wan:#f2f7ff;--nw-logo:#39424d;
--nw-sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;
--nw-mono:ui-monospace,SFMono-Regular,Menlo,monospace"""
TOKENS_DARK = """--nw-bg:#0f1216;--nw-card:#171c22;--nw-line:#2a323c;--nw-line-strong:#4a5563;
--nw-ink:#e7ebf0;--nw-muted:#93a0b0;--nw-accent:#5b9dff;--nw-chip:#222a33;
--nw-bad:#ff7b6b;--nw-badbg:#3a1f1c;--nw-wan:#13202f;--nw-logo:#b6c2d0"""


def render(record: dict, public: bool = False, title: str | None = None, standalone: bool = True) -> str:
    """standalone=True -> a .svg file. standalone=False -> an <svg> to paste into a page.

    Either way the theme tokens ride along, scoped to `.netwalk-map`, because an
    embedded diagram whose tokens stayed behind renders as a black rectangle - the
    kind of bug that only shows up in the artefact you actually hand over.
    """
    devices, edges, geom = build_layout(record)
    site = record.get("site", {})
    heading = title or f"{site.get('name') or site.get('id') or 'network'}"
    sub = [] if public else ([f"scanned {record.get('scanned_at','')}"] if record.get("scanned_at") else [])
    cov = record.get("coverage") or {}
    if cov.get("devices_unreachable"):
        sub.append(f"{cov['devices_unreachable']} device(s) not reachable")

    w, h = geom["width"], geom["height"] + 26
    body = [f'<rect class="bg" width="{w}" height="{h}"/>'] if standalone else []
    body.append(wan_svg(record.get("wan_links") or [], geom))
    for plan in plan_edges(edges, geom):
        body.append(edge_svg(plan, geom))
    for d in devices:
        if d["host_id"] in geom["pos"]:
            x, y = geom["pos"][d["host_id"]]
            body.append(node_svg(d, x, y, public))
    caption = f"{heading} · {len(devices)} device(s), {len(edges)} link(s)"
    if sub:
        caption += " · " + " · ".join(sub)
    body.append(f'<text class="caption" x="{PAD}" y="{h - 8}">{esc(caption)}</text>')

    light = TOKENS_LIGHT if standalone else TOKENS_LIGHT.replace("--nw-bg:#ffffff", "--nw-bg:transparent")
    dark = TOKENS_DARK if standalone else TOKENS_DARK.replace("--nw-bg:#0f1216", "--nw-bg:transparent")
    style = (
        f".netwalk-map{{{light}}}"
        f"@media(prefers-color-scheme:dark){{"
        f"svg.netwalk-map:root:not([data-theme=light]),"
        f":root:not([data-theme=light]) .netwalk-map{{{dark}}}}}"
        f"svg.netwalk-map:root[data-theme=dark],:root[data-theme=dark] .netwalk-map{{{dark}}}"
        + CSS)
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" class="netwalk-map" '
            f'viewBox="0 0 {w:.0f} {h:.0f}" width="{w:.0f}" height="{h:.0f}" '
            f'role="img" aria-label="{esc(caption)}">')
    return f'{head}<style>{style}</style>{"".join(body)}</svg>'


def main() -> int:
    ap = argparse.ArgumentParser(prog="netwalk_map.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("record")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--public", action="store_true", help="omit scan date and other internal detail")
    ap.add_argument("--title")
    args = ap.parse_args()

    with open(args.record, encoding="utf-8") as fh:
        record = json.load(fh)
    svg = render(record, public=args.public, title=args.title)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(svg)
    n = len(record.get("devices", []))
    print(f"wrote {args.out} ({n} device(s), {len(svg)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
