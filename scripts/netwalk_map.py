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
from collections import Counter, defaultdict, deque

HERE = os.path.dirname(os.path.abspath(__file__))
LOGO_DIR = os.path.join(os.path.dirname(HERE), "assets", "logos")

NODE_W, NODE_H = 216, 96
# Left-to-right is the default: a network diagram is read the way a packet travels,
# from the internet on the left to the edge on the right, and a long site then grows
# across the page rather than off the bottom of it.
MAX_SLOTS = 9         # nodes per column before a rank wraps into another column
MAX_TIDY = 60         # above this many leaves, fall back to the wrapped layout
RANK_GAP = 118        # between ranks - along the flow axis
SLOT_GAP = 26         # between nodes inside one rank
WRAP_GAP = 46         # between the wrapped columns of a single rank
PAD = 40
WAN_W, WAN_H = 200, 78

ROLE_RANK = {
    "ap-group": 3,
    "gateway": 0, "router": 0, "firewall": 0,
    "l3-switch": 1, "controller": 1,
    "switch": 2, "unmanaged-switch": 2,
    "ap": 3, "server": 3, "nas": 3, "nvr": 3,
    "printer": 4, "ups": 4, "client": 4, "unknown": 4,
}
ROLE_LABEL = {
    "ap-group": "AP GROUP",
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

def _ip_key(ip: str):
    try:
        return tuple(int(x) for x in str(ip).split("/")[0].split("."))
    except (ValueError, AttributeError):
        return (999, 999, 999, 999)


def group_aps(record: dict, minimum: int = 2) -> dict:
    """Collapse the access points hanging off one switch into a single node.

    A school with 112 APs draws 112 boxes and a comb of 112 lines, which is accurate
    and unreadable. What an engineer actually wants from the picture is: this switch
    feeds this many APs, in this address range. The per-device detail is still in the
    report's inventory table - only the diagram groups them.
    """
    devices = {d["host_id"]: d for d in record.get("devices", []) if d.get("host_id")}
    edges = [e for e in record.get("topology_edges", []) if e.get("a_host") and e.get("b_host")]
    touching = defaultdict(list)
    for e in edges:
        touching[e["a_host"]].append(e)
        touching[e["b_host"]].append(e)

    groups: dict[str, list[dict]] = defaultdict(list)
    for hid, d in devices.items():
        if d.get("role") != "ap":
            continue
        es = touching.get(hid, [])
        if len(es) != 1:          # an AP with a mesh uplink or none stays on its own
            continue
        e = es[0]
        parent = e["b_host"] if e["a_host"] == hid else e["a_host"]
        if devices.get(parent, {}).get("role") not in ("switch", "l3-switch", "gateway", "router"):
            continue
        groups[parent].append(d)
    groups = {k: v for k, v in groups.items() if len(v) >= minimum}
    if not groups:
        return record

    grouped_ids = {d["host_id"] for members in groups.values() for d in members}
    out = dict(record)
    out["devices"] = [d for d in record["devices"] if d.get("host_id") not in grouped_ids]
    out["topology_edges"] = [e for e in edges
                             if e["a_host"] not in grouped_ids and e["b_host"] not in grouped_ids]

    for parent, members in sorted(groups.items()):
        members.sort(key=lambda d: _ip_key(d.get("mgmt_ip")))
        with_ip = [d for d in members if d.get("mgmt_ip")]
        offline = [d for d in members if not d.get("reachable", True)]
        models = Counter(d.get("model") or "unknown" for d in members)
        gid = f"AP group on {parent}"
        out["devices"].append({
            "host_id": gid, "hostname": f"{len(members)} access points",
            "vendor": (members[0].get("vendor") or "unknown"),
            "role": "ap-group", "reachable": len(offline) < len(members),
            "_count": len(members),
            "_ip_from": with_ip[0]["mgmt_ip"] if with_ip else None,
            "_ip_to": with_ip[-1]["mgmt_ip"] if with_ip else None,
            "_no_ip": len(members) - len(with_ip),
            "_offline": len(offline),
            "_models": ", ".join(f"{n}x {m}" for m, n in models.most_common(3)),
        })
        out["topology_edges"].append({"a_host": parent, "b_host": gid,
                                      "discovered_via": "controller",
                                      "note": f"{len(members)} APs"})
    return out


def build_layout(record: dict, orient: str = "lr") -> tuple[list[dict], list[dict], dict]:
    devices = [d for d in record.get("devices", []) if d.get("host_id")]
    by_id = {d["host_id"]: d for d in devices}
    edges = [e for e in record.get("topology_edges", [])
             if e.get("a_host") in by_id and e.get("b_host") in by_id and e["a_host"] != e["b_host"]]

    adj = defaultdict(set)
    for e in edges:
        adj[e["a_host"]].add(e["b_host"])
        adj[e["b_host"]].add(e["a_host"])

    # One root, not several. The crawl started somewhere and everything else was
    # reached FROM there, so a second router is a child of the first - not a peer
    # floating at the top of the page with a long wire running down to it. Extra
    # roots are added only for devices the crawl never reached from the entry point.
    entry = (record.get("entry_point") or {}).get("host_id")
    if entry in by_id:
        roots = [entry]
    else:
        gws = [d["host_id"] for d in devices if d.get("role") in ("gateway", "firewall")]
        roots = gws[:1] or [d["host_id"] for d in devices if d.get("role") == "router"][:1]
    if not roots and devices:
        roots = [devices[0]["host_id"]]

    depth: dict[str, int] = {}
    parent: dict[str, str] = {}
    q = deque()
    for r in roots:
        depth[r] = 0
        q.append(r)
    while q:
        cur = q.popleft()
        for nb in sorted(adj[cur]):
            if nb not in depth:
                depth[nb] = depth[cur] + 1
                parent[nb] = cur          # the edge the crawl actually descended
                q.append(nb)
    for d in sorted(devices, key=lambda d: d["host_id"]):
        hid = d["host_id"]
        if hid in depth:
            continue
        # an island the entry point could not reach: root it where its role belongs
        depth[hid] = ROLE_RANK.get(d.get("role", "unknown"), 4)
        roots.append(hid)
        q.append(hid)
        while q:
            cur = q.popleft()
            for nb in sorted(adj[cur]):
                if nb not in depth:
                    depth[nb] = depth[cur] + 1
                    parent[nb] = cur
                    q.append(nb)

    rows: dict[int, list[str]] = defaultdict(list)
    for d in sorted(devices, key=lambda d: (depth[d["host_id"]], d["host_id"])):
        rows[depth[d["host_id"]]].append(d["host_id"])

    # ---- ordering ----------------------------------------------------------
    # The crawl descended a tree: every device was first reached from exactly one
    # parent. Laying that tree out tidily - each parent centred over its own
    # children, every subtree kept contiguous - is what makes the links readable,
    # because a tree edge then never has to cross another one. Ordering each rank
    # independently (which is what a barycentre pass does) produces the same
    # topology drawn as a bundle of crossing wires.
    children: dict[str, list[str]] = defaultdict(list)
    for child, par in parent.items():
        children[par].append(child)
    for par in children:
        children[par].sort(key=lambda h: (ROLE_RANK.get(by_id[h].get("role", "unknown"), 4), h))

    leaves = sum(1 for d in devices if not children.get(d["host_id"]))
    tidy = leaves <= MAX_TIDY
    order: dict[str, float] = {}
    if tidy:
        cursor = [0.0]
        seen_walk: set[str] = set()

        def walk(node: str) -> None:
            if node in seen_walk:
                return
            seen_walk.add(node)
            kids = [k for k in children.get(node, []) if k not in seen_walk]
            if not kids:
                order[node] = cursor[0]
                cursor[0] += 1
                return
            for k in kids:
                walk(k)
            first, last = order[kids[0]], order[kids[-1]]
            order[node] = (first + last) / 2

        for r in sorted(roots, key=lambda h: (ROLE_RANK.get(by_id[h].get("role", "unknown"), 4), h)):
            walk(r)
        for d in devices:                      # anything the tree never reached
            if d["host_id"] not in order:
                order[d["host_id"]] = cursor[0]
                cursor[0] += 1
        for rank in rows:
            rows[rank].sort(key=lambda h: order[h])
        span = cursor[0]
    else:
        # barycentre passes - cheap, deterministic, and all that is affordable when
        # the tree is too wide to lay out tidily
        pos_in_row = {hid: i for r in rows.values() for i, hid in enumerate(r)}
        for _ in range(4):
            for rank in sorted(rows):
                def bary(hid: str) -> tuple[float, str]:
                    peers = [pos_in_row[n] for n in adj[hid] if depth.get(n) == rank - 1]
                    return ((sum(peers) / len(peers)) if peers else pos_in_row[hid], hid)
                rows[rank].sort(key=bary)
                for i, hid in enumerate(rows[rank]):
                    pos_in_row[hid] = i
        span = 0

    # Place everything in (rank, slot) space first, then project. Keeping the two
    # apart is what lets the same layout render left-to-right or top-to-bottom
    # without a second copy of the ordering logic.
    lr = orient == "lr"
    slot_span = (NODE_H + SLOT_GAP) if lr else (NODE_W + SLOT_GAP)
    rank_span = (NODE_W + RANK_GAP) if lr else (NODE_H + RANK_GAP)
    wrap_span = (NODE_W + WRAP_GAP) if lr else (NODE_H + WRAP_GAP)

    wans = record.get("wan_links") or []
    lead = PAD + ((WAN_W + RANK_GAP) if (wans and lr) else (WAN_H + 44) if wans else 0)
    pos: dict[str, tuple[float, float]] = {}

    if tidy:
        cross = max(span, 1) * slot_span - SLOT_GAP
        for rank in sorted(rows):
            a = lead + rank * rank_span
            for hid in rows[rank]:
                across = PAD + order[hid] * slot_span
                pos[hid] = (a, across) if lr else (across, a)
        along = lead + (max(rows) + 1) * rank_span if rows else lead
    else:
        max_slots = max(3, min(MAX_SLOTS, max((len(r) for r in rows.values()), default=1)))
        cross = max_slots * slot_span - SLOT_GAP
        along = lead
        for rank in sorted(rows):
            row = rows[rank]
            cols = [row[i:i + max_slots] for i in range(0, len(row), max_slots)] or [[]]
            for ci, col in enumerate(cols):
                col_cross = len(col) * slot_span - SLOT_GAP
                c0 = PAD + (cross - col_cross) / 2
                a = along + ci * wrap_span
                for i, hid in enumerate(col):
                    across = c0 + i * slot_span
                    pos[hid] = (a, across) if lr else (across, a)
            along += (len(cols) - 1) * wrap_span + rank_span

    flow_len = along - RANK_GAP + PAD
    width = flow_len if lr else cross + 2 * PAD
    height = (cross + 2 * PAD) if lr else flow_len
    geom = {"width": width, "height": height, "pos": pos, "lead": lead,
            "cross": cross, "orient": orient, "by_id": by_id, "rows": rows,
            "depth": depth, "parent": parent, "tidy": tidy}
    return devices, edges, geom


# ------------------------------------------------------------------ drawing

def group_node_svg(dev: dict, x: float, y: float) -> str:
    n = dev.get("_count", 0)
    off = dev.get("_offline", 0)
    rng = (f'{dev["_ip_from"]} \u2192 {dev["_ip_to"]}' if dev.get("_ip_from") else "no IP recorded")
    if dev.get("_no_ip"):
        rng += f'  (+{dev["_no_ip"]} with no IP)'
    parts = [f'<g class="node group" transform="translate({x:.1f},{y:.1f})">',
             f'<rect class="stackback" x="6" y="-6" width="{NODE_W}" height="{NODE_H}" rx="10"/>',
             f'<rect class="stackback2" x="3" y="-3" width="{NODE_W}" height="{NODE_H}" rx="10"/>',
             f'<rect class="box" width="{NODE_W}" height="{NODE_H}" rx="10"/>',
             logo_group(dev.get("vendor"), 12, 12, 26),
             f'<text class="hostname" x="48" y="26">{n} access points</text>',
             f'<text class="role" x="{NODE_W - 12}" y="17">AP GROUP</text>',
             f'<text class="ip" x="12" y="46">{esc(fit(rng, 12, NODE_W - 24, mono=True))}</text>',
             f'<text class="model" x="12" y="62">{esc(fit(dev.get("_models") or "", 11, NODE_W - 24))}</text>']
    chips = [("UP", str(n - off), False)]
    if off:
        chips.append(("DOWN", str(off), True))
    cx = 12
    for label, val, hot in chips:
        w = 18 + 7.1 * len(label) + 7.8 * len(val)
        parts.append(f'<g class="chip{" hot" if hot else ""}" transform="translate({cx:.1f},70)">'
                     f'<rect width="{w:.1f}" height="18" rx="5"/>'
                     f'<text x="7" y="13">{esc(label)}</text>'
                     f'<text class="v" x="{w - 7:.1f}" y="13">{esc(val)}</text></g>')
        cx += w + 6
    parts.append("</g>")
    return "".join(parts)


def node_svg(dev: dict, x: float, y: float, public: bool) -> str:
    if dev.get("role") == "ap-group":
        return group_node_svg(dev, x, y)
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
            w = 18 + 7.1 * len(label) + 7.8 * len(val)
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
    lr = geom["orient"] == "lr"
    out = []
    span = (WAN_H + 30) if lr else (WAN_W + 46)
    total = len(wans) * span - (30 if lr else 46)
    start = PAD + (geom["cross"] - total) / 2
    for i, w in enumerate(wans):
        if lr:
            x, y = PAD, start + i * span
        else:
            x, y = start + i * span, PAD
        lines = [w.get("isp") or "Internet uplink", w.get("ip") or "",
                 " \u00b7 ".join(p for p in [w.get("link_speed"), w.get("type"), w.get("role")] if p)]
        out.append(f'<g class="wan" transform="translate({x:.1f},{y:.1f})">'
                   f'<rect width="{WAN_W}" height="{WAN_H}" rx="10"/>'
                   f'<text class="wan-title" x="14" y="24">{esc(fit(lines[0], 13, WAN_W - 28))}</text>'
                   f'<text class="wan-ip" x="14" y="44">{esc(fit(lines[1], 12, WAN_W - 28, mono=True))}</text>'
                   f'<text class="wan-meta" x="14" y="62">{esc(fit(lines[2], 10.5, WAN_W - 28))}</text></g>')
        host = w.get("on_host")
        if host in geom["pos"]:
            hx, hy = geom["pos"][host]
            if lr:
                sx, sy = x + WAN_W, y + WAN_H / 2
                ex, ey = hx, hy + NODE_H / 2
                mid = (sx + ex) / 2
                d = f"M{sx:.1f},{sy:.1f} H{mid:.1f} V{ey:.1f} H{ex:.1f}"
            else:
                sx, sy = x + WAN_W / 2, y + WAN_H
                ex, ey = hx + NODE_W / 2, hy
                mid = (sy + ey) / 2
                d = f"M{sx:.1f},{sy:.1f} V{mid:.1f} H{ex:.1f} V{ey:.1f}"
            out.append(f'<path class="link wan-link" d="{d}"/>')
    return "".join(out)


def plan_edges(edges: list[dict], geom: dict) -> list[dict]:
    """Give every link its own exit point, entry point and lane.

    Without this, four links leaving one switch start from the same pixel and their
    port labels print on top of each other - which is the part of a diagram an
    engineer actually needs to read.
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
        # A link the crawl actually descended is the backbone of the picture; any
        # other link between the same ranks is a second path, and drawing them the
        # same way is what makes a diagram look like a bundle of wires.
        par = geom.get("parent", {})
        plans.append({"a": a, "b": b, "ap": ap, "bp": bp, "e": e,
                      "sibling": depth.get(a, 0) == depth.get(b, 0),
                      "tree": par.get(b) == a or par.get(a) == b})

    lr = geom["orient"] == "lr"
    cross_of = (lambda hid: pos[hid][1]) if lr else (lambda hid: pos[hid][0])
    extent = NODE_H if lr else NODE_W

    def slot(n: int, i: int) -> float:
        return extent * (i + 1) / (n + 1)

    out_groups: dict[str, list[dict]] = defaultdict(list)
    in_groups: dict[str, list[dict]] = defaultdict(list)
    for p in plans:
        out_groups[p["a"]].append(p)
        in_groups[p["b"]].append(p)
    for host, group in out_groups.items():
        group.sort(key=lambda p: cross_of(p["b"]))
        for i, p in enumerate(group):
            p["s_off"] = slot(len(group), i)
            p["lane"], p["lanes"] = i, len(group)
    for host, group in in_groups.items():
        group.sort(key=lambda p: cross_of(p["a"]))
        for i, p in enumerate(group):
            p["e_off"] = slot(len(group), i)
    return plans


def edge_svg(p: dict, geom: dict) -> tuple[str, list[dict]]:
    """Return the link's path and the labels it wants, separately.

    Labels are placed later, once every line is on the page, because a port name is
    only useful if something else has not been printed on top of it.
    """
    pos = geom["pos"]
    ax, ay = pos[p["a"]]
    bx, by = pos[p["b"]]
    e = p["e"]
    lr = geom["orient"] == "lr"
    cls = "link"
    if e.get("discovered_via") == "inferred":
        cls += " inferred"
    elif not p.get("tree"):
        cls += " extra"
    s_off = p.get("s_off", (NODE_H if lr else NODE_W) / 2)
    e_off = p.get("e_off", (NODE_H if lr else NODE_W) / 2)

    if p["sibling"]:
        if lr:
            sx, sy = ax + NODE_W / 2, (ay + NODE_H) if by > ay else ay
            ex, ey = bx + NODE_W / 2, by if by > ay else (by + NODE_H)
            d = f"M{sx:.1f},{sy:.1f} V{ey:.1f}"
            pa, pb = (sx + 6, sy + 13, "start"), (ex + 6, ey - 7, "start")
        else:
            sy = ey = ay + NODE_H / 2
            sx, ex = (ax + NODE_W, bx) if bx >= ax else (ax, bx + NODE_W)
            d = f"M{sx:.1f},{sy:.1f} H{ex:.1f}"
            pa = (sx + 6, sy - 8, "start")
            pb = (ex - 6, ey - 8, "end")
        lx, ly, lanchor = (sx + ex) / 2, (sy + ey) / 2 + 4, "middle"
    elif lr:
        sx, sy = ax + NODE_W, ay + s_off
        ex, ey = bx, by + e_off
        spread = min(RANK_GAP - 44, 14 * max(p.get("lanes", 1) - 1, 0))
        base = sx + (RANK_GAP - spread) / 2
        mid = base + spread * (p.get("lane", 0) / max(p.get("lanes", 1) - 1, 1)
                               if p.get("lanes", 1) > 1 else 0)
        d = (f"M{sx:.1f},{sy:.1f} H{mid:.1f} V{ey:.1f} H{ex:.1f}" if abs(ey - sy) > 1
             else f"M{sx:.1f},{sy:.1f} H{ex:.1f}")
        pa, pb = (sx + 7, sy - 6, "start"), (ex - 7, ey - 6, "end")
        # the link's own label goes on the far horizontal run, where only this link is
        lx, ly, lanchor = (mid + ex) / 2, ey - 6, "middle"
    else:
        sx, sy = ax + s_off, ay + NODE_H
        ex, ey = bx + e_off, by
        spread = min(RANK_GAP - 34, 18 * max(p.get("lanes", 1) - 1, 0))
        base = sy + (RANK_GAP - spread) / 2
        mid = base + spread * (p.get("lane", 0) / max(p.get("lanes", 1) - 1, 1)
                               if p.get("lanes", 1) > 1 else 0)
        d = (f"M{sx:.1f},{sy:.1f} V{mid:.1f} H{ex:.1f} V{ey:.1f}" if abs(ex - sx) > 1
             else f"M{sx:.1f},{sy:.1f} V{ey:.1f}")
        pa, pb = (sx + 5, sy + 14, "start"), (ex + 5, ey - 7, "start")
        lx, ly, lanchor = (sx + ex) / 2, mid - 6, "middle"

    labels = []
    if p["ap"]:
        labels.append({"x": pa[0], "y": pa[1], "anchor": pa[2], "cls": "port",
                       "text": fit(p["ap"], 9.5, 104, mono=True), "px": 9.5,
                       "mono": True, "prio": 0})
    if p["bp"]:
        labels.append({"x": pb[0], "y": pb[1], "anchor": pb[2], "cls": "port",
                       "text": fit(p["bp"], 9.5, 104, mono=True), "px": 9.5,
                       "mono": True, "prio": 0})
    note = " \u00b7 ".join(x for x in [e.get("speed"), e.get("note")] if x)
    if note:
        labels.append({"x": lx, "y": ly, "anchor": lanchor, "cls": "linklabel",
                       "text": fit(note, 9.5, 140), "px": 9.5, "mono": False, "prio": 1})
    return f'<path class="{cls}" d="{d}"/>', labels


def place_labels(labels: list[dict], obstacles: list[tuple] | None = None) -> str:
    """Draw labels so they do not sit on top of each other.

    Port names come first because they carry the most information per pixel; a link's
    speed or note gives way. Anything that still cannot find clear space is dropped
    rather than printed as an unreadable overlap - the same fact is in the report's
    tables, and a diagram that lies about being legible is worse than one that leaves
    a label out.
    """
    # Device boxes are obstacles, not just other labels: a port name printed across a
    # node's chips is exactly as unreadable as one printed across another label.
    placed: list[tuple[float, float, float, float]] = list(obstacles or [])
    out, dropped = [], 0

    def box(l, y):
        w = text_w(l["text"], l["px"], l["mono"]) + 6
        x = l["x"] - (w / 2 if l["anchor"] == "middle" else w if l["anchor"] == "end" else 0)
        return (x, y - l["px"] - 1, x + w, y + 3)

    def clash(b):
        return any(not (b[2] <= o[0] or b[0] >= o[2] or b[3] <= o[1] or b[1] >= o[3])
                   for o in placed)

    for l in sorted(labels, key=lambda l: (l["prio"], l["y"], l["x"])):
        for dy in (0, -12, 12, -24, 24, -36, 36):
            b = box(l, l["y"] + dy)
            if not clash(b):
                placed.append(b)
                anchor = f' text-anchor="{l["anchor"]}"' if l["anchor"] != "start" else ""
                out.append(f'<text class="{l["cls"]}"{anchor} x="{l["x"]:.1f}" '
                           f'y="{l["y"] + dy:.1f}">{esc(l["text"])}</text>')
                break
        else:
            dropped += 1
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
.group .box{stroke:var(--nw-accent)}
.stackback{fill:var(--nw-card);stroke:var(--nw-line);stroke-width:1.2;opacity:.55}
.stackback2{fill:var(--nw-card);stroke:var(--nw-line);stroke-width:1.2;opacity:.8}
.logo{fill:var(--nw-logo)}
.logo-fallback{fill:var(--nw-chip)}
.logo-initial{font:600 14px var(--nw-sans);fill:var(--nw-muted);text-anchor:middle}
.link{fill:none;stroke:var(--nw-line-strong);stroke-width:1.6}
.link.inferred{stroke-dasharray:4 4;stroke:var(--nw-muted)}
.link.extra{stroke:var(--nw-accent);stroke-width:1.3;opacity:.75;stroke-dasharray:9 3}
.wan-link{stroke:var(--nw-accent)}
.wan rect{fill:var(--nw-wan);stroke:var(--nw-accent);stroke-width:1.5}
.wan-title{font:600 13px var(--nw-sans);fill:var(--nw-ink)}
.wan-ip{font:12px var(--nw-mono);fill:var(--nw-accent)}
.wan-meta{font:10.5px var(--nw-sans);fill:var(--nw-muted)}
.port,.linklabel{paint-order:stroke fill;stroke:var(--nw-halo);stroke-width:3.5;
stroke-linejoin:round}
.port{font:9.5px var(--nw-mono);fill:var(--nw-ink)}
.linklabel{font:italic 9.5px var(--nw-sans);fill:var(--nw-muted)}
.caption{font:11px var(--nw-sans);fill:var(--nw-muted)}
"""

TOKENS_LIGHT = """--nw-bg:#ffffff;--nw-card:#ffffff;--nw-line:#d8dee6;--nw-line-strong:#9aa6b4;
--nw-ink:#12151a;--nw-muted:#66707d;--nw-accent:#1f6feb;--nw-chip:#eef1f5;
--nw-bad:#c0392b;--nw-badbg:#fdeceb;--nw-wan:#f2f7ff;--nw-logo:#39424d;--nw-halo:#ffffff;
--nw-sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;
--nw-mono:ui-monospace,SFMono-Regular,Menlo,monospace"""
TOKENS_DARK = """--nw-bg:#0f1216;--nw-card:#171c22;--nw-line:#2a323c;--nw-line-strong:#4a5563;
--nw-ink:#e7ebf0;--nw-muted:#93a0b0;--nw-accent:#5b9dff;--nw-chip:#222a33;
--nw-bad:#ff7b6b;--nw-badbg:#3a1f1c;--nw-wan:#13202f;--nw-logo:#b6c2d0;--nw-halo:#0f1216"""


def render(record: dict, public: bool = False, title: str | None = None,
           standalone: bool = True, group: bool = True, orient: str = "lr") -> str:
    """standalone=True -> a .svg file. standalone=False -> an <svg> to paste into a page.

    Either way the theme tokens ride along, scoped to `.netwalk-map`, because an
    embedded diagram whose tokens stayed behind renders as a black rectangle - the
    kind of bug that only shows up in the artefact you actually hand over.
    """
    total_devices = len(record.get("devices", []))
    if group:
        record = group_aps(record)
    devices, edges, geom = build_layout(record, orient=orient)
    site = record.get("site", {})
    heading = title or f"{site.get('name') or site.get('id') or 'network'}"
    sub = [] if public else ([f"scanned {record.get('scanned_at','')}"] if record.get("scanned_at") else [])
    cov = record.get("coverage") or {}
    if cov.get("devices_unreachable"):
        sub.append(f"{cov['devices_unreachable']} device(s) not reachable")

    w, h = geom["width"], geom["height"] + 26
    body = [f'<rect class="bg" width="{w}" height="{h}"/>'] if standalone else []
    body.append(wan_svg(record.get("wan_links") or [], geom))
    labels: list[dict] = []
    for plan in plan_edges(edges, geom):
        path, ls = edge_svg(plan, geom)
        body.append(path)
        labels += ls
    for d in devices:
        if d["host_id"] in geom["pos"]:
            x, y = geom["pos"][d["host_id"]]
            body.append(node_svg(d, x, y, public))

    # Labels go on last, once every line and every box exists, so placement can see
    # what it has to avoid.
    obstacles = [(x, y, x + NODE_W, y + NODE_H) for x, y in geom["pos"].values()]
    if record.get("wan_links"):
        span = (WAN_H + 30) if orient == "lr" else (WAN_W + 46)
        total = len(record["wan_links"]) * span - (30 if orient == "lr" else 46)
        st = PAD + (geom["cross"] - total) / 2
        for i in range(len(record["wan_links"])):
            wx, wy = (PAD, st + i * span) if orient == "lr" else (st + i * span, PAD)
            obstacles.append((wx, wy, wx + WAN_W, wy + WAN_H))
    body.append(place_labels(labels, obstacles))

    shown = len(devices)
    caption = (f"{heading} · {total_devices} device(s)"
               + (f", access points grouped per switch into {shown} nodes"
                  if shown != total_devices else "")
               + f" · {len(edges)} link(s)")
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
    ap.add_argument("--top-down", dest="orient", action="store_const", const="tb",
                    help="stack the diagram top to bottom instead of left to right")
    ap.add_argument("--no-group-aps", dest="group", action="store_false",
                    help="draw every access point separately instead of grouping them per switch")
    ap.set_defaults(group=True, orient="lr")
    args = ap.parse_args()

    with open(args.record, encoding="utf-8") as fh:
        record = json.load(fh)
    svg = render(record, public=args.public, title=args.title, group=args.group,
                 orient=args.orient)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(svg)
    n = len(record.get("devices", []))
    print(f"wrote {args.out} ({n} device(s), {len(svg)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
