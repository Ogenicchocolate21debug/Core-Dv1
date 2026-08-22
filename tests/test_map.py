#!/usr/bin/env python3
"""Checks for the diagram renderer that a real site would otherwise catch for us."""
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import netwalk_map as M  # noqa: E402


def synthetic(n_aps=20, n_switches=3):
    devs = [{"host_id": "gw", "role": "gateway", "vendor": "mikrotik",
             "mgmt_ip": "10.0.0.1", "reachable": True}]
    edges = []
    for si in range(n_switches):
        sid = f"sw{si}"
        devs.append({"host_id": sid, "role": "switch", "vendor": "ubiquiti",
                     "mgmt_ip": f"10.0.0.{10+si}", "reachable": True})
        edges.append({"a_host": "gw", "b_host": sid, "discovered_via": "lldp"})
        for ai in range(n_aps):
            aid = f"{sid}-ap{ai}"
            devs.append({"host_id": aid, "role": "ap", "vendor": "ubiquiti",
                         "model": "AC LR", "mgmt_ip": f"10.0.{si+1}.{ai+1}",
                         "reachable": ai % 7 != 0})
            edges.append({"a_host": sid, "b_host": aid, "discovered_via": "controller"})
    return {"site": {"id": "t", "name": "T"}, "devices": devs, "topology_edges": edges}


def main() -> int:
    fails = []
    rec = synthetic()

    grouped = M.group_aps(rec)
    gnodes = [d for d in grouped["devices"] if d["role"] == "ap-group"]
    if len(gnodes) != 3:
        fails.append(f"expected one AP group per switch, got {len(gnodes)}")
    if any(d["role"] == "ap" for d in grouped["devices"]):
        fails.append("an access point survived grouping")
    g = gnodes[0] if gnodes else {}
    if g.get("_count") != 20:
        fails.append(f"group count wrong: {g.get('_count')}")
    if g.get("_ip_from") != "10.0.1.1" or g.get("_ip_to") != "10.0.1.20":
        fails.append(f"IP range wrong: {g.get('_ip_from')} -> {g.get('_ip_to')}")
    if g.get("_offline") != 3:
        fails.append(f"offline count wrong: {g.get('_offline')} (expected 3)")

    # an AP with two uplinks is meshed and must stay visible on its own
    rec2 = synthetic(n_aps=3, n_switches=2)
    rec2["topology_edges"].append({"a_host": "sw1", "b_host": "sw0-ap0",
                                   "discovered_via": "controller"})
    kept = [d["host_id"] for d in M.group_aps(rec2)["devices"] if d["role"] == "ap"]
    if "sw0-ap0" not in kept:
        fails.append("a multi-homed AP was collapsed into a group")

    def canvas(svg):
        m = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
        return float(m.group(1)), float(m.group(2))

    big = synthetic(n_aps=40, n_switches=4)
    # Left to right, the flow runs along x, so wrapping is what has to bound y.
    _, h_lr = canvas(M.render(big, group=False, orient="lr"))
    if h_lr > 2000:
        fails.append(f"left-to-right canvas is {h_lr:.0f}px tall - rank wrapping is not working")
    # Top to bottom it is the other way round.
    w_tb, _ = canvas(M.render(big, group=False, orient="tb"))
    if w_tb > 3000:
        fails.append(f"top-down canvas is {w_tb:.0f}px wide - rank wrapping is not working")
    # Whatever the orientation, grouping must shrink the picture.
    for o in ("lr", "tb"):
        a = canvas(M.render(big, group=False, orient=o))
        b = canvas(M.render(big, group=True, orient=o))
        if a[0] * a[1] <= b[0] * b[1]:
            fails.append(f"grouping did not shrink the {o} diagram")
    # The gateway must sit before the switches along the flow axis.
    geom = M.build_layout(M.group_aps(synthetic()), orient="lr")[2]
    if geom["pos"]["gw"][0] >= geom["pos"]["sw0"][0]:
        fails.append("left to right: the gateway is not to the left of its switch")
    geom = M.build_layout(M.group_aps(synthetic()), orient="tb")[2]
    if geom["pos"]["gw"][1] >= geom["pos"]["sw0"][1]:
        fails.append("top to bottom: the gateway is not above its switch")

    # WAN boxes carry the operator's mark, and an unknown operator still gets something
    wanrec = synthetic(n_aps=2, n_switches=1)
    wanrec["wan_links"] = [
        {"isp": "3BB", "on_host": "gw", "ip": "1.1.1.1/32", "link_speed": "1G"},
        {"isp": "AIS Fibre", "on_host": "gw", "ip": "2.2.2.2/32"},
        {"isp": "Some Local ISP", "on_host": "gw", "ip": "3.3.3.3/32"},
        {"isp": "True", "on_host": "gw", "ip": "4.4.4.4/32"},
        {"isp": "Symphony", "on_host": "gw", "ip": "5.5.5.5/32"},
    ]
    wsvg = M.render(wanrec)
    if M.isp_key("AIS Fibre") != "isp-ais":
        fails.append(f"ISP alias not resolved: {M.isp_key('AIS Fibre')}")
    if "logo-fallback" not in wsvg:
        fails.append("an ISP with no mark on file did not fall back to a lettered chip")
    # the uplink column must not run off the bottom of the canvas
    _, wh = canvas(wsvg)
    lowest = max(y for _x, y in M.build_layout(M.group_aps(wanrec), orient="lr")[2]["pos"].values())
    need = M.PAD + len(wanrec["wan_links"]) * (M.WAN_H + 30) - 30
    if wh < need:
        fails.append(f"canvas {wh:.0f}px is shorter than the {need:.0f}px WAN column")

    svg = M.render(rec)
    for want in ("AP GROUP", "20 access points", "10.0.1.1", "10.0.1.20"):
        if want not in svg:
            fails.append(f"the group node does not show {want!r}")

    total = 16
    for f in fails:
        print(f"  FAIL  {f}")
    print(f"\n{total - len(fails)}/{total} map checks pass")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
