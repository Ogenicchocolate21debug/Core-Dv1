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

    wide = M.render(synthetic(n_aps=40, n_switches=4), group=False)
    w = float(re.search(r'viewBox="0 0 ([\d.]+)', wide).group(1))
    if w > 4000:
        fails.append(f"ungrouped canvas is {w:.0f}px wide - rank wrapping is not working")
    narrow = float(re.search(r'viewBox="0 0 ([\d.]+)',
                             M.render(synthetic(n_aps=40, n_switches=4))).group(1))
    if narrow > w:
        fails.append("grouping made the diagram wider, not narrower")

    svg = M.render(rec)
    for want in ("AP GROUP", "20 access points", "10.0.1.1", "10.0.1.20"):
        if want not in svg:
            fails.append(f"the group node does not show {want!r}")

    total = 9
    for f in fails:
        print(f"  FAIL  {f}")
    print(f"\n{total - len(fails)}/{total} map checks pass")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
