#!/usr/bin/env python3
"""Checks for the Omada adapter.

There is no Omada controller to point this at, so these run against payloads shaped
like the two published API generations. That covers the mapping and the read-only
guard; it does NOT prove the endpoints or field names are right on a real box. The
UniFi adapter looked correct too until it met live gear and needed three fixes, so
treat a green run here as "the logic holds", not "it works".
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import netwalk_omada as O  # noqa: E402

# Open API (controller 5.x) device shape
OPENAPI = [
    {"name": "SW-CORE", "mac": "AA-BB-CC-00-00-01", "ip": "10.1.1.2", "type": "switch",
     "model": "TL-SG3428MP", "firmwareVersion": "1.2.3", "status": 11, "uptimeLong": 950400,
     "cpuUtil": 17, "memUtil": 42, "poeRemain": 250,
     "ports": [{"port": 1, "name": "to AP1", "portStatus": {"linkStatus": 1, "linkSpeed": 1000}},
               {"port": 2, "portStatus": {"linkStatus": 0}}]},
    {"name": "AP-1", "mac": "AA-BB-CC-00-00-02", "ip": "10.1.1.11", "type": "ap",
     "model": "EAP670", "firmwareVersion": "1.0.11", "status": 11,
     "uplinkMac": "AA-BB-CC-00-00-01", "cpuUtil": 8, "memUtil": 55},
    {"name": "AP-2", "mac": "AA-BB-CC-00-00-03", "ip": "10.1.1.12", "type": "ap",
     "model": "EAP225", "firmwareVersion": "5.1.0", "status": 0,
     "uplinkDeviceName": "SW-CORE"},
    {"name": "GW-1", "mac": "AA-BB-CC-00-00-04", "ip": "10.1.1.1", "type": "gateway",
     "model": "ER605", "firmwareVersion": "2.2.4", "status": 11},
    {"name": "MYSTERY", "mac": "AA-BB-CC-00-00-05", "type": "somethingelse", "status": 11},
]

# older /api/v2 device shape
V2 = [
    {"name": "SW-OLD", "mac": "aa-bb-cc-11-11-01", "ip": "10.2.2.2", "type": "switch",
     "showModel": "T1600G-28TS", "version": "1.0.5", "status": "CONNECTED", "uptime": "3d 4h"},
    {"name": "AP-OLD", "mac": "aa-bb-cc-11-11-02", "ip": "10.2.2.3", "type": "ap",
     "deviceModel": "EAP245", "swVersion": "3.9.0", "status": "CONNECTED",
     "uplinkDeviceMac": "aa-bb-cc-11-11-01"},
]


def main() -> int:
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    devs = [O.map_device(d) for d in OPENAPI]
    by = {d["host_id"]: d for d in devs}

    check(by["SW-CORE"]["role"] == "switch", "switch role not mapped")
    check(by["AP-1"]["role"] == "ap", "ap role not mapped")
    check(by["GW-1"]["role"] == "gateway", "gateway role not mapped")
    check(by["MYSTERY"]["role"] == "unknown",
          f"an unrecognised type should stay unknown, got {by['MYSTERY']['role']!r}")
    check(by["AP-1"]["reachable"] and not by["AP-2"]["reachable"],
          "online/offline not read from status")
    check("unreachable_reason" in by["AP-2"], "an offline device carries no reason")
    check(by["SW-CORE"]["model"] == "TL-SG3428MP" and by["AP-OLD" if False else "AP-1"]["model"] == "EAP670",
          "model not mapped")
    check(by["SW-CORE"]["os_version"] == "1.2.3", "firmware not mapped")
    check(by["SW-CORE"]["uptime"] == "11d0h", f"uptime not mapped: {by['SW-CORE'].get('uptime')}")
    check(by["SW-CORE"]["vendor"] == "tplink", "vendor not set")

    h = by["SW-CORE"].get("health") or {}
    check(h.get("cpu_load_pct") == 17, f"cpu not mapped: {h}")
    check(h.get("memory_used_mb") == 42 and h.get("memory_total_mb") == 100,
          f"Omada memUtil is a percentage and must be recorded as one: {h}")
    check(h.get("poe_budget_w") == 250, f"poe not mapped: {h}")

    ports = by["SW-CORE"].get("interfaces") or []
    check(len(ports) == 2, f"ports not mapped: {ports}")
    check(ports[0].get("alias") == "to AP1" and ports[0].get("link_up") is True,
          f"port detail not mapped: {ports[0]}")

    edges = O.build_edges(devs)
    pairs = {(e["a_host"], e["b_host"]) for e in edges}
    check(("SW-CORE", "AP-1") in pairs, f"uplink by MAC not found: {pairs}")
    check(("SW-CORE", "AP-2") in pairs, f"uplink by device name not found: {pairs}")
    check(not any(a == b for a, b in pairs), "a device was linked to itself")

    v2 = [O.map_device(d) for d in V2]
    check(v2[0]["model"] == "T1600G-28TS" and v2[0]["os_version"] == "1.0.5",
          f"v2 shape not mapped: {v2[0]}")
    check(v2[0]["reachable"] and v2[0]["uptime"] == "3d 4h",
          f"v2 status/uptime not mapped: {v2[0]}")
    check(("SW-OLD", "AP-OLD") in {(e["a_host"], e["b_host"]) for e in O.build_edges(v2)},
          "v2 uplink not found")

    # read-only guard
    c = O.Omada({"ip": "127.0.0.1", "username": "cid", "api_token": "s"})
    for method, path in (("PUT", "/openapi/v1/a/sites/b/devices"),
                         ("DELETE", "/api/v2/sites/a"),
                         ("POST", "/openapi/v1/a/sites/b/devices/c/reboot"),
                         ("POST", "/a/api/v2/cmd/reboot")):
        try:
            c._request(path, method)
            fails.append(f"{method} {path} was NOT refused")
        except ValueError:
            pass
    for path in ("/openapi/authorize/token", "/abc/api/v2/login"):
        try:
            c._request(path, "POST", {})
        except ValueError:
            fails.append(f"the auth endpoint {path} was refused")
        except Exception:
            pass          # no server to talk to; only the guard matters here

    # an SSH port stored by the login form must not be used as a controller port
    check(22 not in O.Omada({"ip": "10.0.0.1", "port": 22}).candidates,
          "port 22 leaked through as a controller port")
    check(O.Omada({"ip": "10.0.0.1", "mgmt_url": "omada.example.com:8043"}).base
          == "https://omada.example.com:8043", "mgmt_url not honoured")

    total = 22
    for f in fails:
        print(f"  FAIL  {f}")
    print(f"\n{total - len(fails)}/{total} omada checks pass")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
