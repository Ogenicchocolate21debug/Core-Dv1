#!/usr/bin/env python3
"""UniFi controller adapter for netwalk.

A UniFi site is not really a pile of independent devices - it is one controller that
already knows every switch, AP and gateway it adopted, along with their model,
firmware, uptime, uplink, PoE draw and port state. Logging into a hundred APs over
SSH to rebuild that is slow, needs per-device credentials, and gets you less.

  netwalk_unifi.py sites   --site S --host H
  netwalk_unifi.py collect --site S --host H [--unifi-site default] --out fragment.json

READ-ONLY, enforced the same way the SSH side is: this module issues GET requests
and nothing else. The single exception is the legacy login POST, which creates a
session and changes no device configuration. There is no code path here that can
write to a controller - see `_request`.

Credentials come from the netwalk store (`method: "api"`, `api_token` for a UniFi OS
API key, or `username`/`password` for a legacy controller login). As everywhere else
in netwalk, the value is read by this process and never returned to the caller.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.cookiejar import CookieJar

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netwalk_common as C  # noqa: E402

TIMEOUT = 20


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def die(msg: str, code: int = 1):
    print(f"netwalk_unifi: {msg}", file=sys.stderr)
    raise SystemExit(code)


def load_host(site: str, host: str) -> dict:
    p = C.creds_dir() / f"{C.slugify(site)}.json"
    if not p.exists():
        die(f"no credential store for site {site!r}. Run /netwalk-login first.", 3)
    vault = json.loads(p.read_text(encoding="utf-8"))
    entry = vault.get("hosts", {}).get(host)
    if not entry:
        known = ", ".join(sorted(vault.get("hosts", {}))) or "(none)"
        die(f"host {host!r} is not in the {site!r} store. Known: {known}", 3)
    return entry


class Controller:
    """Minimal read-only UniFi client that speaks both API generations."""

    def __init__(self, entry: dict, verify: bool = False):
        # The form's "Management URL" wins: a controller rarely answers on the address
        # its devices use, and the person at the browser is the one who knows which.
        url = (entry.get("mgmt_url") or "").strip()
        if url:
            if "://" not in url:
                url = "https://" + url
            u = urllib.parse.urlsplit(url)
            port = u.port or (443 if u.scheme == "https" else 8443)
            self.base = f"{u.scheme}://{u.hostname}:{port}"
        else:
            host = entry.get("ip") or ""
            port = entry.get("port") or 8443
            self.base = f"https://{host}:{port}"
        self.api_key = entry.get("api_token")
        self.username = entry.get("username")
        self.password = entry.get("password")
        self.verify = verify
        self.flavour = None          # "integration" | "unifios" | "classic"
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(CookieJar()))
        self.csrf = None

    # -- transport ---------------------------------------------------------

    def _request(self, path: str, method: str = "GET", body: dict | None = None) -> tuple[int, object]:
        if method not in ("GET", "POST"):
            raise ValueError(f"netwalk_unifi issues GET and login-POST only, not {method}")
        if method == "POST" and not path.endswith(("/login", "/api/auth/login")):
            raise ValueError(f"refusing to POST to {path} - this adapter never writes")
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json", "User-Agent": "netwalk"}
        if data:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["X-API-KEY"] = self.api_key
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=TIMEOUT) as r:
                self.csrf = r.headers.get("X-CSRF-Token") or self.csrf
                raw = r.read().decode("utf-8", "replace")
                try:
                    return r.status, json.loads(raw)
                except json.JSONDecodeError:
                    return r.status, raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                return e.code, json.loads(raw)
            except json.JSONDecodeError:
                return e.code, raw
        except Exception as e:  # noqa: BLE001
            return 0, f"{type(e).__name__}: {e}"

    def get(self, path: str) -> tuple[int, object]:
        return self._request(path, "GET")

    # -- auth --------------------------------------------------------------

    def connect(self) -> str:
        """Work out which API this controller speaks and authenticate. Returns a note."""
        if self.api_key:
            code, body = self.get("/proxy/network/integration/v1/sites")
            if code == 200 and isinstance(body, dict) and "data" in body:
                self.flavour = "integration"
                return "UniFi OS Integration API (X-API-KEY)"
            if code in (401, 403):
                die("the controller rejected the API key (HTTP "
                    f"{code}). Check it was copied whole, and that the key has not expired.", 4)
        for path, flavour in (("/api/auth/login", "unifios"), ("/api/login", "classic")):
            if not (self.username and self.password):
                break
            code, body = self._request(path, "POST",
                                       {"username": self.username, "password": self.password})
            if code == 200:
                self.flavour = flavour
                return f"legacy login ({flavour})"
            if code in (401, 403):
                die(f"the controller rejected the username/password (HTTP {code})", 4)
        if self.api_key:
            die("could not reach the Integration API. On controllers older than "
                "UniFi Network 9 there is no API key - re-run /netwalk-login for this "
                "host and store a controller username and password instead.", 4)
        die("no usable credential: store an API key, or a username and password", 3)
        return ""

    def _prefix(self, unifi_site: str) -> str:
        return ("/proxy/network/api" if self.flavour == "unifios" else "/api")

    # -- reads -------------------------------------------------------------

    def list_sites(self) -> list[dict]:
        if self.flavour == "integration":
            code, body = self.get("/proxy/network/integration/v1/sites")
            return body.get("data", []) if code == 200 and isinstance(body, dict) else []
        code, body = self.get(f"{self._prefix('')}/self/sites")
        return body.get("data", []) if code == 200 and isinstance(body, dict) else []

    def devices(self, unifi_site: str) -> list[dict]:
        if self.flavour == "integration":
            out, offset = [], 0
            while True:
                code, body = self.get(
                    f"/proxy/network/integration/v1/sites/{unifi_site}/devices"
                    f"?limit=200&offset={offset}")
                if code != 200 or not isinstance(body, dict):
                    break
                page = body.get("data", [])
                out += page
                offset += len(page)
                if len(page) < 200 or offset >= (body.get("totalCount") or 0):
                    break
            return out
        code, body = self.get(f"{self._prefix(unifi_site)}/s/{unifi_site}/stat/device")
        return body.get("data", []) if code == 200 and isinstance(body, dict) else []

    def networks(self, unifi_site: str) -> list[dict]:
        code, body = self.get(f"{self._prefix(unifi_site)}/s/{unifi_site}/rest/networkconf")
        return body.get("data", []) if code == 200 and isinstance(body, dict) else []

    def wlans(self, unifi_site: str) -> list[dict]:
        code, body = self.get(f"{self._prefix(unifi_site)}/s/{unifi_site}/rest/wlanconf")
        return body.get("data", []) if code == 200 and isinstance(body, dict) else []

    def clients(self, unifi_site: str) -> list[dict]:
        code, body = self.get(f"{self._prefix(unifi_site)}/s/{unifi_site}/stat/sta")
        return body.get("data", []) if code == 200 and isinstance(body, dict) else []


# ------------------------------------------------------------ schema mapping

ROLE_BY_TYPE = {"ugw": "gateway", "udm": "gateway", "uxg": "gateway",
                "usw": "switch", "uap": "ap", "uph": "client", "ubb": "ap"}

SEC_MAP = {"open": "open", "wep": "wep", "wpapsk": "wpa2-personal", "wpaeap": "wpa2-enterprise",
           "wpa2": "wpa2-personal", "wpa3": "wpa3-personal", "wpa2/wpa3": "wpa2/3-mixed"}


def _mb(v):
    return round(v / 1024 / 1024, 1) if isinstance(v, (int, float)) and v else None


def map_device(d: dict) -> dict:
    """Turn one controller device record into a netwalk device."""
    name = d.get("name") or d.get("hostname") or d.get("mac") or "unnamed"
    dtype = (d.get("type") or "").lower()
    state = d.get("state")
    sysstats = d.get("sys_stats") or {}
    stat = d.get("system-stats") or {}

    dev = {
        "host_id": name,
        "hostname": name,
        "mgmt_ip": d.get("ip") or d.get("ipAddress"),
        "vendor": "ubiquiti",
        "model": d.get("model_name") or d.get("model") or d.get("shortname"),
        "serial": d.get("serial"),
        "os": "UniFi",
        "os_version": d.get("version") or d.get("firmwareVersion"),
        "role": ROLE_BY_TYPE.get(dtype, "switch" if "sw" in dtype else "unknown"),
        "reachable": state in (1, "ONLINE", "online") or d.get("state") == 1,
        "access_method": "controller",
    }
    if d.get("uptime"):
        s = int(d["uptime"])
        dev["uptime"] = f"{s//86400}d{(s%86400)//3600}h"
    if not dev["reachable"]:
        dev["unreachable_reason"] = f"controller reports state {state!r}"

    health = {}
    for key, target in (("cpu", "cpu_load_pct"), ("mem", "memory_used_mb")):
        v = stat.get(key) or sysstats.get(key)
        if v is not None:
            try:
                health[target] = float(v)
            except (TypeError, ValueError):
                pass
    if d.get("general_temperature") is not None:
        health["temperature_c"] = d["general_temperature"]
    total = _mb(d.get("sys_stats", {}).get("mem_total"))
    used = _mb(d.get("sys_stats", {}).get("mem_used"))
    if total:
        health["memory_total_mb"] = total
    if used:
        health["memory_used_mb"] = used
    if d.get("total_max_power") is not None:
        health["poe_budget_w"] = d["total_max_power"]
    poe = sum((p.get("poe_power") or 0) for p in (d.get("port_table") or [])
              if isinstance(p.get("poe_power"), (int, float)))
    if poe:
        health["poe_used_w"] = round(poe, 1)
    if health:
        health["sampled_at"] = now_iso()
        dev["health"] = health

    ports = []
    for p in d.get("port_table") or []:
        pi = {"name": str(p.get("name") or p.get("port_idx") or "?"),
              "alias": p.get("name") if p.get("port_idx") else None,
              "admin_up": p.get("enable", True),
              "link_up": bool(p.get("up")),
              "speed": f"{p.get('speed')}Mbps" if p.get("speed") else None,
              "rx_bytes": p.get("rx_bytes"), "tx_bytes": p.get("tx_bytes"),
              "rx_errors": p.get("rx_errors"), "tx_errors": p.get("tx_errors"),
              "rx_drops": p.get("rx_dropped"), "tx_drops": p.get("tx_dropped")}
        if p.get("poe_power"):
            pi["poe_out"] = f"{p['poe_power']}W"
        ports.append({k: v for k, v in pi.items() if v is not None})
    if ports:
        dev["interfaces"] = ports
    return dev


def map_wlans(wlans: list[dict], networks: list[dict]) -> list[dict]:
    vlan_by_id = {n.get("_id"): n.get("vlan") for n in networks}
    out = []
    for w in wlans:
        if not w.get("enabled", True):
            continue
        sec = (w.get("security") or "").lower()
        entry = {"ssid": w.get("name"),
                 "security": SEC_MAP.get(sec, sec or "unknown"),
                 "guest": bool(w.get("is_guest")),
                 "hidden": bool(w.get("hide_ssid"))}
        vlan = w.get("vlan") or vlan_by_id.get(w.get("networkconf_id"))
        if vlan:
            try:
                entry["vlan"] = int(vlan)
            except (TypeError, ValueError):
                pass
        out.append(entry)
    return out


def build_edges(devices: list[dict], raw: list[dict]) -> list[dict]:
    by_mac = {(d.get("mac") or "").lower(): (d.get("name") or d.get("mac")) for d in raw}
    edges = []
    for d in raw:
        up = d.get("uplink") or {}
        peer = (up.get("uplink_mac") or up.get("uplink_device_mac") or "").lower()
        if not peer or peer not in by_mac:
            continue
        me = d.get("name") or d.get("mac")
        edges.append({k: v for k, v in {
            "a_host": by_mac[peer], "a_port": str(up.get("uplink_remote_port") or "") or None,
            "b_host": me, "b_port": str(up.get("name") or up.get("uplink_device_port") or "") or None,
            "discovered_via": "controller",
            "speed": f"{up.get('speed')}Mbps" if up.get("speed") else None,
        }.items() if v})
    return edges


# --------------------------------------------------------------------- cmds

def _open(args) -> tuple[Controller, dict]:
    entry = load_host(args.site, args.host)
    ctrl = Controller(entry, verify=args.verify)
    note = ctrl.connect()
    if not args.verify:
        print("NOTE: the controller's TLS certificate was NOT verified. UniFi ships a "
              "self-signed certificate, so this is normal on a LAN - but it means this "
              "connection is not proof of the controller's identity. Pass --verify if "
              "the controller has a real certificate.", file=sys.stderr)
    print(f"connected to {ctrl.base} via {note}", file=sys.stderr)
    return ctrl, entry


def cmd_sites(args) -> int:
    ctrl, _ = _open(args)
    sites = ctrl.list_sites()
    if not sites:
        print("no sites returned - the credential may not have permission to list them")
        return 1
    for s in sites:
        sid = s.get("id") or s.get("name") or s.get("_id")
        print(f"  {sid:<28}{s.get('desc') or s.get('description') or ''}")
    print(f"\n{len(sites)} site(s). Pass one to `collect --unifi-site <id>`.")
    return 0


def cmd_collect(args) -> int:
    ctrl, entry = _open(args)
    usite = args.unifi_site or (entry.get("tenant") or "").strip() or None
    if not usite:
        sites = ctrl.list_sites()
        usite = (sites[0].get("id") or sites[0].get("name") or sites[0].get("_id")) if sites else "default"
        print(f"no --unifi-site given, using {usite!r}", file=sys.stderr)

    raw = ctrl.devices(usite)
    if not raw:
        print("the controller returned no devices - wrong site id, or the credential "
              "cannot read this site", file=sys.stderr)
        return 1
    networks = ctrl.networks(usite)
    wlans = ctrl.wlans(usite)

    devices = [map_device(d) for d in raw]
    wl = map_wlans(wlans, networks)
    for d in devices:
        if d["role"] == "ap" and wl:
            d["wireless_networks"] = wl

    vlans = [{k: v for k, v in {"id": n.get("vlan"), "name": n.get("name"),
                                "subnet": n.get("ip_subnet")}.items() if v}
             for n in networks if n.get("vlan")]

    fragment = {"generated_at": now_iso(), "unifi_site": usite,
                "controller": ctrl.base, "api": ctrl.flavour,
                "devices": devices, "topology_edges": build_edges(devices, raw),
                "vlans": vlans}

    out = args.out or "-"
    if out == "-":
        print(json.dumps(fragment, indent=2))
    else:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(fragment, fh, indent=2)
        counts = {}
        for d in devices:
            counts[d["role"]] = counts.get(d["role"], 0) + 1
        offline = sum(1 for d in devices if not d["reachable"])
        print(f"wrote {out}")
        print(f"  {len(devices)} device(s): " + ", ".join(f"{n}× {r}" for r, n in sorted(counts.items())))
        print(f"  {offline} offline, {len(fragment['topology_edges'])} uplink(s), "
              f"{len(vlans)} VLAN(s), {len(wl)} SSID(s)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="netwalk_unifi.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verify", action="store_true", help="verify the controller's TLS certificate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sites", help="list the sites this credential can see")
    s.add_argument("--site", required=True)
    s.add_argument("--host", required=True)
    s.set_defaults(func=cmd_sites)
    c = sub.add_parser("collect", help="read every adopted device into a scan-record fragment")
    c.add_argument("--site", required=True)
    c.add_argument("--host", required=True)
    c.add_argument("--unifi-site")
    c.add_argument("--out")
    c.set_defaults(func=cmd_collect)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
