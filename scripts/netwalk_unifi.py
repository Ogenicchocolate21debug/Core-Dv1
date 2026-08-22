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
import atexit
import json
import os
import shutil
import socket
import ssl
import subprocess
import time
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


class Tunnel:
    """An `ssh -L` hop for controllers that only answer from inside the site.

    A management VLAN that is not routed to the engineer's laptop is the normal
    case, not an edge case. This opens a local port that forwards through a host
    which IS reachable, so the adapter can talk to the controller unchanged.

    It needs LOCAL forwarding on the jump host. MikroTik ships `forwarding-enabled`
    set to `no` or `remote`, and `remote` looks like success - the listener opens and
    then no byte ever crosses - so that case is detected and named rather than left
    as a timeout.
    """

    def __init__(self, via: str, target_host: str, target_port: int):
        self.via = via
        self.target = f"{target_host}:{target_port}"
        self.proc = None
        self.local_port = None

    def _free_port(self) -> int:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def open(self) -> str:
        if not shutil.which("ssh"):
            die("--via needs an OpenSSH client on PATH", 4)
        self.local_port = self._free_port()
        argv = ["ssh", "-N", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"UserKnownHostsFile={C.known_hosts()}",
                "-L", f"{self.local_port}:{self.target}", self.via]
        self.proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        atexit.register(self.close)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                err = self.proc.stderr.read().decode("utf-8", "replace").strip()
                die(f"could not open the tunnel through {self.via}: {err[:300]}", 4)
            try:
                with socket.create_connection(("127.0.0.1", self.local_port), timeout=1):
                    return f"127.0.0.1:{self.local_port}"
            except OSError:
                time.sleep(0.3)
        die(f"the tunnel through {self.via} never came up", 4)
        return ""

    def explain_dead_tunnel(self) -> str:
        return (f"the tunnel to {self.target} through {self.via} accepted the connection but "
                f"carried no data. That is what a jump host that refuses LOCAL forwarding looks "
                f"like - the listener is ours, the far end is never opened. On RouterOS check "
                f"`/ip ssh print`: forwarding-enabled must be `local` or `both`, and `remote` "
                f"alone behaves exactly like this. Changing it is a configuration change, so "
                f"netwalk will not do it - ask the owner, or run netwalk from a host inside the "
                f"management network instead.")

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                self.proc.kill()


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
            port = entry.get("port")
            # 22 is the form's SSH default leaking through, never a controller port.
            self.candidates = ([port] if port and int(port) != 22 else [8443, 443, 8080])
            self.host = host
            self.base = f"https://{host}:{self.candidates[0]}"
        self.api_key = entry.get("api_token")
        self.username = entry.get("username")
        self.password = entry.get("password")
        self.verify = verify
        self.flavour = None          # "integration" | "unifios" | "classic"
        self.candidates = getattr(self, "candidates", None)
        self.host = getattr(self, "host", entry.get("ip") or "")
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
        if self.candidates and len(self.candidates) > 1:
            for port in self.candidates:
                scheme = "http" if port == 8080 else "https"
                self.base = f"{scheme}://{self.host}:{port}"
                code, _ = self.get("/")
                if code:
                    print(f"controller answers on {self.base}", file=sys.stderr)
                    break
            else:
                die(f"nothing answered on {self.host} ports "
                    f"{', '.join(str(p) for p in self.candidates)}. Put the real address "
                    f"in 'Management URL' on the login form.", 4)
        if self.api_key:
            code, body = self.get("/proxy/network/integration/v1/sites")
            if code == 200 and isinstance(body, dict) and "data" in body:
                self.flavour = "integration"
                return "UniFi OS Integration API (X-API-KEY)"
            if code == 0:
                # No HTTP status at all: the connection itself failed. Blaming the
                # credential here sends people to rotate a key that was never used.
                die(f"no HTTP response from {self.base} - {body}. This is a transport "
                    f"problem, not a credential problem.", 4)
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


def _integration_shape(d: dict) -> bool:
    """The Integration API and the classic /stat/device API share almost no field
    names. Detect which one produced this record instead of guessing."""
    return "macAddress" in d or "firmwareVersion" in d


def _role_from_features(features: list, model: str) -> str:
    f = {str(x).lower() for x in (features or [])}
    if f & {"gateway", "routing"}:
        return "gateway"
    if "accesspoint" in f:
        return "ap"          # an AP with a switch port is still an AP
    if "switching" in f:
        return "switch"
    m = (model or "").upper()
    if m.startswith(("US", "USW")):
        return "switch"
    if m.startswith(("UAP", "U6", "U7", "AC")):
        return "ap"
    return "unknown"


def map_device(d: dict) -> dict:
    """Turn one controller device record into a netwalk device."""
    if _integration_shape(d):
        name = d.get("name") or d.get("macAddress") or "unnamed"
        state = str(d.get("state") or "").upper()
        dev = {
            "host_id": name,
            "hostname": name,
            "mgmt_ip": d.get("ipAddress"),
            "vendor": "ubiquiti",
            "model": d.get("model"),
            "os": "UniFi",
            "os_version": d.get("firmwareVersion"),
            "role": _role_from_features(d.get("features"), d.get("model")),
            "reachable": state == "ONLINE",
            "access_method": "controller",
        }
        if state != "ONLINE":
            dev["unreachable_reason"] = f"the controller reports this device as {state or 'unknown'}"
        if d.get("supported") is False:
            dev["unreachable_reason"] = (dev.get("unreachable_reason") or "") + \
                " (the controller marks this model unsupported)"
        ports = []
        for pt in ((d.get("interfaces") or {}).get("ports") or []
                   if isinstance(d.get("interfaces"), dict) else []):
            pi = {"name": str(pt.get("idx") or pt.get("name") or "?"),
                  "link_up": (str(pt.get("state") or "").upper() == "UP") or None,
                  "speed": f"{pt.get('speedMbps')}Mbps" if pt.get("speedMbps") else None,
                  "poe_out": f"{pt.get('poe', {}).get('power')}W"
                             if isinstance(pt.get("poe"), dict) and pt["poe"].get("power") else None}
            ports.append({k: v for k, v in pi.items() if v is not None})
        if ports:
            dev["interfaces"] = ports
        up = d.get("uplink") or {}
        if up.get("deviceId"):
            dev["_uplink_device_id"] = up["deviceId"]
        dev["_id"] = d.get("id")
        dev["_firmware_updatable"] = bool(d.get("firmwareUpdatable"))
        return dev

    # ---- classic /stat/device shape ----
    name = d.get("name") or d.get("hostname") or d.get("mac") or "unnamed"
    dtype = (d.get("type") or "").lower()
    state = d.get("state")
    sysstats = d.get("sys_stats") or {}
    stat = d.get("system-stats") or {}

    dev = {
        "host_id": name,
        "hostname": name,
        "mgmt_ip": d.get("ip"),
        "vendor": "ubiquiti",
        "model": d.get("model_name") or d.get("model") or d.get("shortname"),
        "serial": d.get("serial"),
        "os": "UniFi",
        "os_version": d.get("version"),
        "role": ROLE_BY_TYPE.get(dtype, "switch" if "sw" in dtype else "unknown"),
        "reachable": state in (1, "ONLINE", "online"),
        "access_method": "controller",
    }
    if d.get("uptime"):
        sec = int(d["uptime"])
        dev["uptime"] = f"{sec//86400}d{(sec%86400)//3600}h"
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
              "admin_up": p.get("enable", True), "link_up": bool(p.get("up")),
              "speed": f"{p.get('speed')}Mbps" if p.get("speed") else None,
              "rx_bytes": p.get("rx_bytes"), "tx_bytes": p.get("tx_bytes"),
              "rx_errors": p.get("rx_errors"), "tx_errors": p.get("tx_errors")}
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
    by_id = {d.get("_id"): d["host_id"] for d in devices if d.get("_id")}
    edges = []
    for d in devices:
        peer = by_id.get(d.get("_uplink_device_id"))
        if peer and peer != d["host_id"]:
            edges.append({"a_host": peer, "b_host": d["host_id"],
                          "discovered_via": "controller"})
    if edges:
        return edges

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
    via = args.via or entry.get("jump_host")
    tun = None
    if via:
        host = entry.get("ip")
        port = entry.get("port")
        if not port or int(port) == 22:
            port = 8443
        tun = Tunnel(via, host, int(port))
        local = tun.open()
        print(f"tunnelling to {host}:{port} through {via}", file=sys.stderr)
        entry = {**entry, "mgmt_url": f"https://{local}", "ip": "127.0.0.1", "port": None}
    ctrl = Controller(entry, verify=args.verify)
    ctrl._tunnel = tun
    try:
        note = ctrl.connect()
    except SystemExit:
        if tun:
            print(tun.explain_dead_tunnel(), file=sys.stderr)
        raise
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
    if raw and args.detail and ctrl.flavour == "integration":
        print(f"fetching uplink detail for {len(raw)} device(s) - one request each",
              file=sys.stderr)
        for i, r in enumerate(raw):
            if not r.get("id"):
                continue
            code, body = ctrl.get(
                f"/proxy/network/integration/v1/sites/{usite}/devices/{r['id']}")
            if code == 200 and isinstance(body, dict):
                r.update({k: v for k, v in body.items() if k not in r or k == "uplink"})
            if (i + 1) % 25 == 0:
                print(f"  {i+1}/{len(raw)}", file=sys.stderr)
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

    edges = build_edges(devices, raw)
    updatable = [d["host_id"] for d in devices if d.get("_firmware_updatable")]
    for d in devices:                       # internal join keys, not part of the schema
        d.pop("_id", None)
        d.pop("_uplink_device_id", None)
        d.pop("_firmware_updatable", None)

    fragment = {"generated_at": now_iso(), "unifi_site": usite,
                "firmware_updatable": updatable,
                "controller": ctrl.base, "api": ctrl.flavour,
                "devices": devices, "topology_edges": edges,
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
        if updatable:
            print(f"  {len(updatable)} device(s) have a firmware update available")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="netwalk_unifi.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verify", action="store_true", help="verify the controller's TLS certificate")
    ap.add_argument("--via", metavar="user@host",
                    help="reach the controller through an SSH tunnel on this host. "
                         "The jump host must permit LOCAL forwarding.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sites", help="list the sites this credential can see")
    s.add_argument("--site", required=True)
    s.add_argument("--host", required=True)
    s.add_argument("--via", metavar="user@host", help="SSH tunnel through this host")
    s.add_argument("--verify", action="store_true")
    s.set_defaults(func=cmd_sites)
    c = sub.add_parser("collect", help="read every adopted device into a scan-record fragment")
    c.add_argument("--site", required=True)
    c.add_argument("--host", required=True)
    c.add_argument("--via", metavar="user@host", help="SSH tunnel through this host")
    c.add_argument("--verify", action="store_true")
    c.add_argument("--unifi-site")
    c.add_argument("--out")
    c.add_argument("--no-detail", dest="detail", action="store_false",
                   help="skip the per-device detail fetch (faster, but no topology)")
    c.set_defaults(detail=True)
    c.set_defaults(func=cmd_collect)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
