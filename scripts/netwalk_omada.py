#!/usr/bin/env python3
"""TP-Link Omada controller adapter for netwalk.

Same idea as the UniFi adapter: an Omada site is one controller that already knows
every adopted switch, AP and gateway, so read it once instead of logging into a
hundred devices.

  netwalk_omada.py info    --site S --host H     # reachable? which controller? no auth needed
  netwalk_omada.py sites   --site S --host H
  netwalk_omada.py collect --site S --host H [--omada-site <id>] --out fragment.json

READ-ONLY, enforced structurally: `_request` issues GET, plus a POST whose path is
one of the two authentication endpoints. Every other method or path raises before a
socket is opened, so there is no code path here that can change a controller.

Two API generations are supported and detected at runtime:
  * Open API (controller 5.x, Settings > Platform Integration > Open API) -
    client_id + client_secret, bearer AccessToken.
  * Session login (controller 4.x/5.x web API) - username + password, CSRF token.

Credentials come from the netwalk store:
  Open API : method=api, username = client_id, api_token = client_secret
  Session  : method=api or password, username + password
  tenant   : the Omada site id or name, if you already know it
  mgmt_url : the controller address, e.g. https://omada.example.com:8043

WRITTEN FROM THE PUBLISHED API SHAPE AND NOT YET RUN AGAINST A LIVE CONTROLLER.
The UniFi adapter needed three fixes the first time it met real gear; expect the
same here, and read `info` output before trusting `collect`.
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
from netwalk_unifi import Tunnel  # noqa: E402  - the tunnel is not UniFi-specific

TIMEOUT = 25
AUTH_PATHS = ("/openapi/authorize/token", "/api/v2/login", "/api/v2/hotspot/login")


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def die(msg: str, code: int = 1):
    print(f"netwalk_omada: {msg}", file=sys.stderr)
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
    if entry.get("method") == "not-ours":
        die(f"{host!r} was marked OUT OF SCOPE on the login form.", 5)
    return entry


class Omada:
    def __init__(self, entry: dict, verify: bool = False):
        url = (entry.get("mgmt_url") or "").strip()
        if url:
            if "://" not in url:
                url = "https://" + url
            u = urllib.parse.urlsplit(url)
            port = u.port or (443 if u.scheme == "https" else 8043)
            self.base = f"{u.scheme}://{u.hostname}:{port}"
            self.candidates = [port]
        else:
            host = entry.get("ip") or ""
            port = entry.get("port")
            # 22 is the login form's SSH default leaking through, never a controller port
            self.candidates = ([int(port)] if port and int(port) != 22 else [8043, 443, 8088])
            self.host = host
            self.base = f"https://{host}:{self.candidates[0]}"
        self.host = entry.get("ip") or urllib.parse.urlsplit(self.base).hostname
        self.client_id = entry.get("username")
        self.client_secret = entry.get("api_token")
        self.password = entry.get("password")
        self.omadac_id = None
        self.controller_version = None
        self.flavour = None
        self.token = None
        self.csrf = None
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(CookieJar()))

    # -- transport ---------------------------------------------------------

    def _request(self, path: str, method: str = "GET", body: dict | None = None) -> tuple[int, object]:
        if method not in ("GET", "POST"):
            raise ValueError(f"netwalk_omada issues GET and auth-POST only, not {method}")
        if method == "POST" and not any(a in path for a in AUTH_PATHS):
            raise ValueError(f"refusing to POST to {path} - this adapter never writes")
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json", "User-Agent": "netwalk"}
        if data:
            headers["Content-Type"] = "application/json"
        if self.token and self.flavour == "openapi":
            headers["Authorization"] = f"AccessToken={self.token}"
        if self.csrf:
            headers["Csrf-Token"] = self.csrf
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=TIMEOUT) as r:
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

    # -- discovery + auth --------------------------------------------------

    def probe(self) -> dict:
        """`/api/info` needs no credential and names the controller. Always call it
        first: it separates "wrong address" from "wrong credential", which are the
        two failures that look identical from the outside."""
        for port in self.candidates:
            for scheme in ("https", "http"):
                if port == 8088 and scheme == "https":
                    continue
                self.base = f"{scheme}://{self.host}:{port}"
                code, body = self.get("/api/info")
                if code == 200 and isinstance(body, dict):
                    res = body.get("result") or {}
                    self.omadac_id = res.get("omadacId")
                    self.controller_version = res.get("controllerVer") or res.get("controllerVersion")
                    return {"base": self.base, "omadac_id": self.omadac_id,
                            "version": self.controller_version, "raw": res}
        die(f"nothing answered /api/info on {self.host} ports "
            f"{', '.join(str(p) for p in self.candidates)}. Put the controller address in "
            f"'Management URL' on the login form (e.g. https://omada.example.com:8043).", 4)
        return {}

    def connect(self) -> str:
        info = self.probe()
        if not self.omadac_id:
            die("the controller answered /api/info but gave no omadacId - this may not be "
                f"an Omada controller. It said: {str(info.get('raw'))[:200]}", 4)

        if self.client_id and self.client_secret:
            code, body = self._request(
                "/openapi/authorize/token?grant_type=client_credentials", "POST",
                {"omadacId": self.omadac_id, "client_id": self.client_id,
                 "client_secret": self.client_secret})
            if code == 200 and isinstance(body, dict) and (body.get("result") or {}).get("accessToken"):
                self.flavour = "openapi"
                self.token = body["result"]["accessToken"]
                return f"Open API (controller {self.controller_version})"
            if code == 0:
                die(f"no HTTP response from {self.base} - {body}. Transport problem, not a "
                    f"credential problem.", 4)
            msg = (body.get("msg") if isinstance(body, dict) else str(body))
            print(f"Open API rejected the client_id/client_secret ({code}: {msg}). "
                  f"Trying the session login.", file=sys.stderr)

        user = self.client_id
        if user and self.password:
            code, body = self._request(f"/{self.omadac_id}/api/v2/login", "POST",
                                       {"username": user, "password": self.password})
            if code == 200 and isinstance(body, dict) and (body.get("result") or {}).get("token"):
                self.flavour = "session"
                self.token = body["result"]["token"]
                self.csrf = self.token
                return f"session login (controller {self.controller_version})"
            msg = (body.get("msg") if isinstance(body, dict) else str(body))
            die(f"the controller rejected the username/password ({code}: {msg})", 4)

        die("no usable credential. For Open API store the client_id as the username and the "
            "client_secret as the API token; for the older API store a controller username "
            "and password.", 3)
        return ""

    # -- reads -------------------------------------------------------------

    def _paged(self, path: str, key: str = "data") -> list[dict]:
        out, page = [], 1
        while True:
            sep = "&" if "?" in path else "?"
            code, body = self.get(f"{path}{sep}currentPage={page}&currentPageSize=100"
                                  f"&page={page}&pageSize=100")
            if code != 200 or not isinstance(body, dict):
                break
            res = body.get("result") or {}
            rows = res.get(key) or res.get("list") or []
            if not isinstance(rows, list):
                break
            out += rows
            total = res.get("totalRows") or res.get("total") or len(out)
            if len(rows) < 100 or len(out) >= total:
                break
            page += 1
        return out

    def list_sites(self) -> list[dict]:
        if self.flavour == "openapi":
            return self._paged(f"/openapi/v1/{self.omadac_id}/sites")
        return self._paged(f"/{self.omadac_id}/api/v2/sites?token={self.token}")

    def devices(self, site_id: str) -> list[dict]:
        if self.flavour == "openapi":
            return self._paged(f"/openapi/v1/{self.omadac_id}/sites/{site_id}/devices")
        code, body = self.get(f"/{self.omadac_id}/api/v2/sites/{site_id}/devices"
                              f"?token={self.token}")
        if code == 200 and isinstance(body, dict):
            res = body.get("result")
            if isinstance(res, list):
                return res
            if isinstance(res, dict):
                return res.get("data") or res.get("list") or []
        return []


# ------------------------------------------------------------ schema mapping

ROLE_BY_TYPE = {"ap": "ap", "switch": "switch", "gateway": "gateway", "router": "gateway"}
ONLINE = {1, 4, 10, 11, 12, "CONNECTED", "connected", "ONLINE", "online"}


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def map_device(d: dict) -> dict:
    name = d.get("name") or d.get("mac") or "unnamed"
    dtype = str(d.get("type") or "").lower()
    status = d.get("status")
    if isinstance(status, str):
        status = status.strip()
    dev = {
        "host_id": name,
        "hostname": name,
        "mgmt_ip": d.get("ip") or d.get("ipAddress"),
        "vendor": "tplink",
        "model": d.get("model") or d.get("showModel") or d.get("deviceModel"),
        "serial": d.get("sn") or d.get("serialNumber"),
        "os": "Omada",
        "os_version": d.get("firmwareVersion") or d.get("version") or d.get("swVersion"),
        "role": ROLE_BY_TYPE.get(dtype, "unknown"),
        "reachable": status in ONLINE,
        "access_method": "controller",
    }
    if not dev["reachable"]:
        dev["unreachable_reason"] = f"the controller reports status {status!r}"
    up = d.get("uptimeLong") or d.get("uptime")
    if isinstance(up, (int, float)) and up:
        s = int(up)
        dev["uptime"] = f"{s//86400}d{(s%86400)//3600}h"
    elif isinstance(up, str) and up:
        dev["uptime"] = up

    health = {}
    for src, target in (("cpuUtil", "cpu_load_pct"), ("memUtil", "memory_used_mb")):
        v = _num(d.get(src))
        if v is not None:
            health[target] = v
    if _num(d.get("memUtil")) is not None:      # Omada reports a percentage, not MB
        health.pop("memory_used_mb", None)
        health["memory_total_mb"] = 100.0
        health["memory_used_mb"] = _num(d["memUtil"])
    for src, target in (("poeRemain", "poe_budget_w"), ("poePower", "poe_used_w"),
                        ("temperature", "temperature_c")):
        v = _num(d.get(src))
        if v is not None:
            health[target] = v
    if health:
        health["sampled_at"] = now_iso()
        dev["health"] = health

    ports = []
    for p in (d.get("ports") or d.get("portList") or []):
        if not isinstance(p, dict):
            continue
        st = p.get("portStatus") or {}
        pi = {"name": str(p.get("port") or p.get("portName") or "?"),
              "alias": p.get("name") or None,
              "link_up": bool(st.get("linkStatus") or p.get("linkStatus")) or None,
              "speed": (f"{st.get('linkSpeed') or p.get('linkSpeed')}"
                        if (st.get("linkSpeed") or p.get("linkSpeed")) else None),
              "rx_bytes": _num(st.get("rxRate")), "tx_bytes": _num(st.get("txRate"))}
        ports.append({k: v for k, v in pi.items() if v is not None})
    if ports:
        dev["interfaces"] = ports

    dev["_mac"] = (d.get("mac") or "").lower()
    dev["_uplink_mac"] = (d.get("uplinkMac") or d.get("uplinkDeviceMac") or "").lower()
    dev["_uplink_name"] = d.get("uplinkDeviceName") or ""
    return dev


def build_edges(devices: list[dict]) -> list[dict]:
    by_mac = {d["_mac"]: d["host_id"] for d in devices if d.get("_mac")}
    by_name = {d["host_id"]: d["host_id"] for d in devices}
    edges = []
    for d in devices:
        peer = by_mac.get(d.get("_uplink_mac")) or by_name.get(d.get("_uplink_name"))
        if peer and peer != d["host_id"]:
            edges.append({"a_host": peer, "b_host": d["host_id"],
                          "discovered_via": "controller"})
    return edges


# --------------------------------------------------------------------- cmds

def _open(args) -> tuple[Omada, dict]:
    entry = load_host(args.site, args.host)
    via = getattr(args, "via", None) or entry.get("jump_host")
    tun = None
    if via:
        port = entry.get("port")
        port = 8043 if (not port or int(port) == 22) else int(port)
        tun = Tunnel(via, entry.get("ip"), port)
        local = tun.open()
        print(f"tunnelling to {entry.get('ip')}:{port} through {via}", file=sys.stderr)
        entry = {**entry, "mgmt_url": f"https://{local}", "ip": "127.0.0.1", "port": None}
    ctrl = Omada(entry, verify=args.verify)
    if not args.verify:
        print("NOTE: the controller's TLS certificate was NOT verified. Omada ships a "
              "self-signed certificate, so this is normal on a LAN - but it is not proof "
              "of the controller's identity. Pass --verify if it has a real certificate.",
              file=sys.stderr)
    try:
        note = ctrl.connect()
    except SystemExit:
        if tun:
            print(tun.explain_dead_tunnel(), file=sys.stderr)
        raise
    print(f"connected to {ctrl.base} via {note}", file=sys.stderr)
    return ctrl, entry


def cmd_info(args) -> int:
    entry = load_host(args.site, args.host)
    ctrl = Omada(entry, verify=args.verify)
    info = ctrl.probe()
    print(f"controller   : {info['base']}")
    print(f"omadacId     : {info.get('omadac_id')}")
    print(f"version      : {info.get('version')}")
    print("\nNo credential was used for this - it only proves the address is right.")
    return 0


def cmd_sites(args) -> int:
    ctrl, _ = _open(args)
    sites = ctrl.list_sites()
    if not sites:
        print("no sites returned - the credential may not be allowed to list them")
        return 1
    for s in sites:
        print(f"  {str(s.get('siteId') or s.get('id') or s.get('key')):<28}"
              f"{s.get('name') or s.get('siteName') or ''}")
    print(f"\n{len(sites)} site(s). Pass one to `collect --omada-site <id>`.")
    return 0


def cmd_collect(args) -> int:
    ctrl, entry = _open(args)
    sid = args.omada_site or (entry.get("tenant") or "").strip() or None
    if not sid:
        sites = ctrl.list_sites()
        if not sites:
            die("no site id given and the controller listed none", 1)
        sid = sites[0].get("siteId") or sites[0].get("id") or sites[0].get("key")
        print(f"no --omada-site given, using {sid!r}", file=sys.stderr)

    raw = ctrl.devices(sid)
    if not raw:
        print("the controller returned no devices - wrong site id, or the credential "
              "cannot read this site", file=sys.stderr)
        return 1
    devices = [map_device(d) for d in raw]
    edges = build_edges(devices)
    unknown = [d["host_id"] for d in devices if d["role"] == "unknown"]
    for d in devices:
        for k in ("_mac", "_uplink_mac", "_uplink_name"):
            d.pop(k, None)

    fragment = {"generated_at": now_iso(), "omada_site": sid, "controller": ctrl.base,
                "api": ctrl.flavour, "controller_version": ctrl.controller_version,
                "devices": devices, "topology_edges": edges}
    out = args.out or "-"
    if out == "-":
        print(json.dumps(fragment, indent=2))
    else:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(fragment, fh, indent=2)
        counts: dict[str, int] = {}
        for d in devices:
            counts[d["role"]] = counts.get(d["role"], 0) + 1
        offline = sum(1 for d in devices if not d["reachable"])
        print(f"wrote {out}")
        print(f"  {len(devices)} device(s): "
              + ", ".join(f"{n}x {r}" for r, n in sorted(counts.items())))
        print(f"  {offline} offline, {len(edges)} uplink(s)")
        if unknown:
            print(f"  {len(unknown)} device(s) had a type this adapter does not recognise "
                  f"and were left as role=unknown: {', '.join(unknown[:5])}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="netwalk_omada.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn, extra in (("info", cmd_info, False), ("sites", cmd_sites, True),
                            ("collect", cmd_collect, True)):
        p = sub.add_parser(name)
        p.add_argument("--site", required=True)
        p.add_argument("--host", required=True)
        p.add_argument("--verify", action="store_true")
        if extra:
            p.add_argument("--via", metavar="user@host", help="SSH tunnel through this host")
        if name == "collect":
            p.add_argument("--omada-site")
            p.add_argument("--out")
        p.set_defaults(func=fn)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
