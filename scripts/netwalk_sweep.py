#!/usr/bin/env python3
"""Subnet sweep and well-known port scan for netwalk.

netwalk crawls *from* devices it can log into. That finds the managed estate, and it
misses everything that never speaks LLDP and never appears in an ARP table you read.
This module is the other half: given a range the site owner has explicitly authorised,
it says which addresses answer and which TCP services they answer with.

Three rules hold it in place, and all three are enforced here in code:

  1. **Nothing is swept that was not authorised.** A range must be written into
     `<site>/scope.json` by `authorize`, with the name of the person who said yes.
     Every single address is checked against that scope before a packet leaves.
     There is no --force.
  2. **Read-only means read-only.** TCP connect and nothing else - no SYN games, no
     OS fingerprinting, no NSE-style probes, no writes. A connection is opened and
     immediately closed. Banner grabbing is off unless asked for, and reads at most
     one short response.
  3. **The size is bounded before the first probe**, not discovered halfway through.
     A /16 is refused outright, a projected probe count over the cap is refused, and
     the numbers are printed before anything runs.

What this deliberately cannot see, and what the report must say so:
UDP services (SNMP, DNS over UDP, IPMI, syslog, IKE), anything behind a host firewall
that drops instead of rejecting, and anything on a port outside the list that was used.
"""
from __future__ import annotations

import argparse
import atexit
import ipaddress
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netwalk_common as C  # noqa: E402

# --------------------------------------------------------------------- limits

# A /16 is 65k addresses. If someone really means it they can authorise the /24s.
MAX_PREFIX_V4 = 16
MAX_PREFIX_V6 = 112
MAX_HOSTS_DEFAULT = 4096
MAX_HOSTS_CEILING = 65536
MAX_PROBES = 200_000          # hosts x ports, checked before anything runs
MAX_PORTS = 2048

# Ranges we accept without an extra promise from the user. Everything else is
# someone's public address space, where an unauthorised sweep is not a mistake,
# it is an offence in several of the places netwalk gets used.
PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
        "fc00::/7", "fe80::/10", "::1/128",
    )
]

# ---------------------------------------------------------------------- ports

# Liveness probe set for a host sweep. A REFUSED connection proves a host is there
# just as well as an open one does, so a box with everything closed still shows up.
LIVENESS_PORTS = [443, 80, 22, 445, 3389, 8291, 53, 23]

# TCP only - see the module docstring. `service` is what the port conventionally is;
# `risk` is set when finding it open is worth a line in the report by itself.
WELL_KNOWN: dict[int, tuple[str, str]] = {
    21:    ("ftp", "clear-text file transfer and credentials"),
    22:    ("ssh", ""),
    23:    ("telnet", "clear-text admin session - credentials cross the wire in the clear"),
    25:    ("smtp", ""),
    53:    ("dns-tcp", ""),
    80:    ("http", ""),
    88:    ("kerberos", ""),
    110:   ("pop3", "clear-text mail login"),
    111:   ("rpcbind", "portmapper exposes the RPC service list"),
    135:   ("msrpc", "Windows RPC endpoint mapper"),
    139:   ("netbios-ssn", "legacy SMB transport"),
    143:   ("imap", "clear-text mail login"),
    389:   ("ldap", ""),
    443:   ("https", ""),
    445:   ("smb", "file sharing - a very common ransomware entry point"),
    465:   ("smtps", ""),
    515:   ("lpd", ""),
    548:   ("afp", ""),
    587:   ("submission", ""),
    636:   ("ldaps", ""),
    873:   ("rsync", "rsync daemon, often with no authentication at all"),
    902:   ("vmware-auth", ""),
    993:   ("imaps", ""),
    995:   ("pop3s", ""),
    1080:  ("socks", "open proxy if unauthenticated"),
    1433:  ("mssql", "database reachable from the network"),
    1521:  ("oracle", "database reachable from the network"),
    1723:  ("pptp", "obsolete VPN protocol, broken encryption"),
    1883:  ("mqtt", "IoT broker, frequently unauthenticated"),
    2049:  ("nfs", "file sharing, often IP-authenticated only"),
    2082:  ("cpanel", ""),
    2083:  ("cpanel-ssl", ""),
    2222:  ("ssh-alt", ""),
    3000:  ("http-dev", "dev server or Grafana"),
    3128:  ("squid", "open proxy if unauthenticated"),
    3268:  ("ldap-gc", ""),
    3306:  ("mysql", "database reachable from the network"),
    3389:  ("rdp", "remote desktop - brute-force and CVE magnet"),
    4443:  ("https-alt", ""),
    5000:  ("http-alt", ""),
    5060:  ("sip", ""),
    5432:  ("postgresql", "database reachable from the network"),
    5601:  ("kibana", "often unauthenticated"),
    5900:  ("vnc", "remote desktop, frequently with no password"),
    5985:  ("winrm", ""),
    5986:  ("winrm-ssl", ""),
    6379:  ("redis", "unauthenticated by default - full data access"),
    7547:  ("tr-069", "ISP remote management, a known mass-compromise vector"),
    8000:  ("http-alt", ""),
    8006:  ("proxmox", "hypervisor management interface"),
    8008:  ("http-alt", ""),
    8080:  ("http-proxy", ""),
    8081:  ("http-alt", ""),
    8088:  ("http-alt", ""),
    8090:  ("http-alt", ""),
    8123:  ("home-assistant", ""),
    8291:  ("winbox", "MikroTik management - must never answer on a WAN address"),
    8443:  ("https-alt", ""),
    8728:  ("mikrotik-api", "MikroTik API, clear text"),
    8729:  ("mikrotik-api-ssl", ""),
    8843:  ("unifi-portal", ""),
    8880:  ("unifi-http", ""),
    9000:  ("portainer", "container management"),
    9090:  ("cockpit", "host management or Prometheus"),
    9200:  ("elasticsearch", "unauthenticated by default"),
    10000: ("webmin", "full host management interface"),
    27017: ("mongodb", "unauthenticated by default"),
    32400: ("plex", ""),
}

PROFILES = {
    "quick": [21, 22, 23, 80, 443, 445, 3389, 8080, 8291, 8443],
    "standard": sorted(WELL_KNOWN),
}


def service_of(port: int) -> str:
    return WELL_KNOWN.get(port, ("unknown", ""))[0]


def risk_of(port: int) -> str:
    return WELL_KNOWN.get(port, ("unknown", ""))[1]


# --------------------------------------------------------------------- basics

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def die(msg: str, code: int = 1):
    print(f"netwalk_sweep: {msg}", file=sys.stderr)
    raise SystemExit(code)


def parse_ports(spec: str) -> list[int]:
    """`22,80,8000-8010` -> sorted unique ports. Raises ValueError on nonsense."""
    out: set[int] = set()
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, _, hi_s = chunk.partition("-")
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise ValueError(f"range {chunk} runs backwards")
            if hi - lo > MAX_PORTS:
                raise ValueError(f"range {chunk} is wider than {MAX_PORTS} ports")
            out.update(range(lo, hi + 1))
        else:
            out.add(int(chunk))
    if not out:
        raise ValueError("no ports given")
    for p in out:
        if not 1 <= p <= 65535:
            raise ValueError(f"{p} is not a TCP port")
    if len(out) > MAX_PORTS:
        raise ValueError(f"{len(out)} ports is more than the {MAX_PORTS} cap")
    return sorted(out)


def is_private(net: ipaddress._BaseNetwork) -> bool:
    return any(net.subnet_of(p) for p in PRIVATE_NETS if p.version == net.version)


# ---------------------------------------------------------------------- scope

def scope_path(site: str) -> Path:
    return C.site_dir(site) / "scope.json"


def load_scope(site: str) -> dict:
    p = scope_path(site)
    if not p.exists():
        return {"site": C.slugify(site), "authorized": [], "excluded": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        die(f"{p} is not readable JSON: {e}", 3)


def save_scope(site: str, scope: dict) -> Path:
    p = scope_path(site)
    p.write_text(json.dumps(scope, indent=2) + "\n", encoding="utf-8")
    return p


def authorized_nets(scope: dict) -> list:
    return [ipaddress.ip_network(a["cidr"]) for a in scope.get("authorized", [])]


def excluded_addrs(scope: dict) -> set:
    out = set()
    for item in scope.get("excluded", []):
        try:
            for a in ipaddress.ip_network(item, strict=False):
                out.add(a)
        except ValueError:
            continue
    return out


def check_in_scope(scope: dict, target: str) -> tuple[bool, str]:
    """Is `target` (an address or a CIDR) entirely inside the authorised scope?"""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError as e:
        return False, f"{target!r} is not an address or CIDR: {e}"
    nets = authorized_nets(scope)
    if not nets:
        return False, ("nothing is authorised for this site yet - run "
                       "`netwalk_sweep.py authorize --site <slug> --range <cidr> "
                       "--authorized-by '<who said yes, and when>'` first")
    if not any(net.subnet_of(a) for a in nets if a.version == net.version):
        have = ", ".join(str(a) for a in nets) or "nothing"
        return False, (f"{net} is outside the authorised scope for this site "
                       f"(authorised: {have}). Ask the owner and authorise it - "
                       f"there is no override flag")
    return True, "in scope"


def who_authorized(scope: dict, target: str) -> str:
    """Whose name is on the authorisation that covers `target`. Goes in the report."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return ""
    for a in scope.get("authorized", []):
        auth = ipaddress.ip_network(a["cidr"])
        if auth.version == net.version and net.subnet_of(auth):
            return a.get("authorized_by", "")
    return ""


def targets_of(target: str, scope: dict, max_hosts: int) -> list[str]:
    """Expand a CIDR or single address into the addresses we will actually probe."""
    ok, why = check_in_scope(scope, target)
    if not ok:
        die(why, 5)
    net = ipaddress.ip_network(target, strict=False)
    limit = MAX_PREFIX_V4 if net.version == 4 else MAX_PREFIX_V6
    if net.prefixlen < limit:
        die(f"{net} is larger than a /{limit} - authorise and sweep the smaller "
            f"ranges you actually mean", 5)
    if net.num_addresses == 1:
        hosts = [net.network_address]
    elif net.version == 4 and net.prefixlen <= 30:
        hosts = list(net.hosts())          # drops network and broadcast
    else:
        hosts = list(net)
    skip = excluded_addrs(scope)
    hosts = [h for h in hosts if h not in skip]
    if len(hosts) > max_hosts:
        die(f"{net} expands to {len(hosts)} addresses, over the --max-hosts limit of "
            f"{max_hosts}. Raise it deliberately or sweep a smaller range", 5)
    return [str(h) for h in hosts]


# -------------------------------------------------------------- SOCKS tunnel

class SocksTunnel:
    """`ssh -D` on a host inside the site, so the sweep runs from where it can see.

    A management VLAN that is not routed to the engineer's laptop is the normal case.
    `-L` cannot help here - a sweep needs thousands of destinations, not one - so this
    opens a SOCKS5 listener instead and every probe is a CONNECT through it.

    The jump host must allow dynamic forwarding. RouterOS does not, so a MikroTik
    cannot be the tunnel; use a Linux host in the site, or run the on-device sweep
    (`/tool ip-scan`) through netwalk_exec.py instead.
    """

    def __init__(self, via: str):
        self.via = via
        self.proc = None
        self.port = None

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def open(self) -> tuple[str, int]:
        if not shutil.which("ssh"):
            die("--via needs an OpenSSH client on PATH", 4)
        self.port = self._free_port()
        argv = ["ssh", "-N", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"UserKnownHostsFile={C.known_hosts()}",
                "-D", f"127.0.0.1:{self.port}", self.via]
        self.proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        atexit.register(self.close)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                err = self.proc.stderr.read().decode("utf-8", "replace").strip()
                die(f"could not open the SOCKS tunnel through {self.via}: {err[:300]}\n"
                    f"a jump host with dynamic forwarding disabled looks exactly like this - "
                    f"RouterOS never allows it", 4)
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    return "127.0.0.1", self.port
            except OSError:
                time.sleep(0.3)
        die(f"the SOCKS tunnel through {self.via} never came up", 4)
        return "", 0

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# SOCKS5 reply codes, RFC 1928 s6. Only the ones that tell us something.
SOCKS_REPLY = {
    0x00: "open",
    0x03: "filtered",     # network unreachable
    0x04: "filtered",     # host unreachable
    0x05: "refused",      # connection refused - the host IS there
}


def socks5_probe(proxy: tuple[str, int], host: str, port: int, timeout: float) -> str:
    """One CONNECT through a SOCKS5 proxy. Returns open|refused|filtered|error."""
    try:
        s = socket.create_connection(proxy, timeout=timeout)
    except OSError:
        return "error"
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        greeting = s.recv(2)
        if len(greeting) < 2 or greeting[0] != 0x05 or greeting[1] != 0x00:
            return "error"
        try:
            packed = ipaddress.ip_address(host).packed
            atyp = b"\x01" if len(packed) == 4 else b"\x04"
            addr = packed
        except ValueError:
            atyp, addr = b"\x03", bytes([len(host)]) + host.encode("idna")
        s.sendall(b"\x05\x01\x00" + atyp + addr + struct.pack("!H", port))
        reply = s.recv(4)
        if len(reply) < 2 or reply[0] != 0x05:
            return "error"
        return SOCKS_REPLY.get(reply[1], "filtered")
    except (OSError, socket.timeout):
        return "error"
    finally:
        s.close()


# -------------------------------------------------------------------- probing

def tcp_probe(host: str, port: int, timeout: float,
              proxy: tuple[str, int] | None = None) -> str:
    """open | refused | filtered | error. Connect, then close - nothing is sent."""
    if proxy:
        return socks5_probe(proxy, host, port, timeout)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "refused"
    except (socket.timeout, TimeoutError):
        return "filtered"
    except OSError as e:
        # "no route to host" / "network unreachable" are answers too, not failures.
        if e.errno in (65, 101, 113, 51):
            return "filtered"
        return "error"


def grab_banner(host: str, port: int, timeout: float,
                proxy: tuple[str, int] | None = None) -> str:
    """At most one short read. Off by default: a banner is data off someone's device."""
    if proxy:
        return ""      # keep the SOCKS path to CONNECT and nothing else
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(128)
            except (socket.timeout, TimeoutError):
                if port in (80, 8080, 8000, 8443, 443):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = s.recv(128)
                else:
                    return ""
    except OSError:
        return ""
    text = data.decode("utf-8", "replace").strip()
    return " ".join(text.split())[:120]


def _guard_probe_count(hosts: int, ports: int) -> None:
    total = hosts * ports
    if total > MAX_PROBES:
        die(f"{hosts} addresses x {ports} ports = {total} probes, over the {MAX_PROBES} "
            f"cap. Narrow the range or the port list", 5)


def sweep_ports(hosts: list[str], ports: list[int], timeout: float, concurrency: int,
                proxy=None, banner=False) -> dict[str, list[dict]]:
    """{ip: [{port, service, state, risk, banner?}]} for every port that answered."""
    _guard_probe_count(len(hosts), len(ports))
    jobs = [(h, p) for h in hosts for p in ports]
    found: dict[str, list[dict]] = {}

    def one(job):
        h, p = job
        return h, p, tcp_probe(h, p, timeout, proxy)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for h, p, state in pool.map(one, jobs):
            if state in ("open", "refused"):
                entry = {"port": p, "service": service_of(p), "state": state}
                if risk_of(p):
                    entry["risk"] = risk_of(p)
                found.setdefault(h, []).append(entry)

    if banner:
        for h, entries in found.items():
            for e in entries:
                if e["state"] == "open":
                    b = grab_banner(h, e["port"], timeout, proxy)
                    if b:
                        e["banner"] = b
    for entries in found.values():
        entries.sort(key=lambda e: e["port"])
    return found


def icmp_alive(host: str, timeout: float) -> bool:
    """One bounded ping through the system binary. Never used through a tunnel."""
    ping = shutil.which("ping")
    if not ping:
        return False
    if C.IS_WINDOWS:
        argv = [ping, "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        wait = str(max(1, int(round(timeout))))
        argv = [ping, "-c", "1", "-W", wait, host]
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout + 3)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


# -------------------------------------------------------------------- results

def sweeps_dir(site: str) -> Path:
    d = C.site_dir(site) / "sweeps"
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_result(site: str, result: dict, out: str | None) -> Path:
    if out:
        p = Path(out).expanduser()
    else:
        stamp = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d-%H%M%S")
        tag = C.slugify(result["range"])
        p = sweeps_dir(site) / f"{result['kind']}-{tag}-{stamp}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return p


# ------------------------------------------------------------------- commands

def cmd_authorize(args) -> int:
    scope = load_scope(args.site)
    added = []
    for r in args.range:
        try:
            net = ipaddress.ip_network(r, strict=False)
        except ValueError as e:
            die(f"{r!r}: {e}", 2)
        if not is_private(net) and not args.public_range_authorized:
            die(f"{net} is public address space. Sweeping a range you do not own is not "
                f"a mistake you can undo. If the owner has authorised it in writing, "
                f"re-run with --public-range-authorized", 5)
        limit = MAX_PREFIX_V4 if net.version == 4 else MAX_PREFIX_V6
        if net.prefixlen < limit:
            die(f"{net} is larger than a /{limit} - authorise the ranges you actually mean", 5)
        if any(str(a["cidr"]) == str(net) for a in scope["authorized"]):
            print(f"already authorised: {net}")
            continue
        scope["authorized"].append({
            "cidr": str(net),
            "authorized_by": args.authorized_by,
            "at": now_iso(),
            "note": args.note or "",
        })
        added.append(str(net))
    for x in args.exclude or []:
        if x not in scope["excluded"]:
            scope["excluded"].append(x)
    p = save_scope(args.site, scope)
    print(f"scope written to {p}")
    for a in scope["authorized"]:
        print(f"  authorised  {a['cidr']:<20} by {a['authorized_by']}  ({a['at']})")
    for x in scope["excluded"]:
        print(f"  EXCLUDED    {x}")
    if added:
        print(f"\nadded this run: {', '.join(added)}")
    return 0


def cmd_scope(args) -> int:
    scope = load_scope(args.site)
    if not scope["authorized"]:
        print("nothing authorised for this site - no sweep can run until it is")
        return 1
    print(f"scope for {scope['site']}  ({scope_path(args.site)})")
    for a in scope["authorized"]:
        n = ipaddress.ip_network(a["cidr"])
        print(f"  {a['cidr']:<20} {n.num_addresses:>6} addresses   by {a['authorized_by']}"
              f"{('  - ' + a['note']) if a.get('note') else ''}")
    for x in scope["excluded"]:
        print(f"  EXCLUDED {x}")
    return 0


def cmd_hosts(args) -> int:
    scope = load_scope(args.site)
    targets = targets_of(args.range, scope, args.max_hosts)
    proxy = None
    tun = None
    if args.via:
        tun = SocksTunnel(args.via)
        proxy = tun.open()
        print(f"sweeping through a SOCKS tunnel on {args.via}", file=sys.stderr)

    ports = parse_ports(args.probe_ports) if args.probe_ports else LIVENESS_PORTS
    use_icmp = args.icmp and not proxy
    print(f"{len(targets)} addresses x {len(ports)} probe ports"
          f"{' + icmp' if use_icmp else ''}, timeout {args.timeout}s, "
          f"{args.concurrency} at a time", file=sys.stderr)

    started = now_iso()
    t0 = time.monotonic()
    found = sweep_ports(targets, ports, args.timeout, args.concurrency, proxy)
    if use_icmp:
        rest = [t for t in targets if t not in found]
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            for ip, alive in zip(rest, pool.map(lambda h: icmp_alive(h, args.timeout), rest)):
                if alive:
                    found.setdefault(ip, [])
    elapsed = round(time.monotonic() - t0, 1)

    hosts = []
    for ip in sorted(found, key=lambda a: ipaddress.ip_address(a)):
        entries = found[ip]
        opened = [e for e in entries if e["state"] == "open"]
        hosts.append({
            "ip": ip,
            "evidence": (", ".join(f"tcp/{e['port']} {e['state']}" for e in entries[:4])
                         or "icmp echo reply"),
            "open_ports": [e["port"] for e in opened],
            "services": sorted({e["service"] for e in opened}),
        })

    result = {
        "kind": "host-sweep",
        "site": C.slugify(args.site),
        "range": args.range,
        "method": "tcp-connect" + (" + icmp" if use_icmp else "") + (" via socks" if proxy else ""),
        "via": args.via or None,
        "probe_ports": ports,
        "started_at": started,
        "finished_at": now_iso(),
        "elapsed_s": elapsed,
        "addresses_probed": len(targets),
        "hosts_found": len(hosts),
        "authorized_by": who_authorized(scope, args.range),
        "not_visible": ["UDP services", "hosts that drop rather than reject",
                        "ports outside the probe list"],
        "hosts": hosts,
    }
    p = write_result(args.site, result, args.out)
    if tun:
        tun.close()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{len(hosts)} of {len(targets)} addresses answered in {elapsed}s")
        for h in hosts:
            svc = ", ".join(h["services"]) or "-"
            print(f"  {h['ip']:<16} {svc:<40} {h['evidence']}")
        print(f"\nwritten to {p}")
        print("UDP-only services are invisible to this - say so in coverage.not_covered")
        if hosts:
            print("\nevery one of these belongs on the credential form, including the ones "
                  "you cannot identify:")
            print("  " + " ".join(f"--host '{h['ip']},{h['ip']},unknown,found by subnet sweep'"
                                  for h in hosts[:8])
                  + (" ..." if len(hosts) > 8 else ""))
    return 0


def cmd_ports(args) -> int:
    scope = load_scope(args.site)
    targets: list[str] = []
    for t in args.target:
        targets.extend(targets_of(t, scope, args.max_hosts))
    if args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = PROFILES[args.profile]

    proxy = None
    tun = None
    if args.via:
        tun = SocksTunnel(args.via)
        proxy = tun.open()

    print(f"{len(targets)} targets x {len(ports)} ports = {len(targets) * len(ports)} "
          f"probes, timeout {args.timeout}s", file=sys.stderr)
    started = now_iso()
    t0 = time.monotonic()
    found = sweep_ports(targets, ports, args.timeout, args.concurrency, proxy, args.banner)
    elapsed = round(time.monotonic() - t0, 1)
    if tun:
        tun.close()

    hosts = []
    for ip in sorted(found, key=lambda a: ipaddress.ip_address(a)):
        opened = [e for e in found[ip] if e["state"] == "open"]
        if not opened:
            continue
        hosts.append({"ip": ip, "ports": opened})

    result = {
        "kind": "port-scan",
        "site": C.slugify(args.site),
        "range": ",".join(args.target),
        "method": "tcp-connect" + (" via socks" if proxy else ""),
        "via": args.via or None,
        "profile": None if args.ports else args.profile,
        "ports_probed": ports,
        "banner_grab": bool(args.banner),
        "started_at": started,
        "finished_at": now_iso(),
        "elapsed_s": elapsed,
        "addresses_probed": len(targets),
        "hosts_found": len(hosts),
        "not_visible": ["UDP services", "hosts that drop rather than reject",
                        "ports outside the probed list"],
        "hosts": hosts,
    }
    p = write_result(args.site, result, args.out)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{len(hosts)} hosts with an open port, {elapsed}s")
        for h in hosts:
            print(f"\n  {h['ip']}")
            for e in h["ports"]:
                flag = "  <-- " + e["risk"] if e.get("risk") else ""
                ban = f"   {e['banner']}" if e.get("banner") else ""
                print(f"    {e['port']:>6}/tcp  {e['service']:<18}{ban}{flag}")
        print(f"\nwritten to {p}")
        risky = [(h["ip"], e) for h in hosts for e in h["ports"] if e.get("risk")]
        if risky:
            print(f"\n{len(risky)} of these are worth a finding on their own - "
                  f"write them into findings[] with the port as evidence")
    return 0


def cmd_record(args) -> int:
    """Fold sweep results into the scan record, without touching what is already there."""
    rec_path = Path(args.record).expanduser()
    try:
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        die(f"cannot read the scan record {rec_path}: {e}", 3)

    files = [Path(f).expanduser() for f in args.sweep] or sorted(sweeps_dir(args.site).glob("*.json"))
    if not files:
        die("no sweep results to record - run `hosts` or `ports` first", 2)

    known = {d.get("mgmt_ip") for d in rec.get("devices", [])} | \
            {d.get("host_id") for d in rec.get("devices", [])}
    sweeps = rec.setdefault("sweeps", [])
    unknown: dict[str, list] = {}

    for f in files:
        try:
            res = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"skipping {f}: {e}", file=sys.stderr)
            continue
        entry = {k: res[k] for k in ("kind", "range", "method", "started_at",
                                     "addresses_probed", "hosts_found", "not_visible")
                 if k in res}
        entry["via"] = res.get("via")
        entry["authorized_by"] = res.get("authorized_by", "")
        entry["hosts"] = [
            {"ip": h["ip"],
             "open_ports": h.get("open_ports") or [e["port"] for e in h.get("ports", [])],
             "services": h.get("services") or sorted({e["service"] for e in h.get("ports", [])}),
             "in_record": h["ip"] in known}
            for h in res.get("hosts", [])
        ]
        if not any(s.get("range") == entry.get("range") and
                   s.get("started_at") == entry.get("started_at") for s in sweeps):
            sweeps.append(entry)
        for h in entry["hosts"]:
            if not h["in_record"]:
                # union across sweeps: a host sweep may see nothing a port scan later finds
                merged = set(unknown.get(h["ip"], [])) | set(h["services"])
                unknown[h["ip"]] = sorted(merged)

    cov = rec.setdefault("coverage", {})
    nc = cov.setdefault("not_covered", [])
    note = ("the subnet sweep sees TCP only - UDP services (SNMP, DNS, IPMI, syslog, IKE) "
            "and hosts that silently drop were not detected")
    if note not in nc:
        nc.append(note)

    rec_path.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    print(f"{len(sweeps)} sweep(s) recorded in {rec_path}")
    if unknown:
        print(f"\n{len(unknown)} address(es) answered but are NOT in devices[] yet. "
              f"Put every one on the credential form - an address you cannot identify "
              f"is the question the form exists to ask:")
        for ip, svc in sorted(unknown.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
            print(f"  {ip:<16} {', '.join(svc) or 'no open port, answered a probe'}")
    else:
        print("every address that answered is already in devices[]")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="netwalk_sweep.py",
        description="Authorised subnet sweep and well-known TCP port scan.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="A range must be authorised before it can be swept. There is no --force.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("authorize", help="record which ranges the owner said yes to")
    a.add_argument("--site", required=True)
    a.add_argument("--range", action="append", required=True,
                   help="CIDR, repeatable (10.2.30.0/24)")
    a.add_argument("--authorized-by", required=True,
                   help="who authorised it and when - this goes in the report")
    a.add_argument("--note", default="")
    a.add_argument("--exclude", action="append",
                   help="address or CIDR never to probe, repeatable")
    a.add_argument("--public-range-authorized", action="store_true",
                   help="required before a non-RFC1918 range can be authorised")
    a.set_defaults(func=cmd_authorize)

    s = sub.add_parser("scope", help="show what is authorised for this site")
    s.add_argument("--site", required=True)
    s.set_defaults(func=cmd_scope)

    h = sub.add_parser("hosts", help="which addresses in a range answer at all")
    h.add_argument("--site", required=True)
    h.add_argument("--range", required=True)
    h.add_argument("--probe-ports", help=f"default {','.join(map(str, LIVENESS_PORTS))}")
    h.add_argument("--icmp", action="store_true", default=True)
    h.add_argument("--no-icmp", dest="icmp", action="store_false")
    h.add_argument("--via", metavar="user@host", help="SOCKS tunnel through this host")
    h.add_argument("--timeout", type=float, default=1.0)
    h.add_argument("--concurrency", type=int, default=64)
    h.add_argument("--max-hosts", type=int, default=MAX_HOSTS_DEFAULT)
    h.add_argument("--out", help="write the result here instead of the site's sweeps/ dir")
    h.add_argument("--json", action="store_true")
    h.set_defaults(func=cmd_hosts)

    p = sub.add_parser("ports", help="well-known TCP ports on one or more targets")
    p.add_argument("--site", required=True)
    p.add_argument("--target", action="append", required=True,
                   help="address or CIDR, repeatable")
    p.add_argument("--profile", choices=sorted(PROFILES), default="standard")
    p.add_argument("--ports", help="explicit list, e.g. 22,80,8000-8010 (overrides --profile)")
    p.add_argument("--banner", action="store_true",
                   help="read up to 128 bytes from each open port - off by default")
    p.add_argument("--via", metavar="user@host", help="SOCKS tunnel through this host")
    p.add_argument("--timeout", type=float, default=1.5)
    p.add_argument("--concurrency", type=int, default=64)
    p.add_argument("--max-hosts", type=int, default=256)
    p.add_argument("--out")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_ports)

    r = sub.add_parser("record", help="fold sweep results into the scan record")
    r.add_argument("--site", required=True)
    r.add_argument("--record", required=True, help="path to scan-<date>.json")
    r.add_argument("--sweep", action="append", default=[],
                   help="specific result file, repeatable; default is all of them")
    r.set_defaults(func=cmd_record)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted - partial results were not written", file=sys.stderr)
        raise SystemExit(130)
