#!/usr/bin/env python3
"""Regression suite for the netwalk sweep gate.

This file is the guarantee behind "netwalk never sweeps a range nobody authorised".
The scope check is the sweep's equivalent of netwalk_policy.py: it is the only thing
standing between a survey and an unauthorised port scan of someone else's network,
so it is tested the same way - every refusal has a case, and so does every allowance.

Run after ANY edit to netwalk_sweep.py:  python3 tests/test_sweep.py
Nothing here opens a socket to anything but 127.0.0.1.
"""
import ipaddress
import json
import os
import socket
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

# Point the toolkit at a throwaway home BEFORE importing, so no test can touch a
# real engagement directory.
_TMP = tempfile.mkdtemp(prefix="netwalk-test-")
os.environ["NETWALK_HOME"] = _TMP

import netwalk_sweep as S  # noqa: E402

FAILED: list[str] = []
PASSED = 0


def ok(label: str) -> None:
    global PASSED
    PASSED += 1
    print(f"  ok     {label}")


def bad(label: str, detail: str = "") -> None:
    FAILED.append(f"{label}{(' - ' + detail) if detail else ''}")
    print(f"  FAILED {label}{(' - ' + detail) if detail else ''}")


def check(cond: bool, label: str, detail: str = "") -> None:
    ok(label) if cond else bad(label, detail)


def scope(*cidrs, excluded=()) -> dict:
    return {
        "site": "t",
        "authorized": [{"cidr": c, "authorized_by": "test", "at": "now"} for c in cidrs],
        "excluded": list(excluded),
    }


# --------------------------------------------------------------- scope gate

def test_scope() -> None:
    print("\nscope gate - what may be swept at all")

    empty = scope()
    allowed, why = S.check_in_scope(empty, "10.2.30.0/24")
    check(not allowed, "an empty scope refuses everything")
    check("authorize" in why, "and the refusal names the command that fixes it", why)

    s = scope("10.2.30.0/24")
    check(S.check_in_scope(s, "10.2.30.0/24")[0], "the authorised range itself is allowed")
    check(S.check_in_scope(s, "10.2.30.128/25")[0], "a subnet of it is allowed")
    check(S.check_in_scope(s, "10.2.30.5")[0], "a single address inside it is allowed")
    check(not S.check_in_scope(s, "10.2.31.0/24")[0], "the neighbouring /24 is refused")
    check(not S.check_in_scope(s, "10.2.30.0/23")[0],
          "a SUPERNET of the authorised range is refused - authorising a /24 does not "
          "authorise the /23 that contains it")
    check(not S.check_in_scope(s, "0.0.0.0/0")[0], "the whole internet is refused")
    check(not S.check_in_scope(s, "8.8.8.8")[0], "an unrelated public address is refused")
    check(not S.check_in_scope(s, "not-an-address")[0], "garbage is refused, not crashed on")
    check(not S.check_in_scope(s, "2001:db8::/64")[0],
          "a v6 range is refused when only v4 was authorised")

    v6 = scope("2001:db8:0:1::/120")
    check(S.check_in_scope(v6, "2001:db8:0:1::/120")[0], "a v6 range can be authorised")
    check(not S.check_in_scope(v6, "10.2.30.0/24")[0],
          "and authorising v6 does not authorise v4")

    src = open(os.path.join(ROOT, "scripts", "netwalk_sweep.py"), encoding="utf-8").read()
    check('add_argument("--force' not in src and "args.force" not in src,
          "there is no override flag - the scope check cannot be argued past")


def test_targets() -> None:
    print("\nexpansion - how a range becomes addresses")

    s = scope("10.2.30.0/24")
    t = S.targets_of("10.2.30.0/24", s, 4096)
    check(len(t) == 254, "a /24 expands to 254 hosts, not 256", str(len(t)))
    check("10.2.30.0" not in t and "10.2.30.255" not in t,
          "network and broadcast addresses are not probed")

    t32 = S.targets_of("10.2.30.7", s, 10)
    check(t32 == ["10.2.30.7"], "a single address expands to itself", str(t32))

    ex = scope("10.2.30.0/24", excluded=["10.2.30.5", "10.2.30.64/28"])
    t = S.targets_of("10.2.30.0/24", ex, 4096)
    check("10.2.30.5" not in t, "an excluded address is dropped")
    check("10.2.30.70" not in t, "an excluded CIDR is dropped whole")
    check(len(t) == 254 - 1 - 16, "and only those are dropped", str(len(t)))

    for label, fn in (
        ("a range outside the scope exits rather than probing",
         lambda: S.targets_of("10.9.9.0/24", s, 4096)),
        ("more addresses than --max-hosts exits rather than probing",
         lambda: S.targets_of("10.2.30.0/24", s, 10)),
    ):
        try:
            fn()
            bad(label, "it returned instead of exiting")
        except SystemExit as e:
            check(e.code != 0, label, f"exit code {e.code}")

    big = scope("10.0.0.0/8")
    try:
        S.targets_of("10.0.0.0/8", big, MAX := 999999)
        bad("a /8 is refused even when authorised")
    except SystemExit:
        ok("a /8 is refused even when authorised - the prefix cap is independent of scope")


def test_private_guard() -> None:
    print("\npublic address space - the extra promise")

    net = ipaddress.ip_network
    check(S.is_private(net("10.2.30.0/24")), "10/8 is private")
    check(S.is_private(net("192.168.1.0/24")), "192.168/16 is private")
    check(S.is_private(net("172.16.5.0/24")), "172.16/12 is private")
    check(S.is_private(net("100.64.0.0/24")), "CGNAT space counts as private")
    check(S.is_private(net("fc00::/64")), "v6 ULA is private")
    check(not S.is_private(net("8.8.8.0/24")), "public v4 is not private")
    check(not S.is_private(net("172.32.0.0/24")),
          "172.32/16 is NOT in the 172.16/12 private block")
    check(not S.is_private(net("2001:db8::/64")), "v6 documentation space is not private")


# ------------------------------------------------------------------- ports

def test_ports() -> None:
    print("\nport lists")

    check(S.parse_ports("22") == [22], "one port")
    check(S.parse_ports("22,80,443") == [22, 80, 443], "a list")
    check(S.parse_ports("80,22,80") == [22, 80], "deduped and sorted")
    check(S.parse_ports("8000-8003") == [8000, 8001, 8002, 8003], "a range")
    check(S.parse_ports(" 22 , 80 ") == [22, 80], "whitespace is tolerated")

    for spec, why in (("0", "port 0"), ("65536", "port 65536"), ("80-22", "a backwards range"),
                      ("", "an empty spec"), ("http", "a service name"), ("1-9999", "a huge range")):
        try:
            S.parse_ports(spec)
            bad(f"{why} is rejected", "it parsed")
        except ValueError:
            ok(f"{why} is rejected")

    check(set(PROFILES := S.PROFILES["quick"]) <= set(S.WELL_KNOWN),
          "every port in the quick profile has a service name")
    check(S.PROFILES["standard"] == sorted(S.WELL_KNOWN),
          "the standard profile is exactly the well-known table")
    check(all(1 <= p <= 65535 for p in S.WELL_KNOWN), "every well-known port is a real port")
    for p in (23, 445, 3389, 5900, 6379, 8291, 27017):
        check(bool(S.risk_of(p)), f"tcp/{p} ({S.service_of(p)}) carries a stated risk")
    check(S.risk_of(443) == "", "https carries no risk note by itself")
    check(S.service_of(9999) == "unknown", "an unlisted port is named 'unknown', not guessed")


def test_probe_cap() -> None:
    print("\nsize cap - refused before the first packet, not halfway through")
    try:
        S._guard_probe_count(4096, 100)
        bad("409600 probes is refused", "it went ahead")
    except SystemExit:
        ok("409600 probes is refused before anything runs")
    try:
        S._guard_probe_count(254, 70)
        ok("a /24 against the standard profile is allowed")
    except SystemExit:
        bad("a /24 against the standard profile is allowed", "it was refused")


# ------------------------------------------------------------------ probing

def test_tcp_probe() -> None:
    print("\nTCP probe - against a real listener on 127.0.0.1")

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def accept_loop():
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                c.close()
            except (socket.timeout, OSError):
                continue

    th = threading.Thread(target=accept_loop, daemon=True)
    th.start()
    try:
        check(S.tcp_probe("127.0.0.1", port, 2.0) == "open", "an open port reads as open")
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        shut = closed.getsockname()[1]
        closed.close()
        state = S.tcp_probe("127.0.0.1", shut, 2.0)
        check(state in ("refused", "filtered"),
              "a closed port reads as refused or filtered, never open", state)
        check(S.tcp_probe("127.0.0.1", shut, 2.0) != "open",
              "and a closed port is never reported as open")
    finally:
        stop.set()
        th.join(timeout=2)
        srv.close()


def test_socks_framing() -> None:
    print("\nSOCKS5 framing - the tunnel path speaks the protocol correctly")

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)
    proxy_port = srv.getsockname()[1]
    seen: dict = {}

    def fake_proxy(reply_code: int):
        c, _ = srv.accept()
        seen["greeting"] = c.recv(3)
        c.sendall(b"\x05\x00")
        seen["request"] = c.recv(10)
        c.sendall(bytes([0x05, reply_code, 0x00, 0x01]) + b"\x00" * 6)
        c.close()

    try:
        th = threading.Thread(target=fake_proxy, args=(0x00,), daemon=True)
        th.start()
        state = S.socks5_probe(("127.0.0.1", proxy_port), "10.2.30.5", 443, 3.0)
        th.join(timeout=3)
        check(state == "open", "reply 0x00 means open", state)
        check(seen["greeting"] == b"\x05\x01\x00", "the greeting offers only 'no auth'")
        req = seen["request"]
        check(req[:4] == b"\x05\x01\x00\x01", "the request is CONNECT with an IPv4 address")
        check(req[4:8] == bytes([10, 2, 30, 5]), "the address is packed correctly")
        check(req[8:10] == (443).to_bytes(2, "big"), "the port is big-endian")

        for code, want in ((0x05, "refused"), (0x04, "filtered"), (0x03, "filtered")):
            th = threading.Thread(target=fake_proxy, args=(code,), daemon=True)
            th.start()
            got = S.socks5_probe(("127.0.0.1", proxy_port), "10.2.30.5", 443, 3.0)
            th.join(timeout=3)
            check(got == want, f"reply {code:#04x} means {want}", got)
    finally:
        srv.close()

    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    dead_port = dead.getsockname()[1]
    dead.close()
    check(S.socks5_probe(("127.0.0.1", dead_port), "10.2.30.5", 443, 1.0) == "error",
          "a proxy that is not there is an error, not a host that is not there")


# ------------------------------------------------------------------ record

def test_record_merge() -> None:
    print("\nrecording into the scan record")

    site = "merge-test"
    d = S.C.site_dir(site)
    rec_path = d / "scan-test.json"
    rec_path.write_text(json.dumps({
        "site": {"id": site}, "scanned_at": "now",
        "devices": [{"host_id": "gw01", "mgmt_ip": "10.2.30.1", "reachable": True}],
    }), encoding="utf-8")

    sw = S.sweeps_dir(site) / "host-sweep-test.json"
    sw.write_text(json.dumps({
        "kind": "host-sweep", "site": site, "range": "10.2.30.0/24",
        "method": "tcp-connect", "started_at": "now", "addresses_probed": 254,
        "hosts_found": 2, "not_visible": ["UDP services"], "authorized_by": "test",
        "hosts": [
            {"ip": "10.2.30.1", "open_ports": [22, 443], "services": ["ssh", "https"]},
            {"ip": "10.2.30.99", "open_ports": [23], "services": ["telnet"]},
        ],
    }), encoding="utf-8")

    class A:
        pass
    a = A()
    a.site, a.record, a.sweep = site, str(rec_path), []
    S.cmd_record(a)
    out = json.loads(rec_path.read_text(encoding="utf-8"))

    check(len(out["sweeps"]) == 1, "the sweep lands in sweeps[]")
    check(out["devices"] == [{"host_id": "gw01", "mgmt_ip": "10.2.30.1", "reachable": True}],
          "devices[] is left exactly as it was - the sweep never invents a device")
    hosts = {h["ip"]: h for h in out["sweeps"][0]["hosts"]}
    check(hosts["10.2.30.1"]["in_record"] is True, "a host already in devices[] is marked so")
    check(hosts["10.2.30.99"]["in_record"] is False, "an unknown host is marked as not known")
    check(any("UDP" in n for n in out["coverage"]["not_covered"]),
          "the UDP blind spot is written into coverage automatically")

    S.cmd_record(a)
    out2 = json.loads(rec_path.read_text(encoding="utf-8"))
    check(len(out2["sweeps"]) == 1, "recording the same sweep twice does not duplicate it")
    check(len(out2["coverage"]["not_covered"]) == 1,
          "and does not duplicate the coverage note either")


def test_schema_accepts_sweeps() -> None:
    print("\nschema")
    path = os.path.join(ROOT, "schema", "netwalk-record.schema.json")
    schema = json.load(open(path, encoding="utf-8"))
    check("sweeps" in schema["properties"],
          "the record schema has a sweeps section - additionalProperties is false, so "
          "without it every swept record fails validation")
    if "sweeps" in schema["properties"]:
        item = schema["properties"]["sweeps"]["items"]
        for field in ("range", "method", "authorized_by", "not_visible", "hosts"):
            check(field in item["properties"], f"a recorded sweep carries {field}")


def main() -> int:
    print("netwalk sweep gate - regression suite")
    test_scope()
    test_targets()
    test_private_guard()
    test_ports()
    test_probe_cap()
    test_tcp_probe()
    test_socks_framing()
    test_record_merge()
    test_schema_accepts_sweeps()

    print(f"\n{PASSED} passed, {len(FAILED)} failed")
    for f in FAILED:
        print(f"  FAILED {f}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
