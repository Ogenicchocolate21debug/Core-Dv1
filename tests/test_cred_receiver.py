#!/usr/bin/env python3
"""Regression suite for the netwalk-login credential receiver.

Why this file exists: the first version of the receiver rejected every request
carrying an `Origin` header, on the theory that a same-origin form would not send
one. Browsers attach `Origin` to *every* POST, same-origin included, so the form
blocked itself - and the original tests missed it because they used curl, which
sends no Origin unless told to. The lesson is baked in below: the happy path is
tested through exactly the headers a browser sends, not the ones a CLI sends.

  python3 tests/test_cred_receiver.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CRED = ROOT / "scripts" / "netwalk_cred.py"
SITE = "netwalk-selftest-receiver"

BROWSER_BODY = {"hosts": {"r1": {"ip": "10.0.0.1", "vendor": "mikrotik", "method": "password",
                                 "port": "22", "username": "u", "password": "correct-horse"}}}


def start() -> tuple[subprocess.Popen, str, int]:
    env = dict(os.environ)
    env["NETWALK_HOME"] = str(HERE / ".tmp-netwalk-home")
    p = subprocess.Popen(
        [sys.executable, str(CRED), "request", "--site", SITE,
         "--host", "r1,10.0.0.1,mikrotik", "--timeout", "20", "--no-open"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, text=True)
    for _ in range(100):
        line = p.stdout.readline()
        if line.startswith("NETWALK_LOGIN_URL"):
            url = line.split()[1]
            return p, url, int(url.rsplit(":", 1)[1].split("/")[0])
        if p.poll() is not None:
            raise RuntimeError("receiver exited before printing its URL")
        time.sleep(0.05)
    raise RuntimeError("receiver never printed its URL")


def post(url: str, body: dict, headers: dict) -> tuple[int, dict | str]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **headers},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def get(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


CASES = []


def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


@case("browser same-origin POST is accepted (the bug that shipped once)")
def _(url, port):
    code, body = post(f"{url}/save", BROWSER_BODY, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 200 and body.get("ok"), f"{code} {body}"


@case("localhost alias origin is accepted")
def _(url, port):
    code, body = post(f"{url}/save", BROWSER_BODY, {"Origin": f"http://localhost:{port}"})
    assert code == 200 and body.get("ok"), f"{code} {body}"


@case("no Origin at all (curl, scripts) is accepted")
def _(url, port):
    code, body = post(f"{url}/save", BROWSER_BODY, {})
    assert code == 200 and body.get("ok"), f"{code} {body}"


@case("a hostile site's origin is rejected")
def _(url, port):
    code, body = post(f"{url}/save", BROWSER_BODY, {"Origin": "https://evil.example"})
    assert code == 403, f"{code} {body}"


@case("another app on loopback (different port) is rejected")
def _(url, port):
    code, body = post(f"{url}/save", BROWSER_BODY, {"Origin": "http://127.0.0.1:1"})
    assert code == 403, f"{code} {body}"


@case("wrong URL token is 404, not a save")
def _(url, port):
    base = url.rsplit("/", 1)[0]
    code, _b = post(f"{base}/not-the-token/save", BROWSER_BODY, {})
    assert code == 404, code


@case("GET with the wrong token does not leak the form")
def _(url, port):
    base = url.rsplit("/", 1)[0]
    code, body = get(f"{base}/guess")
    assert code == 404 and "netwalk-login" not in body, code


@case("GET with the right token serves the form")
def _(url, port):
    code, body = get(url)
    assert code == 200 and "netwalk-login" in body and "Save credentials" in body, code


@case("form-encoded POST is refused (this is what forces a CORS preflight)")
def _(url, port):
    req = urllib.request.Request(f"{url}/save", data=b"hosts=x",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"},
                                 method="POST")
    try:
        urllib.request.urlopen(req, timeout=10)
        raise AssertionError("form-encoded POST was accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 415, e.code


@case("pasted private key material is refused with an explanation")
def _(url, port):
    body = {"hosts": {"r1": {"ip": "10.0.0.1", "method": "key",
                             "key_path": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc"}}}
    code, resp = post(f"{url}/save", body, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 400 and "key material" in str(resp), f"{code} {resp}"


@case("an all-skipped submission saves nothing")
def _(url, port):
    code, resp = post(f"{url}/save", {"hosts": {"r1": {"method": "skip"}}},
                      {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 400, f"{code} {resp}"


@case("the saved file is owner-only and the password is really in it")
def _(url, port):
    code, body = post(f"{url}/save", BROWSER_BODY, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 200, code
    path = Path(body["path"])
    assert path.exists(), path
    if os.name != "nt":
        assert oct(path.stat().st_mode)[-3:] == "600", oct(path.stat().st_mode)
    data = json.loads(path.read_text())
    assert data["hosts"]["r1"]["password"] == "correct-horse"


@case("`list` prints host metadata and never the secret")
def _(url, port):
    post(f"{url}/save", BROWSER_BODY, {"Origin": f"http://127.0.0.1:{port}"})
    env = dict(os.environ)
    env["NETWALK_HOME"] = str(HERE / ".tmp-netwalk-home")
    out = subprocess.run([sys.executable, str(CRED), "list", "--site", SITE],
                         capture_output=True, text=True, env=env)
    assert "r1" in out.stdout, out.stdout
    assert "correct-horse" not in out.stdout + out.stderr, "list leaked the password"


def main() -> int:
    home = HERE / ".tmp-netwalk-home"
    fails = []
    for name, fn in CASES:
        proc = None
        try:
            proc, url, port = start()
            fn(url, port)
            print(f"  ok    {name}")
        except AssertionError as e:
            fails.append(f"{name}\n          {e}")
            print(f"  FAIL  {name}\n          {e}")
        except Exception as e:  # noqa: BLE001
            fails.append(f"{name}\n          {type(e).__name__}: {e}")
            print(f"  ERROR {name}\n          {type(e).__name__}: {e}")
        finally:
            if proc and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)

    if home.exists():
        import shutil
        shutil.rmtree(home, ignore_errors=True)

    print(f"\n{len(CASES) - len(fails)}/{len(CASES)} receiver checks pass")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
