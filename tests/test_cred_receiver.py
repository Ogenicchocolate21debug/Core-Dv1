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

BROWSER_BODY = {"hosts": {"r1": {"ip": "192.0.2.1", "vendor": "mikrotik", "method": "password",
                                 "port": "22", "username": "u", "password": "correct-horse"}}}


def start(extra: list[str] | None = None) -> tuple[subprocess.Popen, str, int]:
    env = dict(os.environ)
    env["NETWALK_HOME"] = str(HERE / ".tmp-netwalk-home")
    p = subprocess.Popen(
        [sys.executable, str(CRED), "request", "--site", SITE,
         "--host", "r1,192.0.2.1,mikrotik", "--timeout", "20", "--no-open",
         *(extra or [])],
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
    body = {"hosts": {"r1": {"ip": "192.0.2.1", "method": "key",
                             "key_path": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc"}}}
    code, resp = post(f"{url}/save", body, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 400 and "key material" in str(resp), f"{code} {resp}"


@case("an empty submission is refused, but a Skip verdict is kept")
def _(url, port):
    # Skip used to be discarded. It is now a recorded answer - "ask me again later" is
    # information the crawl needs. What must still be refused is a submission that
    # carries no verdict at all.
    code, resp = post(f"{url}/save", {"hosts": {}}, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 400, f"empty submission was accepted: {code} {resp}"
    code, resp = post(f"{url}/save", {"hosts": {"r1": {"method": "skip"}}},
                      {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 200, f"{code} {resp}"
    e = json.loads(Path(resp["path"]).read_text())["hosts"]["r1"]
    assert e["method"] == "skip", e


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


@case("an agent question appears on the form and comes back answered")
def _(url, port):
    code, body = get(url)
    assert code == 200 and "How do you normally reach this controller?" in body, "question not rendered"
    assert 'name="ask::reach_how"' in body, "question input missing"
    assert "When is the maintenance window?" in body, "form-wide question not rendered"
    payload = dict(BROWSER_BODY)
    payload["hosts"] = {"r1": {**BROWSER_BODY["hosts"]["r1"],
                               "answers": {"reach_how": "https://192.0.2.10:8443", "window": "Sundays"}}}
    code, resp = post(f"{url}/save", payload, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 200, f"{code} {resp}"
    data = json.loads(Path(resp["path"]).read_text())
    ans = data["hosts"]["r1"]["answers"]
    assert ans["reach_how"] == "https://192.0.2.10:8443" and ans["window"] == "Sundays", ans


@case("access detail fields are stored and readable, secrets stay unreadable")
def _(url, port):
    payload = {"hosts": {"r1": {**BROWSER_BODY["hosts"]["r1"],
                                "mgmt_url": "https://192.0.2.10:8443",
                                "jump_host": "admin@192.0.2.1", "tenant": "default"}}}
    code, body = post(f"{url}/save", payload, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 200, f"{code} {body}"
    env = dict(os.environ)
    env["NETWALK_HOME"] = str(HERE / ".tmp-netwalk-home")
    out = subprocess.run([sys.executable, str(CRED), "answers", "--site", SITE],
                         capture_output=True, text=True, env=env)
    both = out.stdout + out.stderr
    for want in ("https://192.0.2.10:8443", "admin@192.0.2.1", "default"):
        assert want in both, f"answers did not print {want}: {both}"
    assert "correct-horse" not in both, "answers leaked the password"


@case("Skip on a fresh host records the answer and no credential")
def _(url, port):
    # "Skip" means "I am not giving you a credential for this one" - the answer to
    # WHY is often the most useful thing on the form, so it must survive. On a host
    # that already had a credential, Skip must also not silently delete it; that is
    # what `forget` is for.
    payload = {"hosts": {"never-seen": {"method": "skip",
                                        "answers": {"why": "no access granted"}}}}
    code, body = post(f"{url}/save", payload, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 200, f"{code} {body}"
    e = json.loads(Path(body["path"]).read_text())["hosts"]["never-seen"]
    assert e["answers"]["why"] == "no access granted", e
    for secret in ("password", "key_path", "api_token", "enable_password"):
        assert not e.get(secret), f"skip stored a {secret}"


@case("Skip does not delete a credential the host already had")
def _(url, port):
    good = {"hosts": {"keepme": {"ip": "192.0.2.2", "vendor": "mikrotik", "method": "password",
                                 "username": "u", "password": "keep-this"}}}
    code, body = post(f"{url}/save", good, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 200, f"{code} {body}"
    proc2, url2, port2 = start()
    try:
        code, body = post(f"{url2}/save",
                          {"hosts": {"keepme": {"method": "skip", "answers": {"why": "later"}}}},
                          {"Origin": f"http://127.0.0.1:{port2}"})
        assert code == 200, f"{code} {body}"
        e = json.loads(Path(body["path"]).read_text())["hosts"]["keepme"]
        assert e.get("password") == "keep-this", "Skip wiped an existing credential"
        assert e["answers"]["why"] == "later", e
    finally:
        if proc2.poll() is None:
            proc2.kill(); proc2.wait(timeout=5)


@case("\"I don't know what this is\" is stored as a real answer")
def _(url, port):
    payload = {"hosts": {"mystery-box": {"method": "unknown", "ip": "192.0.2.44",
                                         "vendor": "unknown",
                                         "note": "was here when we took the site over"}}}
    code, body = post(f"{url}/save", payload, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 200, f"{code} {body}"
    e = json.loads(Path(body["path"]).read_text())["hosts"]["mystery-box"]
    assert e["method"] == "unknown", e
    assert "took the site over" in (e.get("note") or ""), e
    for secret in ("password", "key_path", "api_token"):
        assert not e.get(secret), f"unknown stored a {secret}"


@case("\"I know what it is, no login\" documents the device without a credential")
def _(url, port):
    payload = {"hosts": {"the-printer": {
        "method": "known-no-cred", "ip": "192.0.2.60", "vendor": "unknown",
        "described": "Ricoh MP C4504 in the staff room", "role_hint": "printer",
        "purpose": "staff printing and scan-to-email", "owner": "the copier contractor"}}}
    code, body = post(f"{url}/save", payload, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 200, f"{code} {body}"
    e = json.loads(Path(body["path"]).read_text())["hosts"]["the-printer"]
    assert e["method"] == "known-no-cred", e
    assert e["described"].startswith("Ricoh"), e
    assert e["role_hint"] == "printer" and e["owner"] == "the copier contractor", e
    for secret in ("password", "key_path", "api_token", "enable_password"):
        assert not e.get(secret), f"known-no-cred stored a {secret}"
    env = dict(os.environ)
    env["NETWALK_HOME"] = str(HERE / ".tmp-netwalk-home")
    out = subprocess.run([sys.executable, str(CRED), "answers", "--site", SITE],
                         capture_output=True, text=True, env=env)
    assert "Ricoh MP C4504" in out.stdout, "answers did not print the description"
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "netwalk_exec.py"), "run",
                        "--site", SITE, "--host", "the-printer", "--cmd", "show version"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 3, f"expected no-credential refusal, got {r.returncode}"
    assert "Ricoh" in r.stderr, f"the refusal did not quote the description: {r.stderr}"


@case("the form offers the described-but-no-login option")
def _(url, port):
    code, body = get(url)
    assert code == 200, code
    assert "I know what it is" in body, "the known-no-cred option is missing"
    assert 'name="described"' in body and 'name="role_hint"' in body, "description fields missing"


@case("\"not ours\" is stored and the exec wrapper refuses to connect")
def _(url, port):
    payload = {"hosts": {"landlord-router": {"method": "not-ours", "ip": "192.0.2.45",
                                             "vendor": "unknown",
                                             "note": "belongs to the building"}}}
    code, body = post(f"{url}/save", payload, {"Origin": f"http://127.0.0.1:{port}"})
    assert code == 200, f"{code} {body}"
    env = dict(os.environ)
    env["NETWALK_HOME"] = str(HERE / ".tmp-netwalk-home")
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "netwalk_exec.py"), "run",
                        "--site", SITE, "--host", "landlord-router",
                        "--cmd", "/system identity print"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 5, f"expected refusal, got rc={r.returncode}: {r.stderr}"
    assert "OUT OF SCOPE" in r.stderr, r.stderr


@case("the form marks which devices are new this round")
def _(url, port):
    proc, url, port = start(["--host", "brand-new-switch,192.0.2.99,cisco", "--round", "3"])
    code, body = get(url)
    assert code == 200, code
    assert "NEW this round" in body, "new-device badge missing"
    assert "I don&#x27;t know what this device is" in body or "I don't know what this device is" in body, \
        "the I-don't-know option is not on the form"
    assert "Not ours" in body, "the out-of-scope option is not on the form"
    assert "crawl round 3" in body, "round number not shown in the header"
    if proc.poll() is None:
        proc.kill(); proc.wait(timeout=5)


@case("export writes an access document with no secret values by default")
def _(url, port):
    post(f"{url}/save", BROWSER_BODY, {"Origin": f"http://127.0.0.1:{port}"})
    env = dict(os.environ)
    env["NETWALK_HOME"] = str(HERE / ".tmp-netwalk-home")
    out_file = HERE / ".tmp-netwalk-home" / "access.md"
    r = subprocess.run([sys.executable, str(CRED), "export", "--site", SITE,
                        "--out", str(out_file)], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    doc = out_file.read_text()
    assert "correct-horse" not in doc, "the default export leaked a password"
    assert "192.0.2.1" in doc and "values not in this file" in doc, doc[:400]
    if os.name != "nt":
        assert oct(out_file.stat().st_mode)[-3:] == "600", oct(out_file.stat().st_mode)


@case("export refuses to write into the folder the customer report lives in")
def _(url, port):
    env = dict(os.environ)
    env["NETWALK_HOME"] = str(HERE / ".tmp-netwalk-home")
    target = Path(env["NETWALK_HOME"]) / "sites" / "leak.md"
    r = subprocess.run([sys.executable, str(CRED), "export", "--site", SITE,
                        "--out", str(target)], capture_output=True, text=True, env=env)
    assert r.returncode != 0 and "refusing to write" in r.stderr, r.stderr
    assert not target.exists(), "it wrote the file anyway"


@case("--with-secrets needs an explicit acknowledgement, then does include them")
def _(url, port):
    post(f"{url}/save", BROWSER_BODY, {"Origin": f"http://127.0.0.1:{port}"})
    env = dict(os.environ)
    env["NETWALK_HOME"] = str(HERE / ".tmp-netwalk-home")
    out_file = HERE / ".tmp-netwalk-home" / "secret.md"
    r = subprocess.run([sys.executable, str(CRED), "export", "--site", SITE,
                        "--out", str(out_file), "--with-secrets"],
                       capture_output=True, text=True, env=env)
    assert r.returncode != 0 and "--i-understand" in r.stderr, r.stderr
    assert not out_file.exists(), "it wrote passwords without the acknowledgement"
    r = subprocess.run([sys.executable, str(CRED), "export", "--site", SITE,
                        "--out", str(out_file), "--with-secrets",
                        "--i-understand-this-file-contains-passwords"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    doc = out_file.read_text()
    assert "correct-horse" in doc, "--with-secrets did not include the password"
    assert "LIVE PASSWORDS" in doc, "the file carries no warning banner"


@case("`list` prints host metadata and never the secret")
def _(url, port):
    post(f"{url}/save", BROWSER_BODY, {"Origin": f"http://127.0.0.1:{port}"})
    env = dict(os.environ)
    env["NETWALK_HOME"] = str(HERE / ".tmp-netwalk-home")
    out = subprocess.run([sys.executable, str(CRED), "list", "--site", SITE],
                         capture_output=True, text=True, env=env)
    assert "r1" in out.stdout, out.stdout
    assert "correct-horse" not in out.stdout + out.stderr, "list leaked the password"


ASK = ["--ask", "r1|reach_how|How do you normally reach this controller?|https://host:8443",
       "--ask", "*|window|When is the maintenance window?|"]


def main() -> int:
    home = HERE / ".tmp-netwalk-home"
    fails = []
    for name, fn in CASES:
        proc = None
        try:
            proc, url, port = start(ASK if "question" in name or "access detail" in name else None)
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
