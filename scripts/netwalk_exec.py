#!/usr/bin/env python3
"""Run a READ-ONLY command on a device whose credentials live in the netwalk vault.

The agent calls this instead of calling ssh itself. Two reasons:
  1. Credentials never enter the agent's context - this process reads the vault,
     the agent only ever passes a site slug and a host id.
  2. Every command is gated by netwalk_policy.check() before it leaves the machine,
     so "netwalk never changes a device" is enforced by code, not by good intentions.

  netwalk_exec.py run    --site S --host H --cmd 'show version'
  netwalk_exec.py run    --site S --host H --cmd-file cmds.txt --evidence run.jsonl
  netwalk_exec.py check  --vendor mikrotik --cmd '/export'      # policy only, no connection
  netwalk_exec.py probe  --site S --host H                      # can we log in at all?
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netwalk_common as C  # noqa: E402
import netwalk_policy as policy  # noqa: E402

DEFAULT_TIMEOUT = 45
DEFAULT_MAX_BYTES = 200_000

# Plenty of field gear is a decade old, so we widen the algorithm lists - but only
# with algorithms this machine's ssh still knows about. Naming a retired one (ssh-dss
# on OpenSSH 10) makes ssh refuse the whole command line, which looks exactly like
# "device unreachable" and sends you debugging the wrong end of the cable.
LEGACY = {
    "HostKeyAlgorithms": ("key", ["ssh-rsa", "ssh-dss"]),
    "PubkeyAcceptedAlgorithms": ("key", ["ssh-rsa"]),
    "KexAlgorithms": ("kex", ["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
                              "diffie-hellman-group-exchange-sha1"]),
    "Ciphers": ("cipher", ["aes128-cbc", "aes256-cbc", "3des-cbc"]),
}


def _supported(kind: str) -> set[str]:
    try:
        out = subprocess.run(["ssh", "-Q", kind], capture_output=True, timeout=5)
        return set(out.stdout.decode().split())
    except Exception:
        return set()


def _legacy_opts() -> list[str]:
    opts: list[str] = []
    for name, (kind, wanted) in LEGACY.items():
        have = _supported(kind)
        usable = [a for a in wanted if a in have] if have else []
        if usable:
            opts += ["-o", f"{name}=+{','.join(usable)}"]
    return opts


SSH_BASE = [
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", f"UserKnownHostsFile={C.known_hosts()}",
    "-o", "ConnectTimeout=10",
    "-o", "LogLevel=ERROR",
    "-o", "NumberOfPasswordPrompts=1",
] + _legacy_opts()


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def die(msg: str, code: int = 1):
    print(f"netwalk_exec: {msg}", file=sys.stderr)
    raise SystemExit(code)


def load_host(site: str, host: str) -> dict:
    p = C.creds_dir() / f"{C.slugify(site)}.json"
    if not p.exists():
        die(f"no credential store for site {site!r}. Run /netwalk-login first.", 3)
    vault = json.loads(p.read_text(encoding="utf-8"))
    entry = vault.get("hosts", {}).get(host)
    if not entry:
        known = ", ".join(sorted(vault.get("hosts", {}))) or "(none)"
        die(f"host {host!r} is not in the {site!r} vault. Known: {known}", 3)
    return entry


def scrub(text: str, secrets: list[str]) -> str:
    """Mask credentials we know about (from the vault) wherever a device echoes them."""
    for s in secrets:
        if s and len(s) >= 3:
            text = text.replace(s, "***")
    return text


# Secrets that live in the DEVICE's own config rather than in our vault: PSKs, SNMP
# communities, RADIUS shared secrets, password hashes. A config export is full of
# them. Anything this tool prints ends up in the caller's context - and for an AI
# agent that means it is transmitted and retained - so it is masked by default.
# The file written by --out is never redacted; full fidelity stays on disk.
# Keyword that names a secret. Real configs prefix these constantly - MYSQL_PASSWORD,
# GF_SECURITY_ADMIN_PASSWORD, DB_PASSWORD, wpa2-pre-shared-key - so the prefix has to be
# part of the pattern. Missing that is exactly how a container env block full of database
# passwords sails through a redactor that only looks for a bare `password=`.
_SECRET_WORD = (r'[\w.\-]*'
                r'(?:passwords?|passwd|pwd|secrets?|psk|passphrase|pre[-_]?shared[-_]?key|'
                r'shared[-_]?secret|auth[-_]?key|enc(?:ryption)?[-_]?key|community|'
                r'api[-_]?key|access[-_]?key|token|credentials?)')
# Stop at a comma or a quote: env strings pack several secrets into one value and a
# greedy match would either miss the later ones or eat the whole line.
_SECRET_VAL = r'("[^"]*"|\'[^\']*\'|[^\s,"\']+)'

DEVICE_SECRETS = [
    (re.compile(r'(?i)((?:^|[^\w.\-])' + _SECRET_WORD + r'\s*[:=]\s*)' + _SECRET_VAL),
     r"\1<redacted>"),
    # whitespace-separated, trusted only for a quoted value so ordinary prose survives
    (re.compile(r'(?i)((?:^|[^\w.\-])' + _SECRET_WORD + r'\s+)("[^"]*"|\'[^\']*\')'),
     r"\1<redacted>"),
    (re.compile(r'(?im)^(\s*(?:enable\s+)?secret\s+\d?\s*)(\S+)'), r"\1<redacted>"),
    (re.compile(r'(?im)^(\s*username\s+\S+\s+(?:privilege\s+\d+\s+)?'
                r'(?:secret|password)\s+\d?\s*)(\S+)'), r"\1<redacted>"),
    (re.compile(r'(?i)(snmp-server\s+community\s+)(\S+)'), r"\1<redacted>"),
    (re.compile(r'(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?'
                r'(-----END [A-Z ]*PRIVATE KEY-----)'), r"\1<redacted>\2"),
]

# RouterOS (and others) wrap long lines with a trailing backslash, which can split a
# secret in half and let the tail through. Join continuations before matching.
_CONTINUATION = re.compile(r"\\\n\s*")


def redact_device_secrets(text: str) -> tuple[str, int]:
    hits = 0
    text = _CONTINUATION.sub("", text)
    for pat, repl in DEVICE_SECRETS:
        text, n = pat.subn(repl, text)
        hits += n
    return text, hits


def _needs_password(entry: dict) -> bool:
    return bool(entry.get("password")) and entry.get("method") in ("password", "key+password")


def _secrets_of(entry: dict) -> list[str]:
    return [entry.get(k) for k in ("password", "enable_password", "api_token") if entry.get(k)]


def build_ssh_argv(entry: dict, command: str, backend: str) -> tuple[list[str], dict]:
    user = entry.get("username") or ""
    ip = entry.get("ip") or ""
    port = str(entry.get("port") or 22)
    method = entry.get("method") or "password"
    target = f"{user}@{ip}" if user else ip
    env = dict(os.environ)
    argv: list[str] = []

    if backend == "sshpass":
        env["SSHPASS"] = entry["password"]
        argv += ["sshpass", "-e"]

    argv += ["ssh", "-T", "-p", port, *SSH_BASE]

    # A site whose gear only answers from inside is the normal case, not the exception.
    # The jump host comes from the login form, so the user names it once in the browser
    # rather than being asked for it in conversation.
    if entry.get("jump_host"):
        argv += ["-J", entry["jump_host"]]

    if method in ("key", "key+password") and entry.get("key_path"):
        kp = os.path.expanduser(entry["key_path"])
        if not os.path.exists(kp):
            die(f"key file not found: {kp} (fix it with /netwalk-login)", 3)
        argv += ["-i", kp, "-o", "IdentitiesOnly=yes"]
        if method == "key":
            argv += ["-o", "BatchMode=yes", "-o", "PasswordAuthentication=no"]
    elif method == "password":
        argv += ["-o", "PubkeyAuthentication=no",
                 "-o", "PreferredAuthentications=password,keyboard-interactive"]

    argv += [target, command]
    return argv, env


def _run_subprocess(argv: list[str], env: dict, timeout: int) -> tuple[str, str, int]:
    try:
        proc = subprocess.run(argv, env=env, capture_output=True, timeout=timeout)
        return (proc.stdout.decode("utf-8", "replace"),
                proc.stderr.decode("utf-8", "replace"), proc.returncode)
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s", 124
    except FileNotFoundError as e:
        die(f"missing binary: {e}", 4)
        raise


def _run_paramiko(entry: dict, command: str, timeout: int) -> tuple[str, str, int]:
    """Pure-Python transport. The only one that does passwords on Windows without
    a third-party binary, so it is what makes this toolkit portable."""
    import paramiko

    client = paramiko.SSHClient()
    kh = C.known_hosts()
    if kh.exists():
        try:
            client.load_host_keys(str(kh))
        except Exception:  # noqa: BLE001
            pass
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": entry.get("ip"), "port": int(entry.get("port") or 22),
        "username": entry.get("username") or None, "timeout": 10,
        "banner_timeout": 25, "auth_timeout": 25,
        "look_for_keys": False, "allow_agent": False,
    }
    if entry.get("key_path"):
        kwargs["key_filename"] = os.path.expanduser(entry["key_path"])
    if entry.get("password"):
        kwargs["password"] = entry["password"]
    try:
        client.connect(**kwargs)
        _, out_f, err_f = client.exec_command(command, timeout=timeout)
        out = out_f.read().decode("utf-8", "replace")
        err = err_f.read().decode("utf-8", "replace")
        rc = out_f.channel.recv_exit_status()
        return out, err, rc
    except Exception as e:  # noqa: BLE001
        return "", f"paramiko: {type(e).__name__}: {e}", 255
    finally:
        try:
            client.save_host_keys(str(kh))
        except Exception:  # noqa: BLE001
            pass
        client.close()


def _run_plink(entry: dict, command: str, timeout: int) -> tuple[str, str, int]:
    argv = ["plink", "-ssh", "-batch", "-P", str(entry.get("port") or 22)]
    if entry.get("key_path"):
        argv += ["-i", os.path.expanduser(entry["key_path"])]
    if entry.get("password"):
        argv += ["-pw", entry["password"]]
    user = entry.get("username") or ""
    argv += [f"{user}@{entry.get('ip')}" if user else str(entry.get("ip")), command]
    return _run_subprocess(argv, dict(os.environ), timeout)


def run_one(entry: dict, command: str, timeout: int, max_bytes: int,
            redact: bool = True) -> dict:
    vendor = entry.get("vendor") or "unknown"
    verdict = policy.check(command, vendor)
    started = now_iso()
    base = {"command": command, "at": started, "profile": verdict.profile}

    if not verdict.allowed:
        return {**base, "allowed": False, "reason": verdict.reason,
                "exit_code": None, "stdout": "", "stderr": ""}

    if entry.get("method") == "api":
        return {**base, "allowed": True, "exit_code": None, "stdout": "",
                "reason": "api method - drive the vendor HTTP API yourself",
                "stderr": "netwalk_exec only speaks SSH; this host is registered as method=api"}

    backend, why = C.detect_transport(_needs_password(entry))
    if backend == "none":
        die(f"cannot connect to {entry.get('ip')}: {why}", 4)

    if backend == "paramiko" and entry.get("jump_host"):
        die("this host is set to connect through a jump host, which needs the OpenSSH "
            "client. Install OpenSSH, or clear the jump host on the login form.", 4)
    if backend == "paramiko":
        out, err, rc = _run_paramiko(entry, command, timeout)
    elif backend == "plink":
        out, err, rc = _run_plink(entry, command, timeout)
    else:
        argv, env = build_ssh_argv(entry, command, backend)
        out, err, rc = _run_subprocess(argv, env, timeout)

    secrets = _secrets_of(entry)
    raw = scrub(out, secrets)          # full fidelity, for --out / the operator's disk
    shown = raw
    redacted = 0
    if redact:
        shown, redacted = redact_device_secrets(shown)
    truncated = len(shown) > max_bytes
    if truncated:
        shown = shown[:max_bytes]

    return {**base, "allowed": True, "backend": backend, "exit_code": rc,
            "stdout": shown, "raw_stdout": raw, "stderr": scrub(err, secrets),
            "truncated": truncated, "bytes_out": len(raw), "redacted": redacted}


def append_evidence(path: str, host: str, res: dict) -> None:
    rec = {"host_id": host, "command": res["command"], "at": res["at"],
           "exit_code": res.get("exit_code"), "bytes_out": res.get("bytes_out", 0)}
    if not res.get("allowed"):
        rec["blocked"] = res.get("reason")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def cmd_run(args: argparse.Namespace) -> int:
    commands: list[str] = list(args.cmd)
    if args.cmd_file:
        with open(args.cmd_file, "r", encoding="utf-8") as fh:
            commands += [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    if not commands:
        die("give at least one --cmd or a --cmd-file")

    entry = load_host(args.site, args.host)
    out_fh = None
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        out_fh = open(args.out, "w", encoding="utf-8")
    results = []
    worst = 0
    for c in commands:
        res = run_one(entry, c, args.timeout, args.max_bytes, redact=not args.raw)
        if out_fh and res.get("allowed"):
            out_fh.write(f"### {c}\n{res.get('raw_stdout', '')}\n")
        results.append(res)
        if args.evidence:
            append_evidence(args.evidence, args.host, res)
        if not res["allowed"]:
            worst = max(worst, 2)
        elif res.get("exit_code"):
            worst = max(worst, 1)

    if out_fh:
        out_fh.close()
        harden = C.harden_path(Path(args.out))
        total = sum(r.get("bytes_out", 0) for r in results)
        print(f"wrote {total:,} bytes from {len(results)} command(s) to {args.out} [{harden[1]}]")
        print("NOT printed here on purpose - a config export contains PSKs, community "
              "strings and password hashes, and anything printed enters the agent's context.")
        for res in results:
            flag = "BLOCKED" if not res["allowed"] else ("ok" if not res.get("exit_code") else f"exit {res['exit_code']}")
            print(f"  {flag:>8}  {res['command']}")
        return worst

    if args.json:
        for r in results:
            r.pop("raw_stdout", None)
        print(json.dumps({"host": args.host, "site": args.site,
                          "vendor": entry.get("vendor"), "results": results}, indent=2))
        return worst

    for res in results:
        print(f"\n===== [{args.host}] $ {res['command']}")
        if not res["allowed"]:
            print(f"BLOCKED (read-only policy / {res['profile']}): {res['reason']}")
            continue
        if res.get("stdout"):
            print(res["stdout"].rstrip())
        if res.get("truncated"):
            print(f"... [truncated at {args.max_bytes} bytes]")
        if res.get("redacted"):
            print(f"--- {res['redacted']} secret value(s) in this output were replaced with "
                  f"<redacted>; use --out to keep the full text on disk", file=sys.stderr)
        if res.get("stderr", "").strip():
            print(f"--- stderr: {res['stderr'].strip()}", file=sys.stderr)
        if res.get("exit_code"):
            print(f"--- exit {res['exit_code']}", file=sys.stderr)
    return worst


def cmd_check(args: argparse.Namespace) -> int:
    v = policy.check(args.cmd, args.vendor)
    print(f"{'ALLOW' if v.allowed else 'DENY '} [{v.profile}] {v.reason}")
    return 0 if v.allowed else 1


def server_auth_methods(entry: dict, timeout: int = 10) -> list[str]:
    """Ask the device which authentication methods it will accept.

    `Permission denied (publickey)` on a host where you stored a password reads like
    a wrong password. It is not - it means the device will never accept one. Saying
    so turns a retype-the-password loop into a one-line fix.
    """
    ssh = C.ssh_binary()
    if not ssh:
        return []
    # -v is required: the method list is a debug1 line. Every auth type is switched
    # off so this asks the question without making a login attempt the device would
    # log as a failure.
    argv = [ssh, "-v", "-o", "BatchMode=yes",
            "-o", "PubkeyAuthentication=no", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", f"UserKnownHostsFile={C.known_hosts()}",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=8",
            "-p", str(entry.get("port") or 22),
            f"{entry.get('username','')}@{entry.get('ip')}" if entry.get("username")
            else str(entry.get("ip")), "exit"]
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout)
    except Exception:  # noqa: BLE001
        return []
    m = re.search(r"Authentications that can continue:\s*([\w,\-]+)",
                  r.stderr.decode("utf-8", "replace"))
    return m.group(1).split(",") if m else []


def diagnose_auth(entry: dict) -> str:
    """One actionable line explaining an authentication failure."""
    accepts = server_auth_methods(entry)
    if not accepts:
        return ("could not determine which authentication methods the device accepts - "
                "check the IP, the port, and whether SSH is enabled at all")
    stored = entry.get("method") or "unknown"
    have = "publickey" if stored in ("key", "key+password") else "password"
    if have in accepts or (have == "password" and "keyboard-interactive" in accepts):
        return (f"the device accepts {','.join(accepts)} and you stored a {stored} credential, "
                f"so the credential itself is being rejected - check the username and the value")
    if stored == "password" and accepts == ["publickey"]:
        return ("this device accepts publickey ONLY - a password will never work here, however "
                "correct it is. Re-run /netwalk-login, choose 'SSH key file', and give the path "
                "to a key already authorised on the device (RouterOS: /user ssh-keys print)")
    return (f"the device accepts {','.join(accepts)} but you stored a {stored} credential - "
            f"re-run /netwalk-login and pick a method the device supports")


PROBE = {
    "mikrotik": "/system resource print",
    "cisco": "show version",
    "aruba": "show version",
    "hp": "show version",
    "fortinet": "get system status",
    "juniper": "show version",
    "linux": "uname -a",
    "windows": "hostname",
}


def cmd_probe(args: argparse.Namespace) -> int:
    entry = load_host(args.site, args.host)
    name, _ = policy.resolve_profile(entry.get("vendor"))
    res = run_one(entry, PROBE.get(name, "show version"), args.timeout, 4000)
    ok = res.get("exit_code") == 0 and res.get("stdout", "").strip()
    backend, why = C.detect_transport(_needs_password(entry))
    via = f" via {entry['jump_host']}" if entry.get("jump_host") else ""
    print(f"{'REACHABLE' if ok else 'FAILED'} {args.host} ({entry.get('ip')}){via} "
          f"vendor={entry.get('vendor')} profile={name} transport={backend}")
    if ok:
        print(res["stdout"].strip()[:600])
        return 0
    err = (res.get("stderr") or res.get("reason") or "no output").strip()
    print(err[:400], file=sys.stderr)
    if "permission denied" in err.lower() or "authentication" in err.lower():
        print(f"  -> {diagnose_auth(entry)}", file=sys.stderr)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(prog="netwalk_exec.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run")
    r.add_argument("--site", required=True)
    r.add_argument("--host", required=True)
    r.add_argument("--cmd", action="append", default=[])
    r.add_argument("--cmd-file")
    r.add_argument("--evidence", help="append a JSONL line per command for the report's evidence log")
    r.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    r.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    r.add_argument("--out", help="write the FULL device output to this file and print only a "
                                 "summary - use this for config exports so their secrets never "
                                 "enter the caller's context")
    r.add_argument("--raw", action="store_true",
                   help="do not mask PSKs/community strings/hashes in what is printed. "
                        "Only for a human at a terminal.")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("check", help="ask the policy about a command without connecting")
    c.add_argument("--vendor", required=True)
    c.add_argument("--cmd", required=True)
    c.set_defaults(func=cmd_check)

    p = sub.add_parser("probe", help="verify the stored credential actually logs in")
    p.add_argument("--site", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--timeout", type=int, default=20)
    p.set_defaults(func=cmd_probe)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
