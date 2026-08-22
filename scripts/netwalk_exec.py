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
    for s in secrets:
        if s and len(s) >= 3:
            text = text.replace(s, "***")
    return text


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


def run_one(entry: dict, command: str, timeout: int, max_bytes: int) -> dict:
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

    if backend == "paramiko":
        out, err, rc = _run_paramiko(entry, command, timeout)
    elif backend == "plink":
        out, err, rc = _run_plink(entry, command, timeout)
    else:
        argv, env = build_ssh_argv(entry, command, backend)
        out, err, rc = _run_subprocess(argv, env, timeout)

    truncated = len(out) > max_bytes
    if truncated:
        out = out[:max_bytes]

    secrets = _secrets_of(entry)
    return {**base, "allowed": True, "backend": backend, "exit_code": rc,
            "stdout": scrub(out, secrets), "stderr": scrub(err, secrets),
            "truncated": truncated, "bytes_out": len(out)}


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
    results = []
    worst = 0
    for c in commands:
        res = run_one(entry, c, args.timeout, args.max_bytes)
        results.append(res)
        if args.evidence:
            append_evidence(args.evidence, args.host, res)
        if not res["allowed"]:
            worst = max(worst, 2)
        elif res.get("exit_code"):
            worst = max(worst, 1)

    if args.json:
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
        if res.get("stderr", "").strip():
            print(f"--- stderr: {res['stderr'].strip()}", file=sys.stderr)
        if res.get("exit_code"):
            print(f"--- exit {res['exit_code']}", file=sys.stderr)
    return worst


def cmd_check(args: argparse.Namespace) -> int:
    v = policy.check(args.cmd, args.vendor)
    print(f"{'ALLOW' if v.allowed else 'DENY '} [{v.profile}] {v.reason}")
    return 0 if v.allowed else 1


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
    print(f"{'REACHABLE' if ok else 'FAILED'} {args.host} ({entry.get('ip')}) "
          f"vendor={entry.get('vendor')} profile={name} transport={backend}")
    if ok:
        print(res["stdout"].strip()[:600])
        return 0
    print((res.get("stderr") or res.get("reason") or "no output").strip()[:400], file=sys.stderr)
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
