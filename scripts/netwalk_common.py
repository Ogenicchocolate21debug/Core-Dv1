#!/usr/bin/env python3
"""Cross-platform plumbing shared by the netwalk scripts.

netwalk is meant to run on whatever laptop the engineer walked in with, so nothing
here may assume a POSIX box:

  * paths come from Path.home(), overridable with NETWALK_HOME
  * "make this file private" means chmod on POSIX and icacls on Windows, and it is
    LOUD when it cannot do either - a credential file you think is protected and
    is not is worse than one you know is exposed
  * the SSH transport is picked from what is actually installed, not from what a
    Linux machine usually has
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------- paths

def netwalk_home() -> Path:
    override = os.environ.get("NETWALK_HOME")
    base = Path(override).expanduser() if override else Path.home() / ".netwalk"
    return base


def creds_dir() -> Path:
    d = netwalk_home() / "creds"
    d.mkdir(parents=True, exist_ok=True)
    harden_path(d, is_dir=True)
    return d


def known_hosts() -> Path:
    p = netwalk_home() / "known_hosts"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def slugify(name: str) -> str:
    out = "".join(c if (c.isalnum() or c in "-_.") else "-" for c in name).strip("-")
    return out or "site"


# ----------------------------------------------------------------- file perms

def harden_path(path: Path, is_dir: bool = False) -> tuple[bool, str]:
    """Restrict `path` to the current user. Returns (ok, human explanation)."""
    if not IS_WINDOWS:
        try:
            os.chmod(path, 0o700 if is_dir else 0o600)
            return True, f"POSIX mode {'0700' if is_dir else '0600'}"
        except OSError as e:
            return False, f"chmod failed: {e}"

    icacls = shutil.which("icacls")
    if not icacls:
        return False, "icacls not found - file permissions were NOT restricted"
    user = os.environ.get("USERNAME") or ""
    domain = os.environ.get("USERDOMAIN") or ""
    principal = f"{domain}\\{user}" if domain and user else (user or "%USERNAME%")
    args = [icacls, str(path), "/inheritance:r", "/grant:r", f"{principal}:(F)"]
    if is_dir:
        args += ["/T", "/C"]
    try:
        r = subprocess.run(args, capture_output=True, timeout=30)
        if r.returncode == 0:
            return True, f"Windows ACL: only {principal} has access"
        return False, f"icacls exited {r.returncode}: {r.stderr.decode(errors='replace').strip()[:200]}"
    except Exception as e:  # noqa: BLE001
        return False, f"icacls failed: {e}"


def write_private(path: Path, text: str) -> tuple[bool, str]:
    """Write `text` so only this user can read it. Never leaves a world-readable temp."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    harden_path(tmp)
    os.replace(tmp, path)
    return harden_path(path)


def perm_report(path: Path) -> str:
    if not path.exists():
        return "missing"
    if IS_WINDOWS:
        return "Windows ACL (run `icacls <file>` to inspect)"
    mode = stat.S_IMODE(path.stat().st_mode)
    want = 0o700 if path.is_dir() else 0o600
    warn = "" if mode == want else f"  <-- EXPECTED {oct(want)}"
    return f"{oct(mode)}{warn}"


def shred(path: Path) -> None:
    """Overwrite then delete. Not forensic-grade on a CoW/SSD filesystem, and we say so."""
    try:
        size = path.stat().st_size
        with open(path, "r+b") as fh:
            fh.write(b"\0" * size)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    path.unlink(missing_ok=True)


# ------------------------------------------------------------- ssh transport

def ssh_binary() -> str | None:
    return shutil.which("ssh")


def detect_transport(needs_password: bool) -> tuple[str, str]:
    """Pick how we will actually connect. Returns (backend, explanation).

    key-only auth works everywhere OpenSSH exists. Passwords are the awkward case:
    OpenSSH deliberately refuses to read one from a pipe, so we need a helper.
    """
    have_paramiko = False
    try:
        import paramiko  # noqa: F401
        have_paramiko = True
    except Exception:  # noqa: BLE001
        pass

    if not needs_password:
        if ssh_binary():
            return "openssh", "OpenSSH client with key authentication"
        if have_paramiko:
            return "paramiko", "paramiko (no ssh binary on PATH)"
        return "none", "no SSH client found - install OpenSSH, or `pip install paramiko`"

    if have_paramiko:
        return "paramiko", "paramiko (handles passwords on every OS)"
    if shutil.which("sshpass") and ssh_binary():
        return "sshpass", "sshpass + OpenSSH"
    if IS_WINDOWS and shutil.which("plink"):
        return "plink", "PuTTY plink"
    hint = ("pip install paramiko" if IS_WINDOWS else
            "pip install paramiko   (or: brew install sshpass / apt install sshpass)")
    return "none", f"password auth needs a helper this machine does not have - {hint}"


def preflight() -> int:
    """`netwalk_common.py` run directly = an environment check the user can paste back."""
    print(f"platform         : {sys.platform} ({'windows' if IS_WINDOWS else 'posix'})")
    print(f"python           : {sys.version.split()[0]}")
    print(f"netwalk home     : {netwalk_home()}")
    d = creds_dir()
    print(f"credential store : {d}  [{perm_report(d)}]")
    print(f"ssh binary       : {ssh_binary() or 'NOT FOUND'}")
    for label, needs_pw in (("key auth", False), ("password auth", True)):
        backend, why = detect_transport(needs_pw)
        mark = "ok  " if backend != "none" else "MISS"
        print(f"{label:<17}: [{mark}] {backend} - {why}")
    if IS_WINDOWS and not shutil.which("icacls"):
        print("WARNING          : icacls missing, credential files cannot be locked down")
    return 0


if __name__ == "__main__":
    raise SystemExit(preflight())
