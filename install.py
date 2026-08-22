#!/usr/bin/env python3
"""Install the netwalk skills into Claude Code. Works on Windows, macOS and Linux.

  python3 install.py               # install / upgrade
  python3 install.py --check       # environment report, change nothing
  python3 install.py --uninstall   # remove the skills (never touches your credential store)
  python3 install.py --skills-dir /some/where

What it does:
  1. copies this repo's runtime (scripts, schema, assets, tests, examples) to
     <skills-dir>/netwalk/toolkit/
  2. writes one skill folder per netwalk command, with {{TOOLKIT}} in each SKILL.md
     replaced by the real absolute path on THIS machine - so the skills work no
     matter where you cloned the repo or which OS you are on
  3. prints an environment report so you find out about a missing ssh client now
     rather than halfway through a customer's site
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
RUNTIME = ["scripts", "schema", "assets", "tests", "examples"]
SKILLS = ["netwalk", "netwalk-login", "netwalk-scan", "netwalk-diag",
          "netwalk-map", "netwalk-fullreport"]
TOOLKIT_SUBDIR = Path("netwalk") / "toolkit"


def default_skills_dir() -> Path:
    env = os.environ.get("CLAUDE_CONFIG_DIR")
    base = Path(env).expanduser() if env else Path.home() / ".claude"
    return base / "skills"


def copy_runtime(dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for name in RUNTIME:
        src = REPO / name
        if not src.exists():
            continue
        shutil.copytree(src, dest / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.bak.*"))
    for f in ("README.md", "LICENSE"):
        if (REPO / f).exists():
            shutil.copy2(REPO / f, dest / f)
    # NOTE: nothing from an engagement is ever stored here. This directory is
    # deleted and rewritten on every upgrade; scan records live under
    # $NETWALK_HOME/sites (default ~/.netwalk/sites) precisely so an upgrade
    # cannot take a customer's scan history with it.


def install(skills_dir: Path) -> int:
    toolkit = (skills_dir / TOOLKIT_SUBDIR).resolve()
    print(f"toolkit  -> {toolkit}")
    copy_runtime(toolkit)

    # POSIX: make the entry points executable; harmless no-op elsewhere
    if os.name != "nt":
        for py in (toolkit / "scripts").glob("netwalk_*.py"):
            py.chmod(0o755)

    token = toolkit.as_posix() if os.name != "nt" else str(toolkit)
    written = 0
    for name in SKILLS:
        src = REPO / "skills" / name / "SKILL.md"
        if not src.exists():
            print(f"  ! missing {src}", file=sys.stderr)
            continue
        text = src.read_text(encoding="utf-8").replace("{{TOOLKIT}}", token)
        out_dir = skills_dir / name
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "SKILL.md").write_text(text, encoding="utf-8")
        print(f"  skill  -> {out_dir / 'SKILL.md'}")
        written += 1

    print(f"\ninstalled {written} skill(s)\n")
    sys.path.insert(0, str(toolkit / "scripts"))
    try:
        import netwalk_common  # noqa: PLC0415
        netwalk_common.preflight()
    except Exception as e:  # noqa: BLE001
        print(f"(environment check failed: {e})", file=sys.stderr)

    print("\nnext:")
    print("  optional logos :  python3 "
          f"{(toolkit / 'scripts' / 'netwalk_logos.py')} fetch")
    print("  self-test      :  python3 "
          f"{(toolkit / 'tests' / 'test_policy.py')}")
    print("  then in Claude Code:  /netwalk    (or /netwalk-scan, /netwalk-login, ...)")
    return 0


def uninstall(skills_dir: Path) -> int:
    removed = 0
    for name in SKILLS:
        d = skills_dir / name
        if d.exists():
            shutil.rmtree(d)
            print(f"  removed {d}")
            removed += 1
    hub = skills_dir / "netwalk"
    if hub.exists():
        shutil.rmtree(hub)
        print(f"  removed {hub}")
    print(f"\nremoved {removed} skill(s).")
    print("Your credential store was left alone. To delete it:")
    print("  python3 scripts/netwalk_cred.py forget --site <slug>")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skills-dir", type=Path, default=None)
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--check", action="store_true", help="environment report only")
    args = ap.parse_args()

    if args.check:
        sys.path.insert(0, str(REPO / "scripts"))
        import netwalk_common  # noqa: PLC0415
        return netwalk_common.preflight()

    skills_dir = (args.skills_dir or default_skills_dir()).expanduser().resolve()
    skills_dir.mkdir(parents=True, exist_ok=True)
    print(f"skills   -> {skills_dir}\n")
    return uninstall(skills_dir) if args.uninstall else install(skills_dir)


if __name__ == "__main__":
    sys.exit(main())
