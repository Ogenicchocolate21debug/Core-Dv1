#!/usr/bin/env python3
"""Rebuild AGENTS.md from the skills, so the two can never drift.

AGENTS.md is the agent-agnostic form of the Claude Code skills. Keeping it by hand
means every edit to a SKILL.md has to be remembered twice, and the second one is the
one that gets forgotten - so it is generated instead.

The preamble (everything above the first `## \\`skill-name\\`` heading) is hand-written
prose and is preserved exactly. Everything below it is rebuilt from skills/*/SKILL.md.

  python3 tools/build_agents.py            # rewrite AGENTS.md
  python3 tools/build_agents.py --check    # exit 1 if it is out of date, change nothing
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENTS = ROOT / "AGENTS.md"
SKILLS = ROOT / "skills"

# The order they are presented in: the umbrella first, then the stages in the order a
# survey actually runs them.
ORDER = ["netwalk", "netwalk-login", "netwalk-scan", "netwalk-diag",
         "netwalk-map", "netwalk-fullreport"]

FIRST_SECTION = re.compile(r"^## `", re.MULTILINE)


def front_matter(text: str) -> tuple[dict, str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.index("\n---\n", 3)
    meta = {}
    for line in text[4:end].splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip().strip('"')
    return meta, text[end + 5:].lstrip("\n")


def demote(body: str) -> str:
    """`# x` -> `## x`, so a skill's own headings nest under its AGENTS.md section.

    Fenced code is left alone: a `# comment` inside a bash block is not a heading, and
    turning it into one silently corrupts every example.
    """
    out, fenced = [], False
    for line in body.split("\n"):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced and line.startswith("#"):
            line = "#" + line
        out.append(line)
    return "\n".join(out)


def build() -> str:
    src = AGENTS.read_text(encoding="utf-8")
    m = FIRST_SECTION.search(src)
    if not m:
        sys.exit("AGENTS.md has no '## `skill`' section - refusing to guess where the "
                 "hand-written preamble ends")
    out = [src[:m.start()].rstrip() + "\n"]

    names = ORDER + sorted(p.name for p in SKILLS.iterdir()
                           if p.is_dir() and p.name not in ORDER)
    for name in names:
        skill = SKILLS / name / "SKILL.md"
        if not skill.exists():
            continue
        meta, body = front_matter(skill.read_text(encoding="utf-8"))
        body = body.replace("{{TOOLKIT}}", "<TOOLKIT>")
        body = demote(body)
        out.append(f"\n\n## `{name}`\n\n> {meta.get('description', '')}\n\n{body.rstrip()}\n")
    return "".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if AGENTS.md is stale, without writing it")
    args = ap.parse_args()

    new = build()
    old = AGENTS.read_text(encoding="utf-8")
    if new == old:
        print("AGENTS.md is up to date")
        return 0
    if args.check:
        print("AGENTS.md is STALE - run: python3 tools/build_agents.py", file=sys.stderr)
        return 1
    AGENTS.write_text(new, encoding="utf-8")
    print(f"rewrote AGENTS.md ({len(old)} -> {len(new)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
