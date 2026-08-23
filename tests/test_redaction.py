#!/usr/bin/env python3
"""Regression suite for device-secret redaction.

Anything netwalk_exec.py prints goes into the caller's context. When the caller is an
AI agent, that means it is transmitted to a model API and written into a local
transcript, and neither can be taken back. A config export is full of secrets that
belong to the DEVICE rather than to our credential store, so it gets masked on the
way out.

Every case below is a shape found in a real RouterOS export that an earlier version
of the redactor let straight through. The values here are fabricated; the shapes are
not. Run after any change to DEVICE_SECRETS:  python3 tests/test_redaction.py
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import netwalk_exec as E  # noqa: E402

# (description, text, the substring that must NOT survive)
MUST_HIDE = [
    ("plain assignment",
     "/interface wifi security set passphrase=SuperSecret123", "SuperSecret123"),
    ("quoted value after whitespace",
     'set wpa-psk "my wifi password"', "my wifi password"),
    ("single-quoted value",
     "passphrase 'quoted secret'", "quoted secret"),
    ("RouterOS ppp secret",
     "/ppp secret add name=u password=hunter2 service=l2tp", "hunter2"),
    ("radius shared secret",
     "radius add secret=SharedRadiusKey address=192.0.2.5", "SharedRadiusKey"),
    ("Cisco enable secret",
     "enable secret 5 $1$abcd$efghij", "$1$abcd$efghij"),
    ("Cisco username secret",
     "username admin privilege 15 secret 5 $1$xyz$123", "$1$xyz$123"),
    ("Cisco snmp community",
     "snmp-server community publicRO RO", "publicRO"),
    # --- the shapes that got through the first time ---
    ("prefixed key name (container env)",
     'add env="MYSQL_DATABASE=app,MYSQL_PASSWORD=rKzCq4EZoC4Up90O4,MYSQL_USER=app"',
     "rKzCq4EZoC4Up90O4"),
    ("prefixed key at the START of a quoted string",
     'add env="MYSQL_ROOT_PASSWORD=Ftvo2WuJlZPlw9DGqAq0dz,ALLOW_BACKUP=1"',
     "Ftvo2WuJlZPlw9DGqAq0dz"),
    ("namespaced key separated by a colon",
     'comment="mariadb:MYSQL_PASSWORD=rKzCq4EZoC4Up90O4,mariadb,app"',
     "rKzCq4EZoC4Up90O4"),
    ("deep prefix",
     'add env="GF_SECURITY_ADMIN_PASSWORD=s3cr3tadmin,GF_SECURITY_ADMIN_USER=admin"',
     "s3cr3tadmin"),
    ("lowercase prefixed key",
     'env="pihole:FTLCONF_webserver_api_password=letmein1,pihole:X=1"', "letmein1"),
    ("second secret in the same env string",
     'add env="DB_HOST=127.0.0.1,DB_PASSWORD=rKzCq4EZoC4Up90O4,DB_PORT=3306"',
     "rKzCq4EZoC4Up90O4"),
    ("value split by a RouterOS line continuation",
     'add env="MYSQL_PASSWORD=rKzCq4EZoC4Up90O4pNfi83dHUbE6O1\\\n    w,MYSQL_USER=app"',
     "rKzCq4EZoC4Up90O4pNfi83dHUbE6O1"),
    ("api token",
     "api-key: ak_live_9f8e7d6c5b", "ak_live_9f8e7d6c5b"),
    ("private key block",
     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n"
     "-----END OPENSSH PRIVATE KEY-----", "b3BlbnNzaC1rZXktdjEAAAA"),
]

# Ordinary output an engineer needs to read must come through byte for byte.
MUST_KEEP = [
    "  cpu-load: 8%",
    "password rotation policy is 90 days",
    "ether1  R  1500  1G-baseT-full",
    "address=192.0.2.1/24 network=192.0.2.0",
    'name="office-switch" comment="rack 3"',
    "/interface bridge port add bridge=bridge interface=ether2",
    "uptime: 2w5d19h",
    "tokens: 12 free",
    "  rx-error=0 tx-error=0 rx-drop=12",
    "/ip firewall filter add chain=input action=accept protocol=tcp dst-port=22",
]

# Broad sweep over a synthetic export - nothing shaped like `<anything>password=<value>`
# may survive, whatever the prefix or the delimiter.
SWEEP = re.compile(
    r'(?i)[\w.\-:]*(?:password|passwd|secret|psk|passphrase|community|api[_-]?key|token)'
    r'[\w.\-]*\s*[:=]\s*([^\s,"\']{3,})')


def test_report_sweep_catches_prefixed_secrets():
    """The renderer refuses to build a report from a record holding credential material.

    That guarantee failed once, in front of a customer: an evidence excerpt read
    `trap-community: <value>` and the pattern was anchored on the word "snmp", so the
    sweep walked past it and the report rendered. A community string is a community
    string whatever word precedes it.
    """
    import netwalk_report as R
    must_catch = [
        "enabled: yes  trap-community: hunter2",
        "snmp community: public",
        "ro-community=mysecret",
        "trap-community:secret",
        "wpa2-pre-shared-key: abc123",
        "enable secret 5 $1$ab$cdefgh",
    ]
    must_pass = [
        "214 interface resets",
        "community engagement is not a secret",
        "chain=input action=drop",
        # an excerpt the redactor has already been through must not block the render -
        # the first fix for this bug refused every report that had ever been cleaned
        "enabled: yes  trap-community: <redacted>",
        "password = <redacted>",
    ]
    bad = []
    for x in must_catch:
        rec = {"findings": [{"evidence": [{"excerpt": x}]}]}
        if not R.sweep(rec):
            bad.append(f"MISSED  {x}")
    for x in must_pass:
        rec = {"findings": [{"evidence": [{"excerpt": x}]}]}
        if R.sweep(rec):
            bad.append(f"FALSE POSITIVE  {x}")
    for b in bad:
        print(f"  FAILED {b}")
    if not bad:
        print(f"  ok     report sweep: {len(must_catch)} secret shapes caught, "
              f"{len(must_pass)} innocent strings passed")
    return len(bad)


def main() -> int:
    _extra = test_report_sweep_catches_prefixed_secrets()
    fails = []
    for _ in range(test_report_sweep_catches_prefixed_secrets()):
        fails.append('report sweep missed a secret shape - see above')

    for desc, text, secret in MUST_HIDE:
        out, _ = E.redact_device_secrets(text)
        if secret in out:
            fails.append(f"LEAK       {desc}\n           {out[:120]}")
            print(f"  LEAK   {desc}")
        else:
            print(f"  ok     {desc}")

    for text in MUST_KEEP:
        out, _ = E.redact_device_secrets(text)
        if out != text:
            fails.append(f"OVERREACH  {text!r}\n           -> {out!r}")
            print(f"  OVER   {text[:60]}")
        else:
            print(f"  ok     (untouched) {text[:52]}")

    blob = "\n".join(t for _d, t, _s in MUST_HIDE)
    out, _ = E.redact_device_secrets(blob)
    survivors = [m.group(0)[:70] for m in SWEEP.finditer(out) if m.group(1) != "<redacted>"]
    if survivors:
        fails.append("SWEEP survivors:\n           " + "\n           ".join(survivors))
        print(f"  SWEEP  {len(survivors)} secret-ish value(s) survived the combined blob")
    else:
        print("  ok     combined sweep: nothing secret-shaped survived")

    # If a real export is sitting next to the tests, sweep that too - a live config
    # finds shapes no hand-written fixture will.
    live = os.environ.get("NETWALK_REDACTION_FIXTURE")
    if live and Path(live).exists():
        out, n = E.redact_device_secrets(Path(live).read_text(encoding="utf-8", errors="replace"))
        survivors = [m.group(0)[:70] for m in SWEEP.finditer(out) if m.group(1) != "<redacted>"]
        print(f"  {'ok' if not survivors else 'LEAK'}     live fixture: {n} redacted, "
              f"{len(survivors)} survived")
        if survivors:
            fails.append("live fixture survivors: " + "; ".join(survivors[:5]))

    total = len(MUST_HIDE) + len(MUST_KEEP) + 1
    for f in fails:
        print(f"\n{f}")
    print(f"\n{total - len(fails)}/{total} redaction checks pass")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
