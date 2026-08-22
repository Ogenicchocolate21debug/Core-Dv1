#!/usr/bin/env python3
"""Read-only command policy for netwalk.

netwalk NEVER changes a customer's device. That promise is enforced here, in code,
not in a prompt - because a prompt can be argued with and a regex cannot.

Two device classes:
  cli   - the remote end is a vendor CLI, not a shell. A `|` is a device-side
          display filter and is allowed; command separators still are not.
  shell - the remote end is a real shell. Nothing but an allowlisted binary with
          allowlisted arguments gets through, and no metacharacters at all.

Every command is checked against DENY first (deny always wins), then must match an
ALLOW pattern for its vendor. Unknown vendor -> the strictest profile.
"""
from __future__ import annotations

import re

# Separators / redirection that would let one approved command smuggle a second one.
CLI_META = re.compile(r"[;&\n\r><`$\\]|\|\|")
SHELL_META = re.compile(r"[;&\n\r><`$\\|]")

# Applies to every vendor, checked before anything else.
UNIVERSAL_DENY = [
    (r"\breboot\b", "reboots the device"),
    (r"\bshutdown\b", "shuts the device down"),
    (r"\bhalt\b", "halts the device"),
    (r"\bpoweroff\b", "powers the device off"),
    (r"\bfactory[-_ ]?reset\b", "factory resets the device"),
    (r"\bupgrade\b", "changes firmware"),
    (r"\bdowngrade\b", "changes firmware"),
    (r"\bformat\b", "formats storage"),
    (r"\berase\b", "erases storage or config"),
    (r"\|\s*(redirect|tee|append)\b", "pipes output into a file"),
]

PROFILES: dict[str, dict] = {
    # ------------------------------------------------------------------ MikroTik
    "mikrotik": {
        "class": "cli",
        "allow": [
            r"^/?[a-z0-9 /-]*\bprint\b",              # /interface print, /ip address print detail
            r"^/?[a-z0-9 /-]*\bget\b",
            r"^/?[a-z0-9 /-]*\bmonitor\b.*\bonce\b",  # must be one-shot, never streaming
            r"^/?[a-z0-9 /-]*\bmonitor-traffic\b.*\bonce\b",
            r"^/export\b",                            # config export = read-only dump
            r"^/?system\s+resource\s+print",
            r"^/?tool\s+ping\b.*\bcount=\d+",         # bounded ping only
            r"^/?tool\s+traceroute\b.*\bcount=\d+",
            r"^/?tool\s+bandwidth-test\b.*\bduration=\d+s?\b",
            r"^/?log\s+print\b",
        ],
        "deny": [
            (r"(^|[/ ])set\b", "writes config"),
            (r"(^|[/ ])add\b", "creates config"),
            (r"(^|[/ ])remove\b", "deletes config"),
            (r"(^|[/ ])unset\b", "clears config"),
            (r"(^|[/ ])enable\b", "changes state"),
            (r"(^|[/ ])disable\b", "changes state"),
            (r"(^|[/ ])move\b", "reorders rules"),
            (r"(^|[/ ])edit\b", "opens an editor"),
            (r"(^|[/ ])import\b", "applies a config file"),
            (r"(^|[/ ])reset\b", "resets counters or config"),
            (r"(^|[/ ])disconnect\b", "drops a session"),
            (r"(^|[/ ])kill\b", "kills a process"),
            (r"(^|[/ ])blink\b", "changes LED state"),
            (r"(^|[/ ])password\b", "changes a password"),
            (r"\bfile\s+remove\b", "deletes a file"),
        ],
    },
    # --------------------------------------------------------------------- Cisco
    "cisco": {
        "class": "cli",
        "allow": [
            r"^show\b",
            r"^dir\b",
            r"^terminal\s+(length|width)\s+\d+$",     # session-local paging only
            r"^ping\b.*\brepeat\s+\d+",
            r"^traceroute\b",
        ],
        "deny": [
            (r"^conf(ig(ure)?)?\b", "enters config mode"),
            (r"^wr(ite)?\b", "writes config to flash"),
            (r"^copy\b", "copies files or config"),
            (r"^reload\b", "reloads the device"),
            (r"^clear\b", "clears counters, sessions or logs"),
            (r"^no\s", "removes config"),
            (r"^debug\b", "enables debugging, can overload the CPU"),
            (r"^undebug\b", "changes debug state"),
            (r"^delete\b", "deletes a file"),
            (r"^archive\b", "writes an archive"),
            (r"^test\b", "runs a disruptive test"),
            (r"^send\b", "messages other sessions"),
            (r"^install\b", "installs software"),
            (r"^license\b", "changes licensing"),
        ],
    },
    # -------------------------------------------------------- Aruba CX / ProCurve
    "aruba": {
        "class": "cli",
        "allow": [r"^show\b", r"^display\b", r"^dir\b", r"^ping\b.*\brepeat\s+\d+", r"^traceroute\b"],
        "deny": [
            (r"^conf(ig(ure)?)?\b", "enters config mode"),
            (r"^wr(ite)?\b", "writes config"),
            (r"^copy\b", "copies config"),
            (r"^clear\b", "clears counters or logs"),
            (r"^no\s", "removes config"),
            (r"^boot\b", "reboots"),
            (r"^delete\b", "deletes a file"),
            (r"^checkpoint\b", "writes a checkpoint"),
        ],
    },
    "hp": {
        "class": "cli",
        "allow": [r"^show\b", r"^display\b", r"^dir\b", r"^ping\b", r"^traceroute\b"],
        "deny": [
            (r"^conf(ig(ure)?)?\b", "enters config mode"),
            (r"^wr(ite)?\b", "writes config"),
            (r"^copy\b", "copies config"),
            (r"^clear\b", "clears counters"),
            (r"^no\s", "removes config"),
            (r"^boot\b", "reboots"),
            (r"^setup\b", "opens the setup menu"),
        ],
    },
    # ------------------------------------------------------------------ Fortinet
    "fortinet": {
        "class": "cli",
        "allow": [
            r"^get\b", r"^show\b",
            r"^diagnose\s+(hardware|sys\s+session\s+(stat|list)|ip\s+(arp|address|route)|"
            r"switch|netlink|debug\s+config-error-log|sniffer\s+packet\s+\S+\s+\S+\s+\d+\s+\d+)\b",
            r"^execute\s+(ping|traceroute|date|time)\b",
        ],
        "deny": [
            (r"^config\b", "enters config mode"),
            (r"^set\b", "writes config"),
            (r"^unset\b", "clears config"),
            (r"^delete\b", "deletes config"),
            (r"^execute\s+(?!ping|traceroute|date|time)", "runs a state-changing exec command"),
            (r"^diagnose\s+sys\s+(kill|top|reboot)", "kills processes or reboots"),
            (r"\bpurge\b", "purges a table"),
        ],
    },
    # ------------------------------------------------------- Juniper / Extreme / …
    "juniper": {
        "class": "cli",
        "allow": [r"^show\b", r"^ping\b.*\bcount\s+\d+", r"^traceroute\b", r"^file\s+show\b"],
        "deny": [
            (r"^configure\b", "enters config mode"),
            (r"^set\b", "writes config"),
            (r"^delete\b", "deletes config"),
            (r"^commit\b", "commits config"),
            (r"^request\b", "runs a state-changing request"),
            (r"^restart\b", "restarts a daemon"),
            (r"^clear\b", "clears counters or sessions"),
        ],
    },
    # ------------------------------------------------------------- generic Linux
    "linux": {
        "class": "shell",
        "allow": [
            r"^cat\s+/(proc|sys|etc)/\S+$",
            r"^(head|tail)\s+(-n\s*\d+\s+)?/\S+$",
            r"^ls(\s+-[a-zA-Z]+)*(\s+\S+)*$",
            r"^(uname|uptime|hostname|hostnamectl|timedatectl|nproc|whoami|id|w|who|last|date|lsb_release)\b",
            r"^(lscpu|lsblk|lspci|lsusb|lsmod|dmidecode)\b",
            r"^(free|vmstat|iostat|mpstat|sar)\b",
            r"^df(\s+-[a-zA-Z]+)*(\s+\S+)*$",
            r"^du\s+-[a-zA-Z]+\s+\S+$",
            r"^ps\s+\S+",
            r"^top\s+-b\s+-n\s*1\b",
            r"^(ip|bridge|ss|netstat|arp|route|ethtool|iw|iwconfig|resolvectl|networkctl|nmcli)\b",
            r"^(iptables|ip6tables|nft)\s+(-S|-L|list)\b",
            r"^conntrack\s+-[LC]\b",
            r"^systemctl\s+(status|list-units|list-unit-files|is-active|is-enabled|is-failed|show|cat)\b",
            r"^journalctl\b(?!.*--vacuum)",
            r"^dmesg(\s+(-[a-zA-Z]+|[a-z0-9,]+))*$",
            r"^(sensors|smartctl\s+-[aAiHx]|nvme\s+(list|smart-log))\b",
            r"^(zpool\s+(status|list|iostat)|zfs\s+(list|get))\b",
            r"^(pvs|vgs|lvs|mdadm\s+--detail)\b",
            r"^mount$", r"^findmnt\b", r"^sysctl\s+-[an]\b",
            r"^(dpkg\s+-l|rpm\s+-qa|apk\s+info)\b",
            r"^crontab\s+-l$",
            r"^lldpctl\b", r"^lldpcli\s+show\b",
            r"^docker\s+(ps|images|stats\s+--no-stream|inspect|logs\s+--tail\s+\d+|version|info)\b",
            r"^(podman|kubectl\s+get|kubectl\s+describe)\b",
            r"^(pct\s+list|qm\s+list|pvesm\s+status|pveversion)\b",
            r"^ping\s+-c\s*\d+\b",
            r"^(traceroute|mtr\s+--report)\b",
            r"^getent\b",
        ],
        "deny": [
            (r"\b(rm|mv|cp|dd|mkfs|mkswap|fdisk|parted|chmod|chown|chattr|ln|touch|truncate|tee)\b", "writes or deletes files"),
            (r"\b(kill|killall|pkill)\b", "kills processes"),
            (r"^systemctl\s+(start|stop|restart|reload|enable|disable|mask|unmask|isolate|set-)", "changes service state"),
            (r"\b(apt|apt-get|yum|dnf|zypper|apk\s+add|pip|pip3|npm|gem|cargo\s+install)\b", "installs or removes packages"),
            (r"\b(curl|wget|nc|ncat|socat|ftp|scp|rsync)\b", "moves data off the box"),
            (r"\b(bash|sh|zsh|python|python3|perl|ruby|node|eval|exec)\b", "runs arbitrary code"),
            (r"\bsudo\b", "escalates privilege - ask for an account that already has the read access"),
            (r"\bsu\b\s", "switches user"),
            (r"\bcrontab\s+(-r\b|-e\b|[^-\s])", "edits or removes cron"),
            (r"\biptables\s+-[AIDFXZP]\b", "changes firewall rules"),
            (r"\bsysctl\s+-w\b", "writes a kernel parameter"),
            (r"\bmount\s+\S", "mounts a filesystem"),
            (r"\bumount\b", "unmounts a filesystem"),
            # read TOOLS with write SUBCOMMANDS - the allowlist lets the tool in, this keeps the verb out
            (r"^ip\s+(-\S+\s+)*(link|addr|address|route|neigh|neighbour|rule|netns|tunnel|maddr|mroute|xfrm|vrf|token)\s+(add|del|delete|set|change|replace|flush|append|prepend)\b", "changes network state"),
            (r"^bridge\s+\S+\s+(add|del|delete|set|append|flush)\b", "changes bridge state"),
            (r"^route\s+(add|del|delete|flush)\b", "changes the routing table"),
            (r"^arp\s+-[dsf]\b", "changes the ARP table"),
            (r"^ethtool\s+-[sSKGCLApPrRW]\b", "writes NIC settings"),
            (r"^iw\s+.*\b(set|add|del|connect|disconnect|reg\s+set)\b", "changes wireless state"),
            (r"^iwconfig\s+\S+\s+(essid|mode|channel|freq|key|txpower|rate|ap|enc)\b", "changes wireless state"),
            (r"^nmcli\s+\S+\s+(up|down|add|del|delete|modify|mod|edit|reload|set|clone)\b", "changes NetworkManager state"),
            (r"^resolvectl\s+(dns|domain|flush-caches|reset|revert|llmnr|mdns|dnssec|default-route)\b", "changes DNS state"),
            (r"^networkctl\s+(up|down|reload|reconfigure|renew|forcerenew|delete)\b", "changes link state"),
            (r"^conntrack\s+-[DFU]\b", "flushes or deletes conntrack entries"),
            (r"\bdmesg\s+(-[cC]\b|--clear|--read-clear)", "clears the kernel ring buffer - destroys evidence"),
            (r"\bjournalctl\s+--(vacuum|rotate|flush|sync|relinquish)", "rotates or deletes logs"),
            (r"^smartctl\s+.*-t\b", "starts a drive self-test"),
            (r"^docker\s+(run|exec|stop|start|rm|rmi|kill|restart|build|pull|push|create|update|compose|system)\b", "changes container state"),
            (r"^kubectl\s+(delete|apply|edit|patch|scale|create|drain|cordon|uncordon|exec|rollout)\b", "changes cluster state"),
            (r"^(pct|qm)\s+(start|stop|shutdown|destroy|set|create|clone|migrate|exec|reboot|suspend|resume|rollback|snapshot|unlock|delete|template|resize)\b", "changes a Proxmox guest"),
        ],
    },
    # ------------------------------------------------------------------- Windows
    "windows": {
        "class": "shell",
        "allow": [
            r"^Get-[A-Za-z]+\b", r"^Measure-[A-Za-z]+\b", r"^Test-(Connection|NetConnection|Path)\b",
            r"^(systeminfo|hostname|whoami|ver)\b",
            r"^ipconfig(\s+/all)?$", r"^netstat\s+-\S+$", r"^arp\s+-a$", r"^route\s+print$",
            r"^nslookup\b", r"^ping\s+-n\s*\d+\b", r"^tracert\b",
            r"^wmic\s+\S+\s+get\b", r"^query\s+(user|session|process)\b",
            r"^tasklist\b", r"^driverquery\b", r"^sc\s+query\b", r"^reg\s+query\b",
            r"^dir\b", r"^type\s+\S+$", r"^fsutil\s+volume\s+diskfree\b",
        ],
        "deny": [
            (r"^(Set|New|Remove|Stop|Start|Restart|Suspend|Resume|Clear|Reset|Install|Uninstall|Add|Disable|Enable|Rename|Move|Copy)-", "changes state"),
            (r"\b(shutdown|del|erase|rd|rmdir|md|mkdir|copy|move|xcopy|robocopy|takeown|icacls)\b", "writes, deletes or reboots"),
            (r"^reg\s+(add|delete|import)\b", "writes the registry"),
            (r"^sc\s+(config|start|stop|delete|create)\b", "changes a service"),
            (r"\bInvoke-(Expression|Command|WebRequest|RestMethod)\b", "runs arbitrary code or moves data"),
            (r"\bnet\s+(user|localgroup|share|stop|start)\b", "changes accounts, shares or services"),
        ],
    },
}

# Vendors that behave like an existing profile.
ALIASES = {
    "routeros": "mikrotik", "mt": "mikrotik",
    "ios": "cisco", "ios-xe": "cisco", "nx-os": "cisco", "nxos": "cisco", "catalyst": "cisco",
    "arubaos": "aruba", "aruba-cx": "aruba", "cx": "aruba", "instant": "aruba",
    "procurve": "hp", "hpe": "hp", "comware": "hp",
    "fortigate": "fortinet", "fortios": "fortinet",
    "junos": "juniper",
    "edgeos": "linux", "edgemax": "linux", "ubiquiti": "linux", "unifi": "linux",
    "ruckus": "cli-strict", "extreme": "cli-strict", "dell": "cli-strict", "tplink": "cli-strict",
    "synology": "linux", "dsm": "linux", "debian": "linux", "ubuntu": "linux",
    "proxmox": "linux", "pve": "linux", "alpine": "linux", "openwrt": "linux",
}

# Fallback for a CLI device we have no profile for: `show`/`display` and nothing else.
PROFILES["cli-strict"] = {
    "class": "cli",
    "allow": [r"^show\b", r"^display\b", r"^get\b", r"^print\b"],
    "deny": [(r"^(conf|set|add|delete|remove|no|write|copy|clear|reset|boot)\b", "changes config or state")],
}
PROFILES["unknown"] = PROFILES["cli-strict"]


def resolve_profile(vendor: str | None) -> tuple[str, dict]:
    key = (vendor or "unknown").strip().lower()
    key = ALIASES.get(key, key)
    if key not in PROFILES:
        key = "unknown"
    return key, PROFILES[key]


class Verdict:
    __slots__ = ("allowed", "reason", "profile")

    def __init__(self, allowed: bool, reason: str, profile: str):
        self.allowed = allowed
        self.reason = reason
        self.profile = profile

    def __repr__(self) -> str:
        return f"<Verdict {'ALLOW' if self.allowed else 'DENY'} [{self.profile}] {self.reason}>"


def check(command: str, vendor: str | None) -> Verdict:
    """Decide whether `command` is read-only on `vendor`. Deny wins, always."""
    name, prof = resolve_profile(vendor)
    cmd = command.strip()
    if not cmd:
        return Verdict(False, "empty command", name)
    if len(cmd) > 2000:
        return Verdict(False, "command is absurdly long - split it", name)

    meta = SHELL_META if prof["class"] == "shell" else CLI_META
    hit = meta.search(cmd)
    if hit:
        what = "shell metacharacter" if prof["class"] == "shell" else "command separator or redirection"
        return Verdict(False, f"contains {what} {hit.group(0)!r} - run one plain command at a time", name)

    # On CLI devices a single `|` is a display filter; still check both sides.
    segments = [s.strip() for s in cmd.split("|")] if prof["class"] == "cli" else [cmd]

    for pat, why in UNIVERSAL_DENY:
        if re.search(pat, cmd, re.IGNORECASE):
            return Verdict(False, f"{why} (matched /{pat}/)", name)
    for pat, why in prof["deny"]:
        if re.search(pat, cmd, re.IGNORECASE):
            return Verdict(False, f"{why} (matched /{pat}/)", name)

    head = segments[0]
    if not any(re.search(p, head, re.IGNORECASE) for p in prof["allow"]):
        return Verdict(False,
                       f"not on the {name} read-only allowlist - if this really is a read command, "
                       f"add it to PROFILES['{name}']['allow'] in netwalk_policy.py and say so in the report",
                       name)
    return Verdict(True, "read-only", name)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("usage: netwalk_policy.py <vendor> <command>", file=sys.stderr)
        sys.exit(64)
    v = check(sys.argv[2], sys.argv[1])
    print(f"{'ALLOW' if v.allowed else 'DENY '} [{v.profile}] {v.reason}")
    sys.exit(0 if v.allowed else 1)
