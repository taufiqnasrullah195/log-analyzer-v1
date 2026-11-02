"""Turn a classified issue into a paste-ready CLI remediation script.

Every plan is split into DIAGNOSE and FIX because those carry different risk:
diagnose commands are read-only and always safe, fix commands change device
state. `auto_safe` marks the plans where the fix block is reversible and
idempotent (a `no shutdown` / `duplex auto` on a physical port), so an
unattended poller can apply those and must escalate the rest to a human.

Vendor note: commands below are Cisco IOS. The library is keyed by issue id,
so a Junos/FortiOS variant is a second dict, not a rewrite.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from issue_rules import DetectedIssue


@dataclass(frozen=True)
class FixPlan:
    title: str
    auto_safe: bool
    diagnose: tuple[str, ...] = ()
    fix: tuple[str, ...] = ()
    escalate: str = ""
    entity_key: str = ""      # which detected entity substitutes into the plan


# Issue id -> remediation. `{iface}` / `{ip}` / `{user}` come from the scanner.
FIX_LIBRARY: dict[str, FixPlan] = {
    "interface_flap": FixPlan(
        title="Stabilise flapping interface",
        auto_safe=True,
        entity_key="iface",
        diagnose=(
            "show interfaces {iface}",
            "show interfaces {iface} counters errors",
            "show interfaces status",
            "show run interface {iface}",
        ),
        fix=(
            "conf t",
            "interface {iface}",
            " no shutdown",
            " duplex auto",
            " speed auto",
            " spanning-tree portfast",
            " exit",
            "end",
            "wr",
        ),
        escalate="If flapping continues after the port is re-enabled: replace the "
                 "patch cord, move to a known-good port, attach `show interfaces "
                 "{iface} counters errors` (CRC/FCS) to the ticket.",
    ),
    "admin_shutdown": FixPlan(
        title="Interface administratively shut down",
        auto_safe=False,          # it may be down ON PURPOSE
        entity_key="iface",
        diagnose=(
            "show interfaces {iface}",
            "show run interface {iface}",
            "show users",
        ),
        fix=(
            "conf t",
            "interface {iface}",
            " no shutdown",
            " exit",
            "end",
        ),
        escalate="Confirm this shutdown was intended. The command is trivially "
                 "reversible, but re-enabling a port someone deliberately disabled "
                 "can restore a security or maintenance condition you do not want — "
                 "an out-of-change-window admin shutdown is worth escalating on its own.",
    ),
    # ── OpenWrt / LuCI ─────────────────────────────────────────────────
    "wifi_deauth": FixPlan(
        title="WiFi client deauthentication burst (OpenWrt)",
        auto_safe=False,
        diagnose=("logread | grep -i hostapd | tail -50",
                  "iw dev wlan0 station dump",
                  "cat /etc/config/wireless",
                  "iwinfo wlan0 info"),
        fix=(),
        escalate="A deauth burst is almost never fixed by changing the router. "
                 "Compare the STA MAC in the log with `iw dev wlan0 station "
                 "dump`: one MAC repeating means that client (stale key, "
                 "failing radio); many MACs at once means RF interference or "
                 "channel overlap. Check `iwinfo wlan0 info` for the channel "
                 "and noise floor before touching /etc/config/wireless.",
        entity_key="mac",
    ),
    "wifi_auth_fail": FixPlan(
        title="WiFi authentication failures (OpenWrt)",
        auto_safe=False,
        diagnose=("logread | grep -i 'hostapd.*authentication' | tail -50",
                  "logread | grep -i 'STA' | awk '{print $NF}' | sort | uniq -c | sort -rn | head"),
        fix=(),
        escalate="If one MAC dominates the failures it is a client with a "
                 "stale PSK, or a brute-force attempt — rotate the WPA2 key "
                 "and optionally add a MAC filter. If the failures are spread "
                 "across MACs, suspect the PSK itself or an enterprise "
                 "/ RADIUS config error. Never treat this as a router fault "
                 "without checking the MAC distribution first.",
        entity_key="mac",
    ),
    "wan_link_down": FixPlan(
        title="WAN link down (netifd)",
        auto_safe=False,
        diagnose=("logread | grep -i netifd | tail -40",
                  "ifstatus wan",
                  "ip -br link show",
                  "cat /etc/config/network"),
        fix=("/etc/init.d/network restart",),
        escalate="Carrier loss on the WAN port is an upstream problem: check "
                 "the modem, the cable and the ISP before restarting anything. "
                 "`ifstatus wan` distinguishes 'no carrier' from 'no lease'. "
                 "The restart drops every client, so confirm the modem first.",
        entity_key="iface",
    ),
    "dnsmasq_error": FixPlan(
        title="dnsmasq DNS/DHCP error (OpenWrt)",
        auto_safe=False,
        diagnose=("logread | grep -i dnsmasq | tail -40",
                  "cat /etc/config/dhcp",
                  "nslookup openwrt.org 127.0.0.1",
                  "ubus call network.interface.wan status"),
        fix=("/etc/init.d/dnsmasq restart",),
        escalate="'no upstream servers configured' or 'Network unreachable' is "
                 "a symptom of the WAN being down, not a dnsmasq fault — fix "
                 "wan_link_down first and re-check. Only restart dnsmasq when "
                 "the log shows it failing while the WAN is healthy.",
        entity_key="",
    ),
    "mikrotik_link": FixPlan(
        title="Interface link flapping (RouterOS)",
        auto_safe=False,     # confirm the port is meant to be up before enabling
        entity_key="iface",
        diagnose=(
            "/interface print detail where name={iface}",
            "/interface ethernet monitor {iface} once",
            "/log print where topics~\"interface\"",
        ),
        fix=(
            "/interface enable {iface}",
        ),
        escalate="RouterOS link flaps are nearly always cable or auto-negotiation. "
                 "Check `/interface ethernet monitor {iface} once` for the "
                 "negotiated rate and SFP diagnostics before enabling anything.",
    ),
    "line_proto_down": FixPlan(
        title="Restore line protocol on interface",
        auto_safe=True,
        entity_key="iface",
        diagnose=(
            "show interfaces {iface}",
            "show ip interface brief",
        ),
        fix=(
            "conf t",
            "interface {iface}",
            " no shutdown",
            " exit",
            "end",
            "wr",
        ),
    ),
    "auth_fail": FixPlan(
        title="Block repeated authentication failures",
        auto_safe=False,
        entity_key="ip",
        diagnose=(
            "show login failures",
            "show users",
            "show ip ssh",
        ),
        fix=(
            "conf t",
            "! throttle brute force at the VTY",
            "login block-for 120 attempts 3 within 60",
            "line vty 0 4",
            " transport input ssh",
            " exec-timeout 5 0",
            " exit",
            "ip ssh version 2",
            "access-list 90 deny   {ip}",
            "access-list 90 permit any",
            "line vty 0 4",
            " access-class 90 in",
            " exit",
            "end",
            "wr",
        ),
        escalate="Confirm {ip} is not a legitimate admin station before denying it. "
                 "Rotate the local admin password and review `show logging | include "
                 "SEC_LOGIN`.",
    ),
    "stp_churn": FixPlan(
        title="Stop spanning-tree topology churn",
        auto_safe=False,
        diagnose=(
            "show spanning-tree",
            "show spanning-tree detail",
            "show spanning-tree interface {iface}",
        ),
        fix=(
            "conf t",
            "! enable portfast on known host ports to stop TC storms",
            "interface range {iface}",
            " spanning-tree portfast",
            " spanning-tree bpduguard enable",
            " exit",
            "end",
            "wr",
        ),
        escalate="Apply portfast ONLY to ports facing hosts. On uplinks it can loop "
                 "the network — confirm the port role first.",
    ),
    "ospf_adjacency": FixPlan(
        title="Stabilise OSPF adjacency",
        auto_safe=False,
        entity_key="ip",
        diagnose=(
            "show ip ospf neighbor",
            "show ip ospf interface",
            "show ip route ospf",
        ),
        fix=(
            "conf t",
            "router ospf 1",
            " passive-interface default",
            " no passive-interface {iface}",
            " exit",
            "end",
            "wr",
        ),
        escalate="Adjacency flapping is usually an MTU or hello/dead-interval mismatch "
                 "on the link, not an OSPF config error. Compare `show ip ospf interface` "
                 "on both ends before changing timers.",
    ),
    "duplicate_ip": FixPlan(
        title="Resolve duplicate IP address",
        auto_safe=False,
        entity_key="ip",
        diagnose=(
            "show arp | include {ip}",
            "show ip dhcp snooping binding",
            "show mac address-table | include {ip}",
        ),
        fix=(
            "! find the offending host first — do NOT clear the ARP yet",
            "show ip arp {ip}",
        ),
        escalate="Locate the host holding {ip} (ARP/MAC table) and either move it to "
                 "DHCP or reassign the static address. Clearing ARP alone hides the "
                 "conflict without fixing it.",
    ),
    "memory_exhaustion": FixPlan(
        title="Memory exhaustion — evidence first, do NOT reload",
        auto_safe=False,
        diagnose=(
            "show memory statistics",
            "show processes memory sorted",
            "show processes cpu sorted",
            "show version",
        ),
        fix=(),   # deliberately empty: no safe automatic remedy
        escalate="CRITICAL. Capture `show memory statistics`, `show processes memory "
                 "sorted` and a full `show logging` to TFTP BEFORE anything reloads — "
                 "the evidence is lost on reboot. Prepare console access: if the "
                 "Processor pool is gone, SSH/VTY sessions will fail to establish. "
                 "Escalate to L2 with `show tech-support` if memory allows.",
    ),
    "cpu_hog": FixPlan(
        title="CPU hog — identify the spinning process",
        auto_safe=False,
        diagnose=(
            "show processes cpu sorted",
            "show processes cpu history",
            "show logging | include CPUHOG",
        ),
        fix=(),
        escalate="CRITICAL. Capture `show processes cpu sorted` twice ~30s apart to "
                 "see what is spinning. Common causes: routing loop, broadcast storm, "
                 "or a stuck process. Escalate to L2 with both captures plus "
                 "`show interfaces | include input rate|output rate`.",
    ),
    "device_reload": FixPlan(
        title="Unexpected reload — preserve crash evidence",
        auto_safe=False,
        diagnose=(
            "show version",
            "show logging | include RELOAD|ROM|FREEFREE",
            "dir flash:",
        ),
        fix=(),
        escalate="CRITICAL. Grab the crashinfo/core from flash and the reload reason "
                 "BEFORE the ring buffer overwrites it. Note the uptime in "
                 "`show version` — a short uptime confirms a recent reload.",
    ),
    "power_fault": FixPlan(
        title="Power / PoE fault",
        auto_safe=False,
        diagnose=(
            "show power inline",
            "show environment all",
            "show logging | include POWER|ILPOWER|ENVMON",
        ),
        fix=(),
        escalate="CRITICAL. Check the physical PSU and PoE budget on the rack. "
                 "Attach `show environment all` to the ticket.",
    ),
    "bgp_peer_down": FixPlan(
        title="BGP peer down",
        auto_safe=False,
        entity_key="ip",
        diagnose=(
            "show ip bgp summary",
            "show ip bgp neighbors {ip}",
            "show logging | include BGP",
        ),
        fix=(
            "conf t",
            "router bgp",
            "! only after confirming the peer is up on the far end",
            " neighbor {ip} shutdown",
            " no neighbor {ip} shutdown",
            " exit",
            "end",
        ),
        escalate="Check the hold-timer expiry reason in `show ip bgp neighbors {ip}` "
                 "— 'Hold timer expired' points upstream, not at this device.",
    ),
    "dhcp_issue": FixPlan(
        title="DHCP pool / lease problem",
        auto_safe=False,
        diagnose=(
            "show ip dhcp pool",
            "show ip dhcp binding",
            "show ip dhcp conflict",
        ),
        fix=(),
        escalate="Check pool utilisation in `show ip dhcp pool`. If the pool is full, "
                 "either enlarge the subnet or shorten the lease time.",
    ),
    "interface_err_disable_critical": FixPlan(
        title="Clear err-disabled port",
        auto_safe=False,
        entity_key="iface",
        diagnose=(
            "show interfaces status err-disabled",
            "show errdisable recovery",
        ),
        fix=(
            "conf t",
            "interface {iface}",
            " shutdown",
            " no shutdown",
            " exit",
            "end",
        ),
        escalate="Fix the ROOT cause before recovering: err-disable is almost always "
                 "BPDU guard, port-security, or a duplex mismatch. Recovering without "
                 "fixing it just re-trips the port.",
    ),
    "config_change": FixPlan(
        title="Configuration change (informational)",
        auto_safe=True,
        diagnose=("show run | last 20",),
        fix=(),
    ),
    "logging_host": FixPlan(
        title="Logging host start/stop (informational)",
        auto_safe=True,
        diagnose=("show logging",),
        fix=(),
    ),
}


_IFACE_RE = re.compile(
    r"\b(?:GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet|Port-channel"
    r"|Gi|Fa|Et|Te)\d[\d/.\-]*", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _entity_map(issue: DetectedIssue) -> dict[str, str]:
    """Collect every fill-in value we can find.

    The rule's own extraction is authoritative for its key, but the matched
    lines often name the *other* kind of entity too — an OSPF rule extracts the
    neighbour IP while the same line also names the interface. Reading both
    sources is what stops a raw ``{iface}`` reaching the printed script.
    """
    values: dict[str, str] = {}
    text = "\n".join(issue.samples)

    if issue.rule.extract and issue.entities:
        head = issue.entities[0]
        values["ip" if _IP_RE.fullmatch(head) else "iface"] = head

    if "iface" not in values and (m := _IFACE_RE.search(text)):
        values["iface"] = m.group(0)
    if "ip" not in values and (m := _IP_RE.search(text)):
        values["ip"] = m.group(0)
    return values


# Only these are real placeholders. A fix command legitimately contains regex
# quantifiers like `{2}`, and a blanket substitution silently rewrote
# `grep -oE '([0-9a-f]{2}:){5}'` into `([0-9a-f]<2>:)<5>` — a command that is
# broken but still reads as plausible, which is the worst kind of wrong.
PLACEHOLDER_KEYS = frozenset({
    "iface", "ip", "mac", "host", "device", "user", "port", "vlan", "ssid",
    "pool", "neighbor",
})


def _fill(text: str, values: dict[str, str]) -> str:
    """Resolve ``{key}`` for known keys only.

    An unmapped *known* key becomes ``<key>`` so it is obvious to a human
    reader rather than a silent empty string. Anything else in braces is left
    exactly as written — it is regex syntax, not a placeholder.
    """
    def sub(m: re.Match) -> str:
        key = m.group(1)
        if key not in PLACEHOLDER_KEYS:
            return m.group(0)
        return values.get(key, f"<{key}>")
    return re.sub(r"\{(\w+)\}", sub, text)


def _render_block(issue: DetectedIssue, plan: FixPlan | None) -> str:
    sev = issue.rule.severity
    out = [f"# {'=' * 62}", f"# [{sev}] {issue.label}  ({issue.count} hit)"]
    if plan is None:
        out.append("# no remediation mapped for this issue id")
        out.append("# " + "=" * 60)
        return "\n".join(out)

    out.append(f"# auto-apply: {'YES' if plan.auto_safe else 'NO — needs a human'}")
    out.append(f"# {'=' * 62}")

    values = _entity_map(issue)

    if plan.diagnose:
        out.append("")
        out.append("# --- diagnose (read-only, safe) ---")
        out.extend(_fill(c, values) for c in plan.diagnose)

    fix = tuple(_fill(c, values) for c in plan.fix)
    if fix:
        out.append("")
        out.append("# --- fix (changes device state) ---")
        out.extend(fix)

    if plan.escalate:
        out.append("")
        esc = _fill(plan.escalate, values)
        out.append("# --- notes ---")
        for line in esc.split(". "):
            if line.strip():
                out.append(f"# {line.strip().rstrip('.')}.")

    if issue.samples:
        out.append("")
        out.append("# --- evidence (first matching lines) ---")
        out.extend(f"# {s}" for s in issue.samples[:3])

    return "\n".join(out)


# Some faults are the same on every vendor, but the commands that inspect
# them are not. An OpenWrt box has no `show` CLI at all, so shipping the
# Cisco-oriented plan for it produced advice the operator could not run.
VENDOR_OVERRIDES: dict[str, dict[str, FixPlan]] = {
    "OpenWrt / LuCI": {
        "auth_fail": FixPlan(
            title="Repeated authentication failure (OpenWrt)",
            auto_safe=False,
            diagnose=("logread | grep -iE 'auth|login|dropbear' | tail -50",
                      "logread | grep -i auth | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | sort | uniq -c | sort -rn | head",
                      "uci show dropbear",
                      "netstat -lntp 2>/dev/null | grep -E ':22|:23|:80'"),
            fix=(),
            escalate="OpenWrt ships dropbear as its SSH daemon. A burst from one "
                     "source address is a scan or brute force — restrict WAN-side "
                     "SSH in LuCI (System then Administration) instead of editing "
                     "dropbear by hand. If no source address appears in the log, "
                     "the attempts came from the LAN side, so the source is a "
                     "device already on your own network.",
            entity_key="ip",
        ),
        "interface_flap": FixPlan(
            title="Interface flapping (OpenWrt)",
            auto_safe=False,
            diagnose=("logread | grep -i netifd | tail -60",
                      "ip -br link show",
                      "ethtool eth0 2>/dev/null || ethtool wan 2>/dev/null",
                      "cat /proc/net/dev"),
            fix=(),
            escalate="Read the negotiated speed and the error counters before "
                     "changing any configuration — a flapping WAN port is a "
                     "cable, a failing power supply or an ageing modem far more "
                     "often than a software fault. `ip -br link show` gives the "
                     "carrier state; `/proc/net/dev` gives per-interface drops.",
            entity_key="iface",
        ),
        "line_proto_down": FixPlan(
            title="Line protocol down (OpenWrt)",
            auto_safe=False,
            diagnose=("ip -br link show",
                      "ifstatus wan",
                      "logread | grep -iE 'netifd|wan' | tail -40"),
            fix=(),
            escalate="A down line protocol means the interface has no carrier or "
                     "no lease. `ifstatus wan` separates the two: no carrier is a "
                     "cable or modem fault, carrier-but-no-lease is an ISP or "
                     "PPPoE credential problem.",
            entity_key="iface",
        ),
        "dhcp_issue": FixPlan(
            title="DHCP pool / lease problem (OpenWrt)",
            auto_safe=False,
            diagnose=("logread | grep -i dnsmasq-dhcp | tail -50",
                      "cat /etc/config/dhcp",
                      "ubus call dhcp method dump 2>/dev/null | head -40"),
            fix=(),
            escalate="dnsmasq serves DHCP on OpenWrt. Check the pool range in "
                     "`/etc/config/dhcp` against the active leases before "
                     "widening it — a 'no address available' line usually means "
                     "the pool is too small for the number of client devices, "
                     "not that dnsmasq is broken.",
            entity_key="",
        ),
    },
}


def build_script(issues: list[DetectedIssue], vendor: str = "Cisco IOS",
                 device: str = "") -> str:
    """Render the full paste-ready script for a classified issue set."""
    from issue_rules import worst_severity

    sev = worst_severity(issues)
    header = [
        "#" + "=" * 64,
        "#  LogAnalyzer V1 — Auto Fix Script",
        "#" + "=" * 64,
        f"#  device    : {device or '(unknown)'}",
        f"#  vendor    : {vendor}",
        f"#  severity  : {sev}",
        f"#  issues    : {len(issues)}",
        "#" + "=" * 64,
        "",
        "# Review every block before pasting. Blocks marked",
        "# 'auto-apply: NO' are diagnostics plus guidance only — they are",
        "# intentionally NOT a blind fix.",
        "",
    ]

    if not issues:
        header.append("# No known issue patterns matched. Nothing to remediate.")
        return "\n".join(header)

    if vendor in VENDOR_OVERRIDES:
        header += [
            f"# NOTE: {vendor} has no Cisco-style CLI. The commands below are",
            "# shell (ash/busybox) — run them over SSH if the device exposes it.",
            "# A consumer router that ships with SSH closed has no shell path at",
            "# all: the equivalent actions live in the web UI, not in this file.",
            "",
        ]

    overrides = VENDOR_OVERRIDES.get(vendor, {})
    blocks = []
    for issue in issues:
        plan = overrides.get(issue.rule.id) or FIX_LIBRARY.get(issue.rule.id)
        blocks.append(_render_block(issue, plan))

    return "\n".join(header) + "\n\n".join(blocks) + "\n"


def auto_applicable(issues: list[DetectedIssue]) -> list[DetectedIssue]:
    """Issues whose fix block is safe to apply unattended."""
    return [i for i in issues
            if (p := FIX_LIBRARY.get(i.rule.id)) is not None and p.auto_safe and p.fix]