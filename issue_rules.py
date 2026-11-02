"""Deterministic issue classification for network device logs.

Design: this runs BEFORE the LLM. Pattern matching decides WHAT is wrong —
fast, free, and repeatable — then the LLM explains WHY and what to do next.
Classification stays deterministic on purpose: the same log must always
yield the same issue set, because the auto-fix generator keys off issue ids.

Adding a new issue type is one entry in RULES. No LLM call, no test rewrite.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITY_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}


@dataclass(frozen=True)
class IssueRule:
    id: str
    name: str
    severity: str
    pattern: str
    min_count: int = 1
    extract: str = ""      # regex whose capture groups name the affected entity
    note: str = ""


@dataclass
class DetectedIssue:
    rule: IssueRule
    count: int
    samples: list[str] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if not self.entities:
            return self.rule.name
        return f"{self.rule.name} ({', '.join(self.entities[:3])})"


# ── rule table ──────────────────────────────────────────────────────────────
# Order does not matter; scan() sorts by severity then hit count.
# min_count > 1 means "one occurrence is normal, N is the signal" — e.g. a
# single LINK-3-UPDOWN is a routine cable reseat, three is a flapping port.

RULES: list[IssueRule] = [
    # ---- CRITICAL ---------------------------------------------------------
    IssueRule("memory_exhaustion", "Memory allocation failure", "CRITICAL",
              r"%SYS-2-MALLOCFAIL",
              note="routine allocation already failing -> pool near exhaustion"),
    IssueRule("cpu_hog", "CPU hog / spinning process", "CRITICAL",
              r"%SYS-3-CPUHOG"),
    IssueRule("device_reload", "Unexpected reload or crash", "CRITICAL",
              r"%SYS-5-RELOAD|System returned to ROM|%SYS-2-\w*FREEFREE"),
    IssueRule("power_fault", "Power or PoE fault", "CRITICAL",
              r"%PLATFORM-2-POWER|%ILPOWER-3-|%ENVMON-2-"),
    IssueRule("bgp_peer_down", "BGP peer down", "CRITICAL",
              r"BGP_PEER_DOWN|bgp_peer_down", min_count=2,
              extract=r"peer\s+(\d{1,3}(?:\.\d{1,3}){3})"),
    IssueRule("interface_err_disable_critical", "Interface err-disabled", "CRITICAL",
              r"%PM-4-ERR_DISABLE|err-disable",
              extract=r"\(([A-Za-z][A-Za-z0-9/.\-]+)\)"),

    # ---- WARNING ----------------------------------------------------------
    IssueRule("interface_flap", "Interface flapping", "WARNING",
              r"%LINK-[35]-(?:UPDOWN|CHANGED)|%%01IFNET/\d+/LINK_STATE", min_count=3,
              extract=r"Interface ([A-Za-z][A-Za-z0-9/.\-]+)",
              note="matches LINK-3 and LINK-5: real IOS uses LINK-3 for a physical "
                   "flap and LINK-5 for admin shutdown, but Packet Tracer emits "
                   "LINK-5-CHANGED for BOTH sides of a shutdown/no-shutdown"),
    IssueRule("admin_shutdown", "Interface administratively shut down", "WARNING",
              r"changed state to administratively down",
              extract=r"Interface ([A-Za-z][A-Za-z0-9/.\-]+)",
              note="intentional admin action — confirm against the change ticket "
                   "before treating an unattended shutdown as a fault"),
    IssueRule("mikrotik_link", "Interface link change (RouterOS)", "WARNING",
              r"interface,(?:info|warning|error)\s+\S+\s+link (?:up|down)", min_count=3,
              extract=r"interface,\w+\s+(\S+)\s+link",
              note="RouterOS names the interface inside a topic,severity prefix "
                   "instead of a Cisco-style %LINK mnemonic"),
    IssueRule("line_proto_down", "Line protocol down", "WARNING",
              r"%LINEPROTO-5-UPDOWN",
              extract=r"Interface ([A-Za-z][A-Za-z0-9/.\-]+)"),
    IssueRule("auth_fail", "Repeated auth failure (possible brute force)", "WARNING",
              r"%SEC_LOGIN-4-LOGIN_FAILED|%LOGIN-3-|Authentication failure"
              r"|login failure for user|LOGIN_FAIL|authentication failed",
              min_count=3,
              extract=r"\[Source:\s*(\d{1,3}(?:\.\d{1,3}){3})\]|from\s+(\d{1,3}(?:\.\d{1,3}){3})"),
    IssueRule("duplicate_ip", "Duplicate IP address", "WARNING",
              r"%IP-4-DUPADDR",
              extract=r"(\d{1,3}(?:\.\d{1,3}){3})"),
    IssueRule("stp_churn", "Spanning-tree topology churn", "WARNING",
              r"%SPANTREE-\d-", min_count=3),
    IssueRule("ospf_adjacency", "OSPF adjacency change", "WARNING",
              r"%OSPF-5-ADJCHG",
              extract=r"Nbr\s+(\d{1,3}(?:\.\d{1,3}){3})"),
    IssueRule("dhcp_issue", "DHCP pool / lease problem", "WARNING",
              r"DHCP.*(?:no address|exhaust|pool|conflict)"),

    # ---- INFO -------------------------------------------------------------
    IssueRule("config_change", "Configuration change", "INFO",
              r"%SYS-5-CONFIG_I"),
    IssueRule("logging_host", "Logging host start/stop", "INFO",
              r"%SYS-6-LOGGINGHOST_STARTSTOP"),

    # ---- OpenWrt / LuCI (MERCUSYS, TP-Link, GL.iNet) ----------------------
    # These daemons log `facility.level daemon[pid]: message`, with no Cisco
    # mnemonic, so none of the rules above can see them.
    IssueRule("wifi_deauth", "WiFi client deauthentication burst", "WARNING",
              r"hostapd.*(?:deauthenticat|disassociat)",
              min_count=3,
              extract=r"STA ([0-9a-fA-F:]{17})",
              note="hostapd logs one line per deauth; a burst is roaming, RF "
                   "interference, or a client with a stale key — usually not a "
                   "router fault"),
    IssueRule("wifi_auth_fail", "WiFi authentication failure", "WARNING",
              r"hostapd.*(?:authentication (?:failed|timed out)|invalid "
              r"(?:password|PSK)|authentication reply)",
              min_count=3,
              extract=r"STA ([0-9a-fA-F:]{17})",
              note="counted on repetition: a single wrong PSK is a typo, a "
                   "sustained stream from one MAC is a brute-force attempt"),
    IssueRule("wan_link_down", "WAN / interface link down (netifd)", "WARNING",
              r"netifd:.*link is down",
              extract=r"'([^']+)'\s+link is down",
              note="netifd reports the physical carrier; a WAN interface going "
                   "down is an ISP/modem fault, not a router config fault"),
    IssueRule("dnsmasq_error", "dnsmasq DNS/DHCP error", "WARNING",
              r"dnsmasq(?:-dhcp)?\[\d+\]:.*(?:failed|unreachable|refused|"
              r"no upstream|cannot|error)",
              note="dnsmasq serves both DNS and DHCP on OpenWrt; "
                   "'no upstream servers configured' means the WAN is down, "
                   "not that dnsmasq is broken"),
]


# ── scanning ────────────────────────────────────────────────────────────────

def scan(log_text: str) -> list[DetectedIssue]:
    """Return every rule that fired, sorted most-severe / most-frequent first."""
    lines = [ln for ln in log_text.splitlines() if ln.strip()]
    found: list[DetectedIssue] = []

    for rule in RULES:
        rx = re.compile(rule.pattern, re.IGNORECASE)
        hits = [ln for ln in lines if rx.search(ln)]
        if len(hits) < rule.min_count:
            continue

        entities: list[str] = []
        if rule.extract:
            erx = re.compile(rule.extract, re.IGNORECASE)
            for ln in hits:
                for m in erx.finditer(ln):
                    for g in m.groups():
                        if g and g not in entities:
                            entities.append(g)

        found.append(DetectedIssue(rule, len(hits), hits[:5], entities[:5]))

    found.sort(key=lambda i: (SEVERITY_ORDER.get(i.rule.severity, 9), -i.count))
    return found


def worst_severity(issues: list[DetectedIssue]) -> str:
    if not issues:
        return "INFO"
    return min(issues, key=lambda i: SEVERITY_ORDER.get(i.rule.severity, 9)).rule.severity


def summarize(issues: list[DetectedIssue]) -> str:
    if not issues:
        return "No known issue patterns matched."
    lines = []
    for i in issues:
        lines.append(f"  [{i.rule.severity:<8}] {i.label} — {i.count} hit(s)")
        if i.rule.note:
            lines.append(f"             {i.rule.note}")
    return "\n".join(lines)