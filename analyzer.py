"""Core engine: vendor detection + LLM analysis for network device logs.

Python 3.10+, openai>=1.0 (OpenAI-compatible client pointed at vleee).
No log data is stored; each analyze() call is a single stateless request.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from dotenv import load_dotenv
from openai import OpenAI

# --- config ---------------------------------------------------------------

VLEEE_BASE_URL = "https://api.vleee.net/v1"
# ali/kimi-k3 and cb/kimi-k3 routes 503 on prompts >~200 tokens (verified via
# curl bisect 2026-10-23); deepseek-flash resolves to cb/deepseek-v4.1-flash
# and handles full-size analysis prompts fine (~13s for a 500-token prompt).
DEFAULT_MODEL = "deepseek-flash"
ENV_KEY = "HERMES_CUSTOM_API_VLEEE_NET_API_KEY"
# Hermes keeps its secrets here; also honors a local .env in the project dir.
HERMES_ENV = os.path.expandvars(r"%LOCALAPPDATA%\hermes\.env")

# kimi-k3 is a reasoning model: without a cap it can burn thousands of hidden
# reasoning tokens until the upstream gateway times out and returns 503.
MAX_OUTPUT_TOKENS = 4000  # reasoning models burn hidden tokens before answering
REQUEST_TIMEOUT_S = 120

MAX_LOG_CHARS = 12_000  # keep prompts under ~4k tokens; head+tail if longer

VENDOR_PATTERNS: list[tuple[str, list[str]]] = [
    ("Cisco IOS", [r"%LINK-\d-UPDOWN", r"%LINEPROTO-\d-UPDOWN", r"%SYS-\d-",
                   r"%SEC_LOGIN-\d-", r"%CDP-\d-", r"%SPANTREE-\d-",
                   r"%[A-Z_]+-\d-[A-Z_]+:",  # generic Cisco mnemonic: %FACILITY-SEV-MNEMONIC:
                   r"GigabitEthernet\d|FastEthernet\d", r"cisco", r"IOS"]),
    ("Cisco NX-OS", [r"ETHPORT-", r"nxos", r"Nexus"]),
    ("FortiGate", [r"fortigate", r"logver=\d+", r"srcip=.*dstip=", r"FortiOS",
                   r"subtype=(forward|utm|event)"]),
    ("Juniper Junos", [r"rpd\[", r"bgp_peer", r"juniper", r"ge-\d+/\d+/\d+"]),
    ("Palo Alto", [r"pan.os", r"Palo Alto", r"THREAT,|TRAFFIC,"]),
    ("MikroTik RouterOS", [r"routeros", r"mikrotik",
                           r"^\w+,\w+ \S+",          # topic,severity message
                           r"\bether\d+.*link (up|down)",
                           r"login failure for user",
                           r"dhcp-client on \S+ got"]),
    ("Huawei VRP", [r"%%01", r"\bhuawei\b", r"\bVRP\b", r"LINK_STATE\(l\)",
                    r"IFNET/\d/"]),
    ("pfSense/OPNsense", [r"filterlog", r"pfsense", r"opnsense", r"\bpf: \["]),
    ("OpenWrt / LuCI", [r"\b(?:daemon|kern|auth|user)\.(?:info|warn|err|notice|debug|crit)\b",
                        r"\bnetifd\b", r"dnsmasq(?:-dhcp)?\[\d+\]",
                        r"\bhostapd\b", r"\bbr-lan\b", r"\bubusd?\b",
                        r"/cgi-bin/luci", r"\bopenwrt\b|\bluci\b",
                        r"\bwlan\d*-?\d*: STA [0-9a-f:]{17}"]),
    ("Linux syslog", [r"\w+ \d+ \d+:\d+:\d+ \S+ \w+\[\d+\]:",
                      r"systemd|kernel|sshd\["]),
]

LANG_NAMES = {"id": "Bahasa Indonesia", "en": "English", "de": "Deutsch"}

SYSTEM_PROMPT = """You are a senior network engineer (CCNP-level) writing for a 1st-level \
support agent. Analyze the pasted device log and respond in {language} with EXACTLY \
these five sections, in this order, using these markdown headers:

## Severity
One line: CRITICAL / WARNING / INFO plus a 3-6 word label.

## Summary
2-3 sentences: what happened, on which device/interface, and whether it is ongoing.

## Possible Causes
Ranked numbered list (most likely first), 2-4 items, each with a one-line reason.

## Next Commands
Vendor-correct CLI commands ({vendor}) as fenced code blocks, one command per line, \
with a one-line comment above each explaining what to look for in the output.

## Recommendation
Concrete next physical or config action. If escalation to L2 is warranted, say what \
evidence to attach to the ticket.

Rules: be specific to the actual log content (interface names, timestamps, IPs). \
Never invent log lines. If the log is too vague for a section, say so in one line."""


# --- data types -------------------------------------------------------------

@dataclass
class DetectionResult:
    vendor: str
    confidence_hits: int
    event_count: int
    hints: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    vendor: DetectionResult
    analysis: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    truncated: bool


# --- detection ----------------------------------------------------------------

def detect_vendor(log_text: str) -> DetectionResult:
    """Score regex hits per vendor; the highest score wins. Defaults to generic syslog."""
    best_vendor, best_hits, best_hints = "Generic syslog", 0, []
    for vendor, patterns in VENDOR_PATTERNS:
        hints = [p for p in patterns if re.search(p, log_text, re.IGNORECASE)]
        if len(hints) > best_hits:
            best_vendor, best_hits, best_hints = vendor, len(hints), hints
    events = sum(1 for line in log_text.splitlines() if line.strip())
    return DetectionResult(best_vendor, best_hits, events, best_hints)


def _truncate(log_text: str) -> tuple[str, bool]:
    """Head+tail truncation keeps the first burst of errors AND the latest state."""
    if len(log_text) <= MAX_LOG_CHARS:
        return log_text, False
    half = MAX_LOG_CHARS // 2
    return log_text[:half] + "\n[... middle truncated ...]\n" + log_text[-half:], True


# --- LLM client -----------------------------------------------------------------

def _load_api_key(explicit_key: str | None) -> str:
    if explicit_key:
        return explicit_key
    load_dotenv()  # project-local .env wins if present
    key = os.environ.get(ENV_KEY)
    if not key and os.path.exists(HERMES_ENV):
        load_dotenv(HERMES_ENV)
        key = os.environ.get(ENV_KEY)
    if not key:
        raise RuntimeError(
            f"API key not found. Set {ENV_KEY} in a .env file or the environment.")
    return key


def make_client(api_key: str | None = None) -> OpenAI:
    return OpenAI(base_url=VLEEE_BASE_URL, api_key=_load_api_key(api_key),
                  timeout=REQUEST_TIMEOUT_S, max_retries=1)


def analyze(log_text: str, lang: str = "id", model: str = DEFAULT_MODEL,
            client: OpenAI | None = None) -> AnalysisResult:
    """One-shot stateless analysis. Raises RuntimeError/openai errors on failure."""
    if not log_text.strip():
        raise ValueError("log_text is empty")

    detection = detect_vendor(log_text)
    trimmed, truncated = _truncate(log_text)
    language = LANG_NAMES.get(lang, LANG_NAMES["en"])
    system = SYSTEM_PROMPT.format(language=language, vendor=detection.vendor)

    client = client or make_client()
    resp = client.chat.completions.create(
        model=model,
        temperature=0.2,  # deterministic: same log -> same diagnosis
        max_tokens=MAX_OUTPUT_TOKENS,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": f"Device log ({detection.vendor}):\n\n{trimmed}"},
        ],
    )
    usage = resp.usage
    return AnalysisResult(
        vendor=detection,
        analysis=resp.choices[0].message.content or "(empty response)",
        model=model,
        prompt_tokens=usage.prompt_tokens if usage else 0,
        completion_tokens=usage.completion_tokens if usage else 0,
        truncated=truncated,
    )
