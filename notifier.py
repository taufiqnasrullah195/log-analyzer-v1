"""notifier.py — Telegram alerting for LogAnalyzer V1.

Credentials come from the environment, never from a file in the repo:

    TELEGRAM_BOT_TOKEN   token from @BotFather
    TELEGRAM_CHAT_ID     destination chat id (user, group, or channel)

If either is missing, notify() runs in DRY-RUN: it prints the message it
*would* have sent and returns False. That keeps local runs, CI and cron quiet
by default and means nothing silently half-sends.

    python notifier.py --test
    python notifier.py --text "hello from LogAnalyzer"
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

API = "https://api.telegram.org/bot{token}/sendMessage"
TIMEOUT_S = 15
MAX_LEN = 4000          # Telegram hard-caps at 4096; leave room for the footer


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def configured() -> bool:
    return bool(_env("TELEGRAM_BOT_TOKEN") and _env("TELEGRAM_CHAT_ID"))


def notify(text: str, *, dry_run: bool | None = None) -> bool:
    """Send `text` to the configured chat. Returns True only on a real 200.

    A failed send returns False rather than raising: an alerting side-channel
    must never take down the analysis that produced the alert.
    """
    token, chat = _env("TELEGRAM_BOT_TOKEN"), _env("TELEGRAM_CHAT_ID")
    if dry_run is None:
        dry_run = not (token and chat)

    body = text if len(text) <= MAX_LEN else text[:MAX_LEN] + "\n… (truncated)"

    if dry_run:
        print("[notify] DRY-RUN — TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set")
        print("[notify] would send:")
        for line in body.splitlines():
            print(f"         | {line}")
        return False

    payload = urllib.parse.urlencode({
        "chat_id": chat,
        "text": body,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }).encode()

    try:
        req = urllib.request.Request(API.format(token=token), data=payload)
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            ok = resp.status == 200
            data = json.loads(resp.read().decode(errors="replace"))
            if not data.get("ok", ok):
                print(f"[notify] Telegram refused: {data}", file=sys.stderr)
                return False
            return True
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        print(f"[notify] HTTP {exc.code}: {detail}", file=sys.stderr)
    except Exception as exc:
        print(f"[notify] {type(exc).__name__}: {exc}", file=sys.stderr)
    return False


# ── message builders ────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_summary(reports, folder: str = "") -> str:
    """Build the alert body from batch_report.DeviceReport objects.

    Only CRITICAL and WARNING devices are listed — a Telegram alert that
    recites INFO noise gets muted, and a muted channel is worse than none.
    """
    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for r in reports:
        counts[r.severity] = counts.get(r.severity, 0) + 1

    interesting = [r for r in reports if r.severity in ("CRITICAL", "WARNING")]
    head = "🔴" if counts.get("CRITICAL") else ("🟠" if counts.get("WARNING") else "🟢")

    lines = [
        f"{head} <b>LogAnalyzer V1</b>",
        f"<code>{_esc(folder or 'scan')}</code> · {datetime.now():%Y-%m-%d %H:%M}",
        "",
        f"Devices: {len(reports)} · "
        f"CRITICAL {counts.get('CRITICAL', 0)} · "
        f"WARNING {counts.get('WARNING', 0)} · "
        f"INFO {counts.get('INFO', 0)}",
    ]

    if interesting:
        lines.append("")
        for r in interesting[:10]:
            top = r.issues[0].label if r.issues else "—"
            lines.append(f"• <b>{r.severity}</b> <code>{_esc(r.name)}</code> — "
                         f"{_esc(top)}")
        if len(interesting) > 10:
            lines.append(f"… +{len(interesting) - 10} perangkat lain")
    else:
        lines.append("")
        lines.append("Tidak ada CRITICAL/WARNING.")

    return "\n".join(lines)


def format_issue_alert(device: str, severity: str, issues) -> str:
    """Single-device alert, for hooking into auto_scan."""
    icon = {"CRITICAL": "🔴", "WARNING": "🟠"}.get(severity, "🔵")
    lines = [f"{icon} <b>{severity}</b> — <code>{_esc(device)}</code>", ""]
    for i in issues[:8]:
        ent = f" ({_esc(', '.join(i.entities[:3]))})" if i.entities else ""
        lines.append(f"• [{i.rule.severity}] {_esc(i.rule.name)}{ent} — {i.count} hit")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="LogAnalyzer V1 — Telegram notifier")
    ap.add_argument("--test", action="store_true", help="send a test message")
    ap.add_argument("--text", default="", help="send arbitrary text")
    args = ap.parse_args()

    print(f"[notify] configured: {configured()}")
    if not configured():
        print("[notify] set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to send for real")

    if args.test or args.text:
        body = args.text or (f"✅ LogAnalyzer V1 test @ {datetime.now():%H:%M:%S}")
        ok = notify(body)
        print(f"[notify] sent: {ok}")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())