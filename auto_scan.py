"""auto_scan.py — Level 1 auto-scan pipeline for LogAnalyzer V1.

    log file(s)  ->  issue_rules.scan()  ->  fix_generator  ->  fix_script.txt
                          (deterministic)         (CLI commands)
                                      \\->  analyzer.analyze()  (optional LLM)

The deterministic pass always runs (free, instant, repeatable). The LLM pass is
opt-in via --llm because it costs tokens and needs the API key.

Usage:
    # analyse one file, no LLM
    python auto_scan.py ..\\pt_syslog.txt

    # analyse every .log/.txt in a folder, then watch it for new files
    python auto_scan.py ..\\logs --watch --interval 15

    # include the LLM deep-dive and write the fix script to a specific path
    python auto_scan.py ..\\pt_syslog.txt --llm --lang id --fix-out ..\\fix_script.txt
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

import fix_generator
import issue_rules

LOG_EXTENSIONS = (".log", ".txt", ".syslog")
STATE_NAME = ".autoscan_state.json"


# ── helpers ─────────────────────────────────────────────────────────────────

def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _fingerprint(path: str) -> str:
    """Content hash so a re-saved identical file is not re-analysed."""
    with open(path, "rb") as fh:
        return hashlib.sha1(fh.read()).hexdigest()


def _load_state(folder: str) -> set[str]:
    fp = os.path.join(folder, STATE_NAME)
    try:
        with open(fp, encoding="utf-8") as fh:
            return set(json.load(fh))
    except Exception:
        return set()


def _save_state(folder: str, seen: set[str]) -> None:
    with open(os.path.join(folder, STATE_NAME), "w", encoding="utf-8") as fh:
        json.dump(sorted(seen), fh)


def _candidates(folder: str) -> list[str]:
    """Log files to ingest — never our own output.

    The `.fix.txt` guard is load-bearing: watch mode writes its remediation
    script next to the logs, and without this filter the next poll re-reads
    that script as input and emits `name.fix.fix.fix.txt` forever.
    """
    out = []
    for name in sorted(os.listdir(folder)):
        if name.startswith("."):
            continue
        if name.endswith(".fix.txt"):
            continue
        path = os.path.join(folder, name)
        if os.path.isfile(path) and name.lower().endswith(LOG_EXTENSIONS):
            out.append(path)
    return out


# ── pipeline ────────────────────────────────────────────────────────────────

def process(path: str, *, use_llm: bool, lang: str, fix_out: str | None,
            notify: bool = False) -> tuple[list[issue_rules.DetectedIssue], str]:
    log_text = _read(path)
    if not log_text.strip():
        print(f"[skip] {path} — empty")
        return [], ""

    issues = issue_rules.scan(log_text)
    severity = issue_rules.worst_severity(issues)

    print(f"\n{'=' * 66}")
    print(f"  FILE     : {os.path.basename(path)}")
    print(f"  LINES    : {len(log_text.splitlines())}")
    print(f"  SEVERITY : {severity}")
    print(f"{'=' * 66}")
    print(issue_rules.summarize(issues))

    # Detect the vendor on every run, not only with --llm. The fix script's
    # command dialect depends on it, and defaulting to Cisco IOS sent
    # `show ip ssh` to an OpenWrt box that has no such command.
    vendor = "Cisco IOS"
    try:
        from analyzer import detect_vendor
        det = detect_vendor(log_text)
        vendor = det.vendor
        print(f"\n[vendor] {vendor} ({det.confidence_hits} pattern hits)")
    except Exception as exc:
        print(f"\n[vendor] deteksi gagal — {type(exc).__name__}: {exc}",
              file=sys.stderr)

    if use_llm:
        try:
            from analyzer import analyze
            print("[llm]  menjalankan analisis…")
            result = analyze(log_text, lang=lang)
            print("\n" + result.analysis)
            print(f"\n[llm] model={result.model} "
                  f"tokens={result.prompt_tokens}+{result.completion_tokens}")
        except Exception as exc:
            print(f"\n[llm] skipped — {type(exc).__name__}: {exc}", file=sys.stderr)

    script = fix_generator.build_script(issues, vendor=vendor)

    safe = fix_generator.auto_applicable(issues)
    if safe:
        print("\n[auto] reversible fixes available for: "
              + ", ".join(i.label for i in safe))
    else:
        print("\n[auto] nothing safe to apply unattended — human review required")

    if fix_out:
        with open(fix_out, "w", encoding="utf-8") as fh:
            fh.write(script)
        print(f"[fix]  written -> {fix_out}")

    if notify and severity in ("CRITICAL", "WARNING"):
        import notifier
        sent = notifier.notify(
            notifier.format_issue_alert(os.path.basename(path), severity, issues))
        print(f"[notify] alert sent: {sent}")

    return issues, script


# ── modes ───────────────────────────────────────────────────────────────────

def run_once(target: str, args) -> int:
    if os.path.isdir(target):
        files = _candidates(target)
        if not files:
            print(f"[scan] no log files in {target}")
            return 0
        for path in files:
            process(path, use_llm=args.llm, lang=args.lang, fix_out=args.fix_out,
                    notify=args.notify)
        return 0
    if not os.path.isfile(target):
        print(f"error: {target} is neither a file nor a directory", file=sys.stderr)
        return 2
    process(target, use_llm=args.llm, lang=args.lang, fix_out=args.fix_out,
            notify=args.notify)
    return 0


def run_watch(folder: str, args) -> int:
    if not os.path.isdir(folder):
        print(f"error: {folder} is not a directory", file=sys.stderr)
        return 2
    seen = _load_state(folder)
    print(f"[watch] {folder} every {args.interval}s "
          f"({len(seen)} file(s) already processed) — Ctrl+C to stop")
    try:
        while True:
            for path in _candidates(folder):
                fp = _fingerprint(path)
                if fp in seen:
                    continue
                print(f"\n[watch] new/changed: {os.path.basename(path)}")
                fixdir = os.path.join(folder, "fixes")
                os.makedirs(fixdir, exist_ok=True)
                out = args.fix_out or os.path.join(
                    fixdir, os.path.splitext(os.path.basename(path))[0] + ".fix.txt")
                process(path, use_llm=args.llm, lang=args.lang, fix_out=out,
                        notify=args.notify)
                seen.add(fp)
                _save_state(folder, seen)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[watch] stopped")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="LogAnalyzer V1 — auto-scan pipeline")
    ap.add_argument("target", help="log file or folder")
    ap.add_argument("--watch", action="store_true", help="keep scanning for new files")
    ap.add_argument("--interval", type=int, default=15, help="watch poll seconds")
    ap.add_argument("--llm", action="store_true", help="also run the LLM deep-dive")
    ap.add_argument("--lang", choices=["id", "en", "de"], default="id")
    ap.add_argument("--fix-out", default=None, help="where to write fix_script.txt")
    ap.add_argument("--notify", action="store_true",
                    help="send a Telegram alert on CRITICAL/WARNING")
    args = ap.parse_args()

    if args.watch:
        return run_watch(args.target, args)
    return run_once(args.target, args)


if __name__ == "__main__":
    raise SystemExit(main())