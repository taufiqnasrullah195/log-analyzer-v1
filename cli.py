"""CLI front-end: python cli.py <logfile> [--lang id|en|de] or pipe via stdin."""
from __future__ import annotations

import argparse
import sys

from analyzer import analyze, detect_vendor


def main() -> int:
    parser = argparse.ArgumentParser(description="AI network log analyzer (L1 support tool)")
    parser.add_argument("logfile", nargs="?", help="path to log file (omit to read stdin)")
    parser.add_argument("--lang", choices=["id", "en", "de"], default="id")
    parser.add_argument("--detect-only", action="store_true",
                        help="only run vendor detection, skip the LLM call")
    args = parser.parse_args()

    if args.logfile:
        with open(args.logfile, encoding="utf-8", errors="replace") as fh:
            log_text = fh.read()
    else:
        log_text = sys.stdin.read()

    if not log_text.strip():
        parser.error("empty log input")

    detection = detect_vendor(log_text)
    print(f"Detected : {detection.vendor} ({detection.confidence_hits} pattern hits)")
    print(f"Events   : {detection.event_count} lines")
    if args.detect_only:
        return 0

    print("Analyzing...\n")
    try:
        result = analyze(log_text, lang=args.lang)
    except Exception as exc:  # surface the real error, never swallow it
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(result.analysis)
    print(f"\n---\nmodel={result.model} tokens={result.prompt_tokens}+{result.completion_tokens}"
          + (" (input truncated)" if result.truncated else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
