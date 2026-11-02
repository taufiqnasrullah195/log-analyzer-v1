"""batch_report.py — scan a folder of device logs into one prioritised report.

Single-file mode (auto_scan.py) answers "what is wrong with this device".
Batch mode answers the question an L1/L2 engineer actually starts the day
with: "of all the devices I collected, which ones need me first?"

Ordering is severity-first, then issue count, so a CRITICAL device can never
sit below a WARNING one just because its filename sorts later.

    python batch_report.py logs
    python batch_report.py logs --llm --out report.md --html report.html
    python batch_report.py logs --min-severity WARNING
"""
from __future__ import annotations

import argparse
import html
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime

import fix_generator
import issue_rules
from issue_rules import SEVERITY_ORDER

LOG_EXTENSIONS = (".log", ".txt", ".syslog")
SKIP_SUFFIXES = (".fix.txt",)
SKIP_DIRS = {"fixes", "__pycache__"}


@dataclass
class DeviceReport:
    path: str
    name: str
    vendor: str
    lines: int
    severity: str
    issues: list[issue_rules.DetectedIssue] = field(default_factory=list)
    analysis: str = ""

    @property
    def rank(self) -> tuple[int, int]:
        """Sort key: worst severity first, then most issues."""
        return (SEVERITY_ORDER.get(self.severity, 9), -len(self.issues))


# ── collection ──────────────────────────────────────────────────────────────

def collect(folder: str) -> list[str]:
    """Log files under `folder` (one level of subdirs), never our own output."""
    found: list[str] = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in sorted(files):
            if name.startswith(".") or name.endswith(SKIP_SUFFIXES):
                continue
            if name.lower().endswith(LOG_EXTENSIONS):
                found.append(os.path.join(root, name))
    return sorted(found)


# ── analysis ────────────────────────────────────────────────────────────────

def analyse(path: str, use_llm: bool, lang: str) -> DeviceReport | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"[skip] {path}: {exc}", file=sys.stderr)
        return None

    if not text.strip():
        return None

    issues = issue_rules.scan(text)
    vendor, severity = "Generic syslog", issue_rules.worst_severity(issues)

    if use_llm:
        try:
            from analyzer import analyze, detect_vendor
            det = detect_vendor(text)
            vendor = det.vendor
            # only pay for the LLM where it changes a decision
            if severity in ("CRITICAL", "WARNING"):
                result = analyze(text, lang=lang)
                vendor = result.vendor.vendor
                analysis = result.analysis
            else:
                analysis = ""
        except Exception as exc:
            print(f"[llm] {os.path.basename(path)}: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            analysis = ""
    else:
        try:
            from analyzer import detect_vendor
            vendor = detect_vendor(text).vendor
        except Exception:
            pass
        analysis = ""

    return DeviceReport(
        path=path,
        name=os.path.relpath(path),
        vendor=vendor,
        lines=len(text.splitlines()),
        severity=severity,
        issues=issues,
        analysis=analysis,
    )


# ── rendering ───────────────────────────────────────────────────────────────

def render_markdown(reports: list[DeviceReport], folder: str) -> str:
    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for r in reports:
        counts[r.severity] = counts.get(r.severity, 0) + 1

    out = [
        "# LogAnalyzer V1 — Batch Report",
        "",
        f"- **Folder**      : `{folder}`",
        f"- **Generated**   : {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"- **Devices**     : {len(reports)}",
        f"- **CRITICAL**    : {counts.get('CRITICAL', 0)}",
        f"- **WARNING**     : {counts.get('WARNING', 0)}",
        f"- **INFO**        : {counts.get('INFO', 0)}",
        "",
        "---",
        "",
        "## Ringkasan",
        "",
        "| # | Device | Vendor | Lines | Severity | Masalah utama |",
        "|---|--------|--------|-------|----------|----------------|",
    ]

    for i, r in enumerate(reports, 1):
        top = r.issues[0].label if r.issues else "—"
        out.append(f"| {i} | `{r.name}` | {r.vendor} | {r.lines} | "
                   f"**{r.severity}** | {top} |")

    out += ["", "---", "", "## Detail per perangkat", ""]

    for i, r in enumerate(reports, 1):
        out.append(f"### {i}. `{r.name}` — {r.severity}")
        out.append("")
        out.append(f"- Vendor : {r.vendor}")
        out.append(f"- Lines  : {r.lines}")
        out.append(f"- Issues : {len(r.issues)}")
        out.append("")
        if r.issues:
            for issue in r.issues:
                ent = f" — {', '.join(issue.entities[:3])}" if issue.entities else ""
                out.append(f"  - **[{issue.rule.severity}]** {issue.rule.name}"
                           f"{ent} ({issue.count} hit)")
        else:
            out.append("  - tidak ada pola masalah yang cocok")
        out.append("")

        if r.analysis:
            out.append("<details><summary>Analisis LLM</summary>")
            out.append("")
            out.append(r.analysis)
            out.append("")
            out.append("</details>")
            out.append("")

        script = fix_generator.build_script(r.issues, vendor=r.vendor)
        if r.issues:
            out.append("<details><summary>Fix script</summary>")
            out.append("")
            out.append("```")
            out.append(script)
            out.append("```")
            out.append("")
            out.append("</details>")
            out.append("")

    return "\n".join(out)


def render_html(reports: list[DeviceReport], folder: str) -> str:
    rows = []
    for i, r in enumerate(reports, 1):
        cls = r.severity.lower()
        top = html.escape(r.issues[0].label if r.issues else "—")
        rows.append(
            f"<tr class='{cls}'><td>{i}</td><td><code>{html.escape(r.name)}</code></td>"
            f"<td>{html.escape(r.vendor)}</td><td>{r.lines}</td>"
            f"<td><span class='sev {cls}'>{r.severity}</span></td><td>{top}</td></tr>")

    detail = []
    for i, r in enumerate(reports, 1):
        items = "".join(
            f"<li><b>[{x.rule.severity}]</b> {html.escape(x.rule.name)}"
            + (f" — {html.escape(', '.join(x.entities[:3]))}" if x.entities else "")
            + f" ({x.count} hit)</li>"
            for x in r.issues) or "<li>tidak ada pola masalah yang cocok</li>"
        script = html.escape(fix_generator.build_script(r.issues, vendor=r.vendor))
        detail.append(f"""
        <section class="dev {r.severity.lower()}">
          <h3>{i}. <code>{html.escape(r.name)}</code>
              <span class="sev {r.severity.lower()}">{r.severity}</span></h3>
          <p class="meta">{html.escape(r.vendor)} · {r.lines} lines · {len(r.issues)} issues</p>
          <ul>{items}</ul>
          <details><summary>Fix script</summary><pre>{script}</pre></details>
        </section>""")

    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for r in reports:
        counts[r.severity] = counts.get(r.severity, 0) + 1

    return f"""<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogAnalyzer V1 — Batch Report</title>
<style>
  :root {{ --bg:#020617; --card:#0f172a; --line:#1e293b; --dim:#94a3b8; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:2rem; background:var(--bg); color:#e2e8f0;
         font:14px/1.6 ui-monospace,'JetBrains Mono',Consolas,monospace; }}
  .wrap {{ max-width:1100px; margin:0 auto; }}
  h1 {{ font-size:1.4rem; margin:0 0 .25rem; }}
  .sub {{ color:var(--dim); margin-bottom:1.5rem; }}
  .stats {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
  .stat {{ background:var(--card); border:1px solid var(--line);
           border-radius:.6rem; padding:.75rem 1.1rem; min-width:120px; }}
  .stat .n {{ font-size:1.5rem; font-weight:700; }}
  .stat.critical .n {{ color:#fb7185; }}
  .stat.warning .n {{ color:#fbbf24; }}
  .stat.info .n {{ color:#38bdf8; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
           border:1px solid var(--line); border-radius:.6rem; overflow:hidden; }}
  th,td {{ padding:.55rem .7rem; text-align:left; border-bottom:1px solid var(--line); }}
  th {{ color:var(--dim); font-weight:600; font-size:.8rem; text-transform:uppercase; }}
  tr.critical td:first-child {{ border-left:3px solid #fb7185; }}
  tr.warning  td:first-child {{ border-left:3px solid #fbbf24; }}
  tr.info     td:first-child {{ border-left:3px solid #38bdf8; }}
  .sev {{ padding:.1rem .5rem; border-radius:.35rem; font-size:.75rem; font-weight:700; }}
  .sev.critical {{ background:rgba(251,113,133,.15); color:#fb7185; }}
  .sev.warning  {{ background:rgba(251,191,36,.15);  color:#fbbf24; }}
  .sev.info     {{ background:rgba(56,189,248,.15);  color:#38bdf8; }}
  section.dev {{ background:var(--card); border:1px solid var(--line);
                 border-radius:.6rem; padding:1rem 1.25rem; margin:1rem 0; }}
  section.dev.critical {{ border-left:3px solid #fb7185; }}
  section.dev.warning  {{ border-left:3px solid #fbbf24; }}
  section.dev.info     {{ border-left:3px solid #38bdf8; }}
  .meta {{ color:var(--dim); font-size:.8rem; margin:.2rem 0 .6rem; }}
  pre {{ background:#010409; border:1px solid var(--line); border-radius:.4rem;
         padding:.8rem; overflow-x:auto; font-size:.78rem; }}
  details summary {{ cursor:pointer; color:var(--dim); }}
  code {{ color:#7dd3fc; }}
</style></head><body><div class="wrap">
<h1>LogAnalyzer V1 — Batch Report</h1>
<p class="sub">folder <code>{html.escape(folder)}</code> · {datetime.now():%Y-%m-%d %H:%M:%S} · {len(reports)} perangkat</p>
<div class="stats">
  <div class="stat"><div class="n">{len(reports)}</div><div>Devices</div></div>
  <div class="stat critical"><div class="n">{counts.get('CRITICAL', 0)}</div><div>CRITICAL</div></div>
  <div class="stat warning"><div class="n">{counts.get('WARNING', 0)}</div><div>WARNING</div></div>
  <div class="stat info"><div class="n">{counts.get('INFO', 0)}</div><div>INFO</div></div>
</div>
<table><thead><tr><th>#</th><th>Device</th><th>Vendor</th><th>Lines</th>
<th>Severity</th><th>Masalah utama</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2 style="margin-top:2rem">Detail per perangkat</h2>
{''.join(detail)}
</div></body></html>"""


# ── entry point ─────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="LogAnalyzer V1 — batch report")
    ap.add_argument("folder", help="folder of log files")
    ap.add_argument("--llm", action="store_true",
                    help="run the LLM on CRITICAL/WARNING devices only")
    ap.add_argument("--lang", choices=["id", "en", "de"], default="id")
    ap.add_argument("--min-severity", choices=["INFO", "WARNING", "CRITICAL"],
                    default="INFO", help="hide devices below this severity")
    ap.add_argument("--out", default=None, help="markdown output path")
    ap.add_argument("--html", default=None, help="html output path")
    ap.add_argument("--notify", action="store_true",
                    help="send a Telegram alert when CRITICAL/WARNING is found")
    args = ap.parse_args()

    if not os.path.isdir(args.folder):
        print(f"error: {args.folder} is not a directory", file=sys.stderr)
        return 2

    files = collect(args.folder)
    if not files:
        print(f"[scan] no log files under {args.folder}", file=sys.stderr)
        return 1

    print(f"[scan] {len(files)} file(s) under {args.folder}")
    reports: list[DeviceReport] = []
    for path in files:
        r = analyse(path, args.llm, args.lang)
        if r is None:
            continue
        mark = " " if SEVERITY_ORDER.get(r.severity, 9) <= \
            SEVERITY_ORDER[args.min_severity] else "."
        print(f"  {mark} {r.severity:<8} {len(r.issues):>2} issue(s)  {r.name}")
        if SEVERITY_ORDER.get(r.severity, 9) <= SEVERITY_ORDER[args.min_severity]:
            reports.append(r)

    reports.sort(key=lambda r: r.rank)

    print()

    md = render_markdown(reports, args.folder)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"[out] markdown -> {args.out}")
    else:
        print(md)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(reports, args.folder))
        print(f"[out] html     -> {args.html}")

    if args.notify:
        import notifier
        interesting = [r for r in reports if r.severity in ("CRITICAL", "WARNING")]
        if interesting:
            sent = notifier.notify(notifier.format_summary(reports, args.folder))
            print(f"[notify] alert sent: {sent}")
        else:
            print("[notify] nothing CRITICAL/WARNING — staying quiet")

    # Non-zero exit on CRITICAL so this composes with cron/CI.
    critical = sum(1 for r in reports if r.severity == "CRITICAL")
    return 1 if critical else 0


if __name__ == "__main__":
    raise SystemExit(main())