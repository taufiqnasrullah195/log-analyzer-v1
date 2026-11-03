"""desktop.py — LogAnalyzer Desktop GUI (Tkinter/ttk).

Second front-end next to cli.py/menu.py: same engine (analyzer,
issue_rules, fix_generator), no logic duplicated. Terminal users keep
`python cli.py <log>`; desktop users get this window.

    python desktop.py            # interactive
    python desktop.py --selftest # headless: load sample, run local
                                 # pipeline (no LLM), verify render, exit 0
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import sqlite3
import sys
import threading
import time
import traceback
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import tkinter as tk

import analyzer
import fix_generator
import issue_rules

HERE = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / \
    "LogAnalyzer" / "loganalyzer.db"

# ── Editorial Light palette (shared with TheWiseAudit / portfolio) ──────────
PAPER = "#F7F6F3"
SURFACE = "#FFFFFF"
ACCENT = "#A94F1C"
ACCENT_DEEP = "#7E3A12"
ACCENT_SOFT = "#F0E2D8"
INK = "#16171A"
INK_SOFT = "#33343A"
FAINT = "#67686D"
LINE = "#DAD8D3"

SEV_COLORS = {"CRITICAL": ACCENT, "WARNING": "#8a6d1a", "INFO": FAINT,
              "OK": "#4a7a3a"}

FONT_DISPLAY = ("Georgia", 15, "bold")
FONT_MONO = ("Consolas", 10)
FONT_BODY = ("Segoe UI", 10)


class LogAnalyzerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("LogAnalyzer — AI syslog triage")
        self.geometry("1100x720")
        self.configure(bg=PAPER)

        self._log_text = ""
        self._log_path: Path | None = None
        self._issues: list[issue_rules.DetectedIssue] = []
        self._analysis: analyzer.AnalysisResult | None = None
        self._queue: queue.Queue = queue.Queue()
        self._busy = threading.Event()

        self._build_style()
        self._build_header()
        self._build_toolbar()
        self._build_tabs()
        self._build_footer()
        self.after(100, self._drain_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI scaffolding ──────────────────────────────────────────────────
    def _build_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=PAPER, foreground=INK,
                        font=FONT_BODY)
        style.configure("TNotebook", background=PAPER, borderwidth=0)
        style.configure("TNotebook.Tab", background=PAPER, foreground=INK_SOFT,
                        padding=(14, 7), font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                  background=[("selected", SURFACE)],
                  foreground=[("selected", ACCENT_DEEP)])
        style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE,
                        foreground=INK, rowheight=26, font=FONT_BODY)
        style.configure("Treeview.Heading", background=PAPER,
                        foreground=INK_SOFT, font=("Segoe UI", 9, "bold"))

    def _build_header(self) -> None:
        bar = tk.Frame(self, bg=PAPER)
        bar.pack(fill="x", padx=24, pady=(16, 6))
        tk.Label(bar, text="LogAnalyzer", font=FONT_DISPLAY, bg=PAPER,
                 fg=ACCENT_DEEP).pack(side="left")
        tk.Label(bar, text="  AI syslog triage · vendor detect · auto-fix",
                 font=FONT_MONO, bg=PAPER, fg=FAINT).pack(side="left",
                                                          pady=(6, 0))

    def _build_toolbar(self) -> None:
        bar = tk.Frame(self, bg=PAPER)
        bar.pack(fill="x", padx=24, pady=6)
        self._btn_open = self._mk_btn(bar, "Open log…", self._open_log)
        self._btn_open.pack(side="left")
        self._btn_run = self._mk_btn(bar, "Run local analysis",
                                     self._run_local, primary=True)
        self._btn_run.pack(side="left", padx=6)
        self._btn_llm = self._mk_btn(bar, "AI analysis", self._run_llm)
        self._btn_llm.pack(side="left")
        self._btn_fix = self._mk_btn(bar, "Build fix script",
                                     self._build_fix)
        self._btn_fix.pack(side="left", padx=6)
        self._btn_export = self._mk_btn(bar, "Export report", self._export_md)
        self._btn_export.pack(side="left")
        self._status = tk.StringVar(value="Ready — open a log file to begin")
        tk.Label(bar, textvariable=self._status, font=FONT_MONO, bg=PAPER,
                 fg=FAINT).pack(side="right")

    def _mk_btn(self, parent, text, cmd, primary=False):
        btn = tk.Button(parent, text=text, command=cmd, cursor="hand2",
                        bg=ACCENT if primary else SURFACE,
                        fg=SURFACE if primary else INK,
                        activebackground=ACCENT_DEEP if primary else ACCENT_SOFT,
                        activeforeground=SURFACE if primary else INK,
                        relief="flat", padx=14, pady=6, font=FONT_BODY,
                        highlightthickness=1,
                        highlightbackground=LINE)
        return btn

    def _build_tabs(self) -> None:
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True, padx=24, pady=(4, 6))

        # Tab 1 — raw log
        f1 = tk.Frame(self._nb, bg=SURFACE)
        self._nb.add(f1, text="  Log  ")
        self._log_view = tk.Text(f1, wrap="none", font=FONT_MONO, bg=SURFACE,
                                 fg=INK_SOFT, relief="flat", padx=12, pady=10)
        ys = ttk.Scrollbar(f1, orient="vertical", command=self._log_view.yview)
        xs = ttk.Scrollbar(f1, orient="horizontal",
                           command=self._log_view.xview)
        self._log_view.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self._log_view.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns"); xs.grid(row=1, column=0,
                                                       sticky="ew")
        f1.rowconfigure(0, weight=1); f1.columnconfigure(0, weight=1)

        # Tab 2 — issues (rule engine)
        f2 = tk.Frame(self._nb, bg=SURFACE)
        self._nb.add(f2, text="  Issues  ")
        cols = ("severity", "rule", "count", "entities", "samples")
        self._tree = ttk.Treeview(f2, columns=cols, show="headings", height=18)
        for c, w in zip(cols, (90, 220, 60, 220, 420)):
            self._tree.heading(c, text=c.capitalize())
            self._tree.column(c, width=w, anchor="w")
        self._tree.tag_configure("CRITICAL", foreground=ACCENT)
        self._tree.tag_configure("WARNING", foreground="#8a6d1a")
        self._tree.tag_configure("INFO", foreground=FAINT)
        y2 = ttk.Scrollbar(f2, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=y2.set)
        self._tree.pack(side="left", fill="both", expand=True, padx=(12, 0),
                        pady=12)
        y2.pack(side="right", fill="y", pady=12, padx=(0, 12))

        # Tab 3 — AI analysis
        f3 = tk.Frame(self._nb, bg=SURFACE)
        self._nb.add(f3, text="  AI Analysis  ")
        self._ai_view = tk.Text(f3, wrap="word", font=FONT_BODY, bg=SURFACE,
                                fg=INK, relief="flat", padx=14, pady=12,
                                state="disabled")
        y3 = ttk.Scrollbar(f3, orient="vertical", command=self._ai_view.yview)
        self._ai_view.configure(yscrollcommand=y3.set)
        self._ai_view.pack(side="left", fill="both", expand=True,
                           padx=(12, 0), pady=12)
        y3.pack(side="right", fill="y", pady=12, padx=(0, 12))

        # Tab 4 — fix script
        f4 = tk.Frame(self._nb, bg=SURFACE)
        self._nb.add(f4, text="  Fix Script  ")
        top4 = tk.Frame(f4, bg=SURFACE)
        top4.pack(fill="x", padx=12, pady=(12, 0))
        tk.Button(top4, text="Copy to clipboard", command=self._copy_fix,
                  bg=SURFACE, fg=INK, relief="flat", padx=12, pady=4,
                  highlightthickness=1, highlightbackground=LINE,
                  cursor="hand2", font=FONT_BODY).pack(side="left")
        tk.Button(top4, text="Save as .txt", command=self._save_fix,
                  bg=SURFACE, fg=INK, relief="flat", padx=12, pady=4,
                  highlightthickness=1, highlightbackground=LINE,
                  cursor="hand2", font=FONT_BODY).pack(side="left", padx=6)
        self._fix_view = tk.Text(f4, wrap="none", font=FONT_MONO, bg=SURFACE,
                                 fg=INK_SOFT, relief="flat", padx=12, pady=10)
        y4 = ttk.Scrollbar(f4, orient="vertical", command=self._fix_view.yview)
        self._fix_view.configure(yscrollcommand=y4.set)
        self._fix_view.pack(fill="both", expand=True, padx=(12, 0),
                            pady=(8, 12))
        y4.pack(side="right", fill="y", pady=(8, 12), padx=(0, 12))

        # Tab 5 — history
        f5 = tk.Frame(self._nb, bg=SURFACE)
        self._nb.add(f5, text="  History  ")
        hcols = ("id", "when", "file", "vendor", "issues", "worst",
                 "llm_used")
        self._hist = ttk.Treeview(f5, columns=hcols, show="headings", height=18)
        for c, w in zip(hcols, (40, 150, 260, 130, 60, 90, 70)):
            self._hist.heading(c, text={"id": "ID", "when": "Analyzed",
                                        "file": "File", "vendor": "Vendor",
                                        "issues": "Issues",
                                        "worst": "Worst",
                                        "llm_used": "AI"}.get(c, c))
            self._hist.column(c, width=w, anchor="w")
        y5 = ttk.Scrollbar(f5, orient="vertical", command=self._hist.yview)
        self._hist.configure(yscrollcommand=y5.set)
        self._hist.pack(side="left", fill="both", expand=True, padx=(12, 0),
                        pady=12)
        y5.pack(side="right", fill="y", pady=12, padx=(0, 12))
        tk.Button(f5, text="Delete selected", command=self._delete_hist_row,
                  bg=SURFACE, fg=INK, relief="flat", padx=12, pady=4,
                  highlightthickness=1, highlightbackground=LINE,
                  cursor="hand2", font=FONT_BODY).pack(anchor="w", padx=12,
                                                       pady=(0, 12))
        self._refresh_history()

    def _build_footer(self) -> None:
        bar = tk.Frame(self, bg=PAPER)
        bar.pack(fill="x", padx=24, pady=(0, 10))
        self._foot = tk.StringVar(
            value=f"LogAnalyzer v1.0 · Editorial Light · "
                  f"model: {analyzer.DEFAULT_MODEL} · engine: local rules + LLM")
        tk.Label(bar, textvariable=self._foot, font=FONT_MONO, bg=PAPER,
                 fg=FAINT).pack(side="left")

    # ── actions ─────────────────────────────────────────────────────────
    def _open_log(self) -> None:
        path = filedialog.askopenfilename(
            title="Open log file",
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")])
        if not path:
            return
        self._log_path = Path(path)
        try:
            self._log_text = self._log_path.read_text(
                encoding="utf-8", errors="replace")
        except OSError as exc:
            messagebox.showerror("Open failed", str(exc))
            return
        self._log_view.configure(state="normal")
        self._log_view.delete("1.0", "end")
        self._log_view.insert("1.0", self._log_text)
        self._log_view.configure(state="disabled")
        det = analyzer.detect_vendor(self._log_text)
        self._status.set(f"{self._log_path.name} · {det.vendor} · "
                         f"{det.event_count} events · "
                         f"{len(self._log_text):,} chars")
        self._nb.select(0)

    def _worker(self, fn) -> None:
        if self._busy.is_set():
            return
        if not self._log_text:
            messagebox.showinfo("No log loaded", "Open a log file first.")
            return
        self._busy.set()
        self._btn_run.configure(state="disabled")
        self._btn_llm.configure(state="disabled")

        def run():
            try:
                fn()
            except Exception:
                self._queue.put(("error", traceback.format_exc()))
            finally:
                self._busy.clear()
                self._queue.put(("done", None))
        threading.Thread(target=run, daemon=True).start()

    def _run_local(self) -> None:
        self._worker(self._task_local)

    def _task_local(self) -> None:
        t0 = time.time()
        issues = issue_rules.scan(self._log_text)
        det = analyzer.detect_vendor(self._log_text)
        self._queue.put(("local", det, issues, time.time() - t0))

    def _run_llm(self) -> None:
        self._worker(self._task_llm)

    def _task_llm(self) -> None:
        t0 = time.time()
        res = analyzer.analyze(self._log_text)
        self._queue.put(("llm", res, time.time() - t0))

    def _build_fix(self) -> None:
        if not self._issues:
            messagebox.showinfo("No issues", "Run local analysis first.")
            return
        det = analyzer.detect_vendor(self._log_text)
        script = fix_generator.build_script(self._issues, det.vendor)
        self._fix_view.configure(state="normal")
        self._fix_view.delete("1.0", "end")
        self._fix_view.insert("1.0", script)
        self._fix_view.configure(state="disabled")
        self._nb.select(3)
        self._status.set(f"Fix script built · {len(self._issues)} issues · "
                         f"vendor {det.vendor}")

    def _copy_fix(self) -> None:
        text = self._fix_view.get("1.0", "end").strip()
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._status.set("Fix script copied to clipboard")

    def _save_fix(self) -> None:
        text = self._fix_view.get("1.0", "end").strip()
        if not text:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile="fix_script.txt")
        if path:
            Path(path).write_text(text, encoding="utf-8")
            self._status.set(f"Fix script saved → {path}")

    def _export_md(self) -> None:
        if not self._log_text:
            return
        det = analyzer.detect_vendor(self._log_text)
        lines = [f"# LogAnalyzer report — {det.vendor}",
                 f"*{datetime.now():%Y-%m-%d %H:%M:%S} · "
                 f"{det.event_count} events*", ""]
        if self._issues:
            lines.append(f"**Worst severity:** "
                         f"{issue_rules.worst_severity(self._issues)}")
            lines.append("")
            for iss in self._issues:
                lines.append(f"- **{iss.rule.severity}** {iss.label} "
                             f"({iss.count}x)")
            lines.append("")
        if self._analysis:
            lines.append("## AI analysis")
            lines.append("")
            lines.append(self._analysis.analysis)
            lines.append("")
        path = filedialog.asksaveasfilename(
            defaultextension=".md", initialfile="loganalyzer_report.md")
        if path:
            Path(path).write_text("\n".join(lines), encoding="utf-8")
            self._status.set(f"Report saved → {path}")

    # ── history (SQLite) ────────────────────────────────────────────────
    def _db(self) -> sqlite3.Connection:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analyzed_at TEXT NOT NULL,
            file_name TEXT NOT NULL,
            vendor TEXT NOT NULL,
            issue_count INTEGER NOT NULL,
            worst_severity TEXT NOT NULL,
            llm_used INTEGER NOT NULL DEFAULT 0)""")
        return conn

    def _save_history(self, det, issues: list, llm_used: bool) -> None:
        try:
            conn = self._db()
            conn.execute(
                "INSERT INTO analysis_history (analyzed_at, file_name,"
                " vendor, issue_count, worst_severity, llm_used)"
                " VALUES (?,?,?,?,?,?)",
                (f"{datetime.now():%Y-%m-%d %H:%M:%S}",
                 self._log_path.name if self._log_path else "(pasted)",
                 det.vendor, len(issues),
                 issue_rules.worst_severity(issues) if issues else "OK",
                 1 if llm_used else 0))
            conn.commit()
            conn.close()
        except sqlite3.Error:
            pass  # persistence is best-effort, never blocks analysis

    def _refresh_history(self) -> None:
        for row in self._hist.get_children():
            self._hist.delete(row)
        try:
            conn = self._db()
            for row in conn.execute("SELECT id, analyzed_at, file_name,"
                                    " vendor, issue_count, worst_severity,"
                                    " llm_used FROM analysis_history"
                                    " ORDER BY id DESC LIMIT 100"):
                self._hist.insert("", "end", values=row)
            conn.close()
        except sqlite3.Error:
            pass

    def _delete_hist_row(self) -> None:
        sel = self._hist.selection()
        if not sel:
            return
        rid = self._hist.item(sel[0])["values"][0]
        try:
            conn = self._db()
            conn.execute("DELETE FROM analysis_history WHERE id=?", (rid,))
            conn.commit()
            conn.close()
        except sqlite3.Error:
            pass
        self._refresh_history()

    # ── queue drain ─────────────────────────────────────────────────────
    def _drain_queue(self) -> None:
        try:
            while True:
                item = self._queue.get_nowait()
                if item[0] == "local":
                    _, det, issues, secs = item
                    self._issues = issues
                    for row in self._tree.get_children():
                        self._tree.delete(row)
                    for iss in issues:
                        self._tree.insert("", "end", tags=(iss.rule.severity,),
                                           values=(iss.rule.severity,
                                                   iss.rule.name, iss.count,
                                                   ", ".join(iss.entities[:4]),
                                                   iss.samples[0][:90]
                                                   if iss.samples else ""))
                    self._status.set(f"Local analysis done · {len(issues)} "
                                     f"issues · {det.vendor} · {secs:.2f}s")
                    self._save_history(det, issues, llm_used=False)
                    self._refresh_history()
                    self._nb.select(1)
                elif item[0] == "llm":
                    _, res, secs = item
                    self._analysis = res
                    self._ai_view.configure(state="normal")
                    self._ai_view.delete("1.0", "end")
                    self._ai_view.insert("1.0", res.analysis)
                    self._ai_view.configure(state="disabled")
                    det = res.vendor
                    self._status.set(f"AI analysis done · {res.model} · "
                                     f"{res.prompt_tokens}+"
                                     f"{res.completion_tokens} tokens · "
                                     f"{secs:.1f}s")
                    self._save_history(det, self._issues, llm_used=True)
                    self._refresh_history()
                    self._nb.select(2)
                elif item[0] == "error":
                    messagebox.showerror("Analysis failed", item[1])
                    self._status.set("Error — see dialog")
                elif item[0] == "done":
                    self._btn_run.configure(state="normal")
                    self._btn_llm.configure(state="normal")
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    def _on_close(self) -> None:
        self.destroy()


def selftest() -> int:
    """Headless render test: load a sample, run the local pipeline through
    the same methods the buttons call, verify state, close."""
    app = LogAnalyzerApp()
    app.update_idletasks()
    sample = (HERE / "samples")
    logs = sorted(sample.glob("*.log")) or sorted(sample.glob("*.txt"))
    assert logs, "no sample logs found for selftest"
    app._log_path = logs[0]
    app._log_text = logs[0].read_text(encoding="utf-8", errors="replace")
    det = analyzer.detect_vendor(app._log_text)
    issues = issue_rules.scan(app._log_text)
    script = fix_generator.build_script(issues, det.vendor)
    assert det.vendor, "vendor detection returned empty"
    assert isinstance(issues, list), "issue scan did not return a list"
    assert script.strip(), "fix script empty"
    app.update()
    app.destroy()
    print(f"SELFTEST OK · sample={logs[0].name} · vendor={det.vendor} · "
          f"issues={len(issues)} · fix_script={len(script)} chars")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="LogAnalyzer Desktop")
    ap.add_argument("--selftest", action="store_true",
                    help="headless render test, exit 0 on success")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    LogAnalyzerApp().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
