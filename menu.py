"""menu.py — interactive control panel for LogAnalyzer V1.

One entry point instead of six scripts to remember. Every action shells out to
the existing CLI (`auto_scan.py`, `batch_report.py`, ...) rather than importing
and duplicating logic, so the CLI stays the single source of truth and a crash
inside one action cannot take the menu down with it.

    python menu.py
    python menu.py --no-color
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOGS = os.path.join(HERE, "logs")
DESKTOP = os.path.expanduser("~/Desktop")

# ── styling ─────────────────────────────────────────────────────────────────

class Style:
    def __init__(self, enabled: bool):
        self.on = enabled

    def _w(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.on else s

    def bold(self, s):   return self._w("1", s)
    def dim(self, s):    return self._w("2", s)
    def red(self, s):    return self._w("91", s)
    def green(self, s):  return self._w("92", s)
    def yellow(self, s): return self._w("93", s)
    def blue(self, s):   return self._w("94", s)
    def cyan(self, s):   return self._w("96", s)


S = Style(True)


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    try:
        input(S.dim("\n  [Enter] kembali ke menu…"))
    except EOFError:
        pass


def ask(prompt: str, default: str = "") -> str:
    suffix = f" {S.dim(f'[{default}]')}" if default else ""
    try:
        got = input(f"  {prompt}{suffix}: ").strip()
    except EOFError:
        return default
    return got or default


def yes(prompt: str, default: bool = False) -> bool:
    d = "y" if default else "n"
    return ask(f"{prompt} (y/n)", d).lower().startswith("y")


# ── discovery ───────────────────────────────────────────────────────────────

def log_files(folder: str) -> list[str]:
    if not os.path.isdir(folder):
        return []
    out = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d != "fixes" and not d.startswith(".")]
        for n in sorted(files):
            if n.startswith(".") or n.endswith((".fix.txt",)):
                continue
            if n.lower().endswith((".log", ".txt", ".syslog")):
                out.append(os.path.join(root, n))
    return sorted(out)


def counts() -> tuple[int, int]:
    """(rule count, vendor count) read from the modules — never hardcoded."""
    rules = vendors = 0
    try:
        sys.path.insert(0, HERE)
        import issue_rules
        rules = len(issue_rules.RULES)
    except Exception:
        pass
    try:
        from analyzer import VENDOR_PATTERNS
        vendors = len(VENDOR_PATTERNS)
    except Exception:
        pass
    return rules, vendors


def telegram_on() -> bool:
    return bool(os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
                and os.environ.get("TELEGRAM_CHAT_ID", "").strip())


def report_status(logs_dir: str) -> None:
    rules, vendors = counts()
    files = len(log_files(logs_dir))
    tg = S.green("ON") if telegram_on() else S.dim("OFF (dry-run)")
    print(f"  {S.dim('Status')}  ·  {rules} rules  ·  {vendors} vendors  ·  "
          f"{files} log file  ·  Telegram {tg}")
    print(f"  {S.dim('Logs')}    ·  {logs_dir}")


# ── banner + menu ───────────────────────────────────────────────────────────

BANNER = r"""
   _                 _                _                         __   __
  | |    ___   __ _ | |  __ _ _ __   | |    __ _  _ __    ___  \ \ / /
  | |   / _ \ / _` || | / _` | '_ \  | |   / _` || '_ \  / _ \  \ V /
  | |__| (_) | (_| || || (_| | | | | | |__| (_| || | | ||  __/   | |
  |_____\___/ \__,_||_| \__,_|_| |_| |_____\__,_||_| |_| \___|   |_|
"""


def show_menu(logs_dir: str) -> None:
    clear()
    print(S.cyan(BANNER))
    print(f"  {S.bold('AI Network Log Analyzer')} — L1 support console")
    print(S.dim("  " + "─" * 62))
    report_status(logs_dir)
    print(S.dim("  " + "─" * 62))
    print()
    items = [
        ("1", "FULL SCAN",    "batch + LLM + report + alert, semua sekaligus"),
        ("2", "Scan 1 file",  "analisis cepat satu log (tanpa LLM)"),
        ("3", "Scan folder",  "batch report → markdown + HTML"),
        ("4", "Watch folder", "mode daemon, auto-scan tiap file baru"),
        ("5", "Analyze + LLM","deep-dive satu file pakai model AI"),
        ("6", "Auto-Resolve", "terapkan fix otomatis (dry-run dulu, ada gate)"),
        ("7", "Check router", "poll syslog dari router LuCI (MERCUSYS)"),
        ("L", "Live Scan",   "ambil syslog langsung dari router, analisis real-time"),
        ("8", "Run tests",    "jalankan test suite pipeline"),
        ("9", "Settings",     "ganti folder log & status konfigurasi"),
        ("R", "Last report",  "buka laporan batch terakhir"),
        ("0", "Exit",         "keluar"),
    ]
    for key, title, desc in items:
        col = S.green if key == "1" else (S.dim if key == "0" else S.blue)
        print(f"   {col('[' + key + ']')} {S.bold(title):<24} {S.dim(desc)}")
    print()


# ── actions ─────────────────────────────────────────────────────────────────

def run(args: list[str], cwd: str = HERE) -> int:
    print(S.dim(f"  $ {' '.join([os.path.basename(sys.executable)] + args)}\n"))
    try:
        p = subprocess.run([sys.executable] + args, cwd=cwd)
        return p.returncode
    except KeyboardInterrupt:
        print(S.yellow("\n  dihentikan (Ctrl+C)"))
        return 130
    except Exception as exc:
        print(S.red(f"  error: {type(exc).__name__}: {exc}"))
        return 1


def pick_file(logs_dir: str) -> str | None:
    files = log_files(logs_dir)
    if not files:
        print(S.yellow("  tidak ada file log di folder itu."))
        return None
    print()
    for i, f in enumerate(files, 1):
        print(f"   {S.blue(f'[{i}]')} {os.path.relpath(f, logs_dir)}")
    print()
    raw = ask("pilih nomor", "1")
    if not raw.isdigit() or not (1 <= int(raw) <= len(files)):
        print(S.red("  nomor tidak valid."))
        return None
    return files[int(raw) - 1]


def act_full(logs_dir: str) -> None:
    """The one-button path: everything, in the order that matters."""
    print(S.bold("\n  FULL SCAN — batch + LLM + report + alert\n"))
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    md = os.path.join(DESKTOP, f"logreport_{stamp}.md")
    html = os.path.join(DESKTOP, f"logreport_{stamp}.html")

    use_llm = yes("jalankan analisis LLM (butuh token, hemat: hanya CRITICAL/WARNING)",
                  True)
    use_notify = yes("kirim alert Telegram kalau ada CRITICAL/WARNING", telegram_on())

    args = ["batch_report.py", logs_dir, "--out", md, "--html", html]
    if use_llm:
        args.append("--llm")
    if use_notify:
        args.append("--notify")

    rc = run(args)
    print()
    if os.path.isfile(md):
        print(S.green(f"  ✓ markdown : {md}"))
    if os.path.isfile(html):
        print(S.green(f"  ✓ html     : {html}"))
    if rc == 1:
        print(S.red("  ⚠ ada perangkat CRITICAL — cek laporan"))
    elif rc == 0:
        print(S.green("  ✓ tidak ada CRITICAL"))


def act_single(logs_dir: str) -> None:
    path = pick_file(logs_dir)
    if not path:
        return
    stem = os.path.splitext(os.path.basename(path))[0]
    out = os.path.join(DESKTOP, f"{stem}.fix.txt")
    print()
    run(["auto_scan.py", path, "--fix-out", out])
    if os.path.isfile(out):
        print(S.green(f"\n  ✓ fix script : {out}"))


def act_folder(logs_dir: str) -> None:
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    md = os.path.join(DESKTOP, f"logreport_{stamp}.md")
    html = os.path.join(DESKTOP, f"logreport_{stamp}.html")
    print()
    run(["batch_report.py", logs_dir, "--out", md, "--html", html])
    print(S.green(f"\n  ✓ {md}\n  ✓ {html}"))


def act_watch(logs_dir: str) -> None:
    every = ask("interval detik", "15")
    notify = "--notify" if yes("kirim alert Telegram?", telegram_on()) else None
    print(S.yellow(f"\n  mode watch — scan tiap {every}s. Ctrl+C untuk stop.\n"))
    args = ["auto_scan.py", logs_dir, "--watch", "--interval", every]
    if notify:
        args.append(notify)
    run(args)


def act_llm(logs_dir: str) -> None:
    path = pick_file(logs_dir)
    if not path:
        return
    lang = ask("bahasa analisis (id/en/de)", "id")
    print()
    run(["auto_scan.py", path, "--llm", "--lang", lang])


def act_resolve(logs_dir: str) -> None:
    """Apply fixes automatically — but always show the dry-run first."""
    print(S.bold("\n  Auto-Resolve — terapkan fix otomatis\n"))
    path = pick_file(logs_dir)
    if not path:
        return
    device = ask("nama device untuk audit trail", os.path.basename(path))

    print()
    print(S.dim("  transport:"))
    print(S.dim("    dry-run    — tampilkan saja (default, paling aman)"))
    print(S.dim("    clipboard  — taruh perintah di clipboard, paste ke CLI/PT"))
    print(S.dim("    ssh        — jalankan langsung ke device (butuh paramiko + --apply)"))
    transport = ask("transport (dry-run/clipboard/ssh)", "dry-run")
    if transport not in ("dry-run", "clipboard", "ssh"):
        print(S.red("  transport tidak dikenal."))
        return

    args = ["auto_resolve.py", path, "--device", device, "--transport", transport]

    if transport == "ssh":
        host = ask("host SSH")
        if not host:
            print(S.red("  host wajib untuk ssh."))
            return
        args += ["--host", host]
        user = ask("user SSH (kosong = env DEVICE_USER)", "")
        if user:
            args += ["--user", user]
        print(S.yellow("\n  ⚠ ssh akan MENGUBAH device. Tanpa --apply cuma dry-run."))
        if yes("benar-benar APPLY ke device? (password dari env DEVICE_PASS)", False):
            args.append("--apply")

    print()
    run(args)
    print(S.dim(f"\n  audit trail: {os.path.join(HERE, 'auto_resolve_audit.jsonl')}"))


def act_live_scan(logs_dir: str) -> None:
    """Live syslog pull langsung dari router MR3000X — DOM scrape, no API."""
    print(S.bold("\n  Live Scan — ambil syslog real-time dari Mercusys MR3000X\n"))

    ip = ask("IP router", os.environ.get("ROUTER_IP", "192.168.1.1"))
    pw = os.environ.get("ROUTER_PASS", "").strip()
    if not pw:
        import getpass
        try:
            pw = getpass.getpass(f"  Password router {ip} (tidak disimpan): ")
        except (KeyboardInterrupt, EOFError):
            print(S.yellow("\n  dibatalkan"))
            return
    if not pw:
        print(S.red("  password wajib diisi."))
        return

    use_llm  = yes("jalankan analisis LLM pada event baru", True)
    lang     = ask("bahasa (id/en/de)", "id")
    once     = yes("satu kali poll saja? (n = terus-menerus tiap 30s)", False)
    interval = "30"
    if not once:
        interval = ask("interval poll (detik)", "30")

    args = [
        "live_scan.py",
        "--ip", ip,
        "--lang", lang,
        "--interval", interval,
    ]
    if use_llm:
        args.append("--llm")
    if once:
        args.append("--once")

    env = os.environ.copy()
    env["ROUTER_PASS"] = pw
    env["ROUTER_IP"]   = ip

    print(S.yellow(
        f"\n  Scanning {ip} … Ctrl+C untuk stop.\n"
        if not once else f"\n  Single poll dari {ip} …\n"
    ))
    try:
        import subprocess
        subprocess.run([sys.executable] + args, cwd=HERE, env=env)
    except KeyboardInterrupt:
        print(S.yellow("\n  dihentikan"))


def act_router(logs_dir: str) -> None:
    print(S.bold("\n  Check router — MERCUSYS/MR3000X LuCI poller\n"))
    token = ask("stok token dari URL (kosong = mode login)", "")
    if token:
        run(["router_log_poller.py", "--mode", "token", "--token", token, "--once"])
    else:
        print(S.dim("  mode login butuh handshake browser (F12 → login?form=auth)."))
        print(S.dim("  tanpa itu, jalankan mode recon dulu untuk lihat respons API.\n"))
        if yes("jalankan recon sekarang", True):
            run(["router_log_poller.py", "--mode", "recon"])


def act_tests() -> None:
    print()
    rc = run(["test_pipeline.py"])
    print(S.green("\n  ✓ semua test lolos") if rc == 0
          else S.red("\n  ✗ ada test yang gagal"))


def act_last_report() -> None:
    import glob
    found = sorted(glob.glob(os.path.join(DESKTOP, "logreport_*.md"))
                   + glob.glob(os.path.join(DESKTOP, "batch_report.md")))
    if not found:
        print(S.yellow("  belum ada laporan."))
        return
    latest = max(found, key=os.path.getmtime)
    print(S.green(f"\n  laporan terakhir: {latest}\n"))
    try:
        with open(latest, encoding="utf-8") as fh:
            head = "".join(fh.readlines()[:32])
        print(S.dim("  " + "─" * 62))
        print("\n".join("  " + ln.rstrip() for ln in head.splitlines()))
        print(S.dim("  " + "─" * 62))
        print(S.dim(f"  (…{os.path.getsize(latest)} byte total — buka file untuk lengkap)"))
    except OSError as exc:
        print(S.red(f"  gagal baca: {exc}"))


def act_settings(state: dict) -> None:
    print(S.bold("\n  Settings\n"))
    rules, vendors = counts()
    print(f"   folder log      : {state['logs']}")
    print(f"   rules           : {rules}")
    print(f"   vendor          : {vendors}")
    print(f"   Telegram token  : {'set' if os.environ.get('TELEGRAM_BOT_TOKEN') else 'belum di-set'}")
    print(f"   Telegram chat   : {'set' if os.environ.get('TELEGRAM_CHAT_ID') else 'belum di-set'}")
    print(f"   output folder   : {DESKTOP}")
    print()
    new = ask("folder log baru (kosong = tidak berubah)", "")
    if new and os.path.isdir(new):
        state["logs"] = new
        print(S.green(f"  ✓ folder log → {new}"))
    elif new:
        print(S.red("  folder tidak ada, dibiarkan."))
    print()
    if not telegram_on():
        print(S.dim("  Telegram belum aktif. Set di terminal sebelum jalankan menu:"))
        print(S.dim("    set TELEGRAM_BOT_TOKEN=xxx"))
        print(S.dim("    set TELEGRAM_CHAT_ID=yyy"))


# ── main loop ───────────────────────────────────────────────────────────────

def main() -> int:
    global S
    ap = argparse.ArgumentParser(description="LogAnalyzer V1 — control panel")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--logs", default=DEFAULT_LOGS, help="folder log awal")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        S = Style(False)

    state = {"logs": args.logs}
    if not os.path.isdir(state["logs"]):
        os.makedirs(state["logs"], exist_ok=True)

    while True:
        logs_dir = state["logs"]
        show_menu(logs_dir)
        try:
            choice = input(f"  {S.bold('Pilih')} [0-9]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice not in {str(i) for i in range(10)} | {"r", "R", "l", "L"}:
            continue
        choice = choice.upper()
        if choice == "0":
            print(S.dim("\n  sampai jumpa.\n"))
            return 0

        try:
            if choice == "1":
                act_full(logs_dir)
            elif choice == "2":
                act_single(logs_dir)
            elif choice == "3":
                act_folder(logs_dir)
            elif choice == "4":
                act_watch(logs_dir)
            elif choice == "5":
                act_llm(logs_dir)
            elif choice == "6":
                act_resolve(logs_dir)
            elif choice == "7":
                act_router(logs_dir)
            elif choice == "L":
                act_live_scan(logs_dir)
            elif choice == "8":
                act_tests()
            elif choice == "9":
                act_settings(state)
            elif choice == "R":
                act_last_report()
        except KeyboardInterrupt:
            print(S.yellow("\n  dibatalkan"))

        if os.environ.get("LOGANALYZER_NO_PAUSE"):
            continue
        pause()


if __name__ == "__main__":
    raise SystemExit(main())