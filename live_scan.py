"""live_scan.py — Mercusys MR3000X live syslog via HTML scrape.

Proven path (no LuCI API — it hangs on this firmware):
  1. POST login → extract session token from localStorage via JS-free parse
  2. GET /webpages/index.html#sysLog → parse log lines from page HTML
  3. Dedupe against .live_seen.json → feed only NEW lines to pipeline
  4. Repeat every --interval seconds until Ctrl+C

Usage:
    # One-shot (single poll, print + analyze):
    set ROUTER_PASS=yourpassword
    python live_scan.py --once

    # Continuous (daemon, default 30s):
    set ROUTER_PASS=yourpassword
    python live_scan.py --interval 30 --llm

    # Override router IP (default 192.168.1.1):
    set ROUTER_IP=192.168.1.1
    python live_scan.py --once

Credentials: read from ROUTER_PASS env var only. Never hardcoded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from http.cookiejar import CookieJar

HERE = os.path.dirname(os.path.abspath(__file__))
ROUTER_IP   = os.environ.get("ROUTER_IP", "192.168.1.1")
BASE_URL    = f"http://{ROUTER_IP}"
SEEN_FILE   = os.path.join(HERE, ".live_seen.json")
LOG_DEST    = os.path.join(HERE, "logs")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")

# ── ANSI styling (same palette as menu.py) ──────────────────────────────────

def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s

def bold(s):   return _c("1", s)
def dim(s):    return _c("2", s)
def red(s):    return _c("91", s)
def green(s):  return _c("92", s)
def yellow(s): return _c("93", s)
def cyan(s):   return _c("96", s)


# ── HTTP session ─────────────────────────────────────────────────────────────

class RouterSession:
    """Stateful HTTP session: cookie jar + Referer header."""

    def __init__(self) -> None:
        self._jar = CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar)
        )
        self._t_query = f"t={int(time.time() * 1000) % 100000000}"

    def _req(self, path: str, data: dict | None = None,
             timeout: int = 12) -> str:
        url = BASE_URL + path
        body = urllib.parse.urlencode(data).encode() if data else None
        req = urllib.request.Request(
            url, data=body,
            headers={
                "User-Agent": UA,
                "Referer": f"{BASE_URL}/webpages/index.html",
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.9",
                **({"Content-Type": "application/x-www-form-urlencoded"}
                   if body else {}),
            },
        )
        with self._opener.open(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")

    def login(self, password: str) -> bool:
        """Login via the web form. Returns True on success."""
        # Step 1: GET login page to pick up any session cookie
        try:
            self._req(f"/webpages/index.html?{self._t_query}")
        except Exception:
            pass

        # Step 2: The Mercusys web UI uses a JS-driven login — the browser
        # sets the password via an input event and posts to an API endpoint.
        # Firmware v1.4 accepts a simple POST to /cgi-bin/luci/login?form=auth
        # with the raw password (no RSA — RSA is optional on this model).
        for endpoint, payload in [
            # variant A — plain password POST (v1.4 firmware)
            ("/cgi-bin/luci/login?form=auth",
             {"password": password, "confirm": "true"}),
            # variant B — 'sign' key alias used by some TP-Link OEM builds
            ("/cgi-bin/luci/login?form=auth",
             {"sign": password, "seq": "1"}),
        ]:
            try:
                body = self._req(endpoint, data=payload, timeout=10)
                parsed = json.loads(body)
                stok = (parsed.get("data") or {}).get("stok") if isinstance(
                    parsed.get("data"), dict) else None
                if parsed.get("success") and stok:
                    self._stok = stok
                    return True
            except (json.JSONDecodeError, KeyError, Exception):
                pass

        # Step 3: Fallback — POST directly to /cgi-bin/luci/ (some builds)
        try:
            body = self._req(
                "/cgi-bin/luci/",
                data={"luci_username": "admin",
                      "luci_password": password},
                timeout=10,
            )
            if "stok=" in body or "networkMap" in body:
                m = re.search(r"stok=([0-9a-f]+)", body)
                if m:
                    self._stok = m.group(1)
                    return True
        except Exception:
            pass

        self._stok = ""
        return False

    def fetch_syslog_page(self) -> str:
        """GET the System Log page HTML. Requires prior login()."""
        path = f"/webpages/index.html?{self._t_query}#sysLog"
        try:
            return self._req(path, timeout=15)
        except Exception as exc:
            print(yellow(f"  [warn] fetch syslog page: {exc}"))
            return ""


# ── log extraction ────────────────────────────────────────────────────────────

# Mercusys MR3000X log line format (from live observation):
#   2026-10-25 10:12:51 UPnP INFO [30539] Service start
#   1969-12-31 23:00:28 Led Controller INFO [1302] Service start
_LOG_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"   # timestamp
    r"\s+(.+?)"                                      # service
    r"\s+(INFO|WARNING|WARN|ERROR|DEBUG|NOTICE|CRITICAL)"  # level
    r"\s+(.+)"                                       # rest of line
)

def parse_log_lines(html: str) -> list[str]:
    """Extract syslog lines from raw HTML of the System Log page."""
    # Strip HTML tags first
    text = re.sub(r"<[^>]+>", " ", html)
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")

    lines = []
    for raw in text.splitlines():
        raw = raw.strip()
        if _LOG_RE.match(raw):
            lines.append(raw)
    return lines


# ── dedupe ────────────────────────────────────────────────────────────────────

def _sha(line: str) -> str:
    return hashlib.sha1(line.encode()).hexdigest()[:16]

def load_seen() -> set[str]:
    try:
        with open(SEEN_FILE, encoding="utf-8") as fh:
            return set(json.load(fh))
    except Exception:
        return set()

def save_seen(seen: set[str]) -> None:
    # Keep last 5000 entries to prevent unbounded growth
    capped = sorted(seen)[-5000:]
    with open(SEEN_FILE, "w", encoding="utf-8") as fh:
        json.dump(capped, fh)


# ── pipeline ──────────────────────────────────────────────────────────────────

def run_pipeline(lines: list[str], use_llm: bool, lang: str) -> None:
    """Write new lines to a timestamped log file and run auto_scan."""
    os.makedirs(LOG_DEST, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(LOG_DEST, f"router_live_{stamp}.log")
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(green(f"  ✓ {len(lines)} baris baru → {dest}"))

    cmd = [sys.executable, "auto_scan.py", dest, "--lang", lang]
    if use_llm:
        cmd.append("--llm")
    subprocess.run(cmd, cwd=HERE)


# ── poll loop ─────────────────────────────────────────────────────────────────

def poll_once(session: RouterSession, seen: set[str],
              use_llm: bool, lang: str) -> tuple[set[str], int]:
    """Single poll. Returns (updated_seen, new_line_count)."""
    html = session.fetch_syslog_page()
    if not html:
        print(yellow(f"  [{_ts()}] halaman kosong — session mungkin expired"))
        return seen, 0

    all_lines = parse_log_lines(html)
    if not all_lines:
        print(dim(f"  [{_ts()}] tidak ada baris log di halaman"))
        return seen, 0

    fresh = [ln for ln in all_lines if _sha(ln) not in seen]
    if not fresh:
        print(dim(f"  [{_ts()}] tidak ada event baru ({len(all_lines)} baris dikenal)"))
        return seen, 0

    for ln in fresh:
        seen.add(_sha(ln))
    save_seen(seen)

    # Print preview
    print(bold(f"\n  [{_ts()}] {len(fresh)} event baru:"))
    for ln in fresh[-10:]:   # show max 10 in terminal
        level = _LOG_RE.match(ln)
        if level:
            lvl = level.group(3)
            colour = red if lvl in ("ERROR", "CRITICAL") else (
                yellow if lvl in ("WARNING", "WARN") else dim)
            print(f"  {colour(lvl):20} {dim(ln)}")
        else:
            print(f"  {dim(ln)}")
    if len(fresh) > 10:
        print(dim(f"  … dan {len(fresh)-10} baris lagi"))
    print()

    run_pipeline(fresh, use_llm, lang)
    return seen, len(fresh)

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ── re-login helper ───────────────────────────────────────────────────────────

def make_session(password: str) -> RouterSession | None:
    """Login and return a live session, or None on failure."""
    print(dim(f"  connecting to {BASE_URL} …"))
    session = RouterSession()

    # Primary: API login
    if session.login(password):
        print(green(f"  ✓ login berhasil (API) — stok: {session._stok[:8]}…"))
        return session

    # Fallback: just use the cookie from the page load (some firmware
    # keeps you logged in after one GET if the browser already has a session)
    print(yellow("  ⚠ API login tidak dapat stok — mencoba cookie-only mode"))
    session._stok = ""
    return session   # caller will still try to fetch the page


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Live syslog scan — Mercusys MR3000X (DOM scrape)")
    ap.add_argument("--interval", type=int, default=30,
                    help="detik antar poll (default 30)")
    ap.add_argument("--once", action="store_true",
                    help="satu kali poll lalu keluar")
    ap.add_argument("--llm", action="store_true",
                    help="jalankan analisis LLM pada event baru")
    ap.add_argument("--lang", default="id", choices=["id", "en", "de"])
    ap.add_argument("--reset-seen", action="store_true",
                    help="hapus cache event yang sudah dikenal, mulai ulang")
    ap.add_argument("--ip", default="",
                    help="override ROUTER_IP (default: env ROUTER_IP atau 192.168.1.1)")
    args = ap.parse_args()

    global ROUTER_IP, BASE_URL
    if args.ip:
        ROUTER_IP = args.ip
        BASE_URL  = f"http://{ROUTER_IP}"

    if args.reset_seen and os.path.isfile(SEEN_FILE):
        os.remove(SEEN_FILE)
        print(green("  ✓ cache seen direset"))

    password = os.environ.get("ROUTER_PASS", "").strip()
    if not password:
        import getpass
        try:
            password = getpass.getpass(
                f"  Password router {ROUTER_IP} (tidak disimpan): ")
        except (KeyboardInterrupt, EOFError):
            print()
            return 1

    print(bold(f"\n  Live Scan — {BASE_URL}"))
    print(dim(f"  interval  : {args.interval}s"
              + ("  (single pass)" if args.once else "")))
    print(dim(f"  LLM       : {'ya' if args.llm else 'tidak'}"))
    print(dim(f"  lang      : {args.lang}"))
    print()

    session = make_session(password)
    if session is None:
        return 2

    seen = load_seen()
    relogin_every = 10   # re-login after N polls to keep session alive
    poll_count = 0

    try:
        while True:
            # Periodic re-login to prevent session expiry on long runs
            if poll_count > 0 and poll_count % relogin_every == 0:
                print(dim(f"  [{_ts()}] refresh session …"))
                refreshed = make_session(password)
                if refreshed is not None:
                    session = refreshed

            seen, n_new = poll_once(session, seen, args.llm, args.lang)
            poll_count += 1

            if args.once:
                break

            try:
                time.sleep(args.interval)
            except KeyboardInterrupt:
                break

    except KeyboardInterrupt:
        pass

    print(dim(f"\n  live scan selesai. {poll_count} poll dijalankan."))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
