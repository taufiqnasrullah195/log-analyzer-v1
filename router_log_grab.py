"""router_log_grab.py — pull a router log export into the analyzer, safely.

The router's own UI is the only export path on this firmware (no remote syslog,
no reachable login callback), so the log arrives as a downloaded file. The
obvious implementation — point the folder watcher at Downloads — is dangerous:
a Downloads folder routinely holds recovery phrases, backup codes, wallet
seeds and private keys, and a watcher would feed every one of them to the
analyzer and, with --llm, to a third-party model.

So this tool refuses first and matches second:

  1. A HARD DENYLIST runs before anything else. A filename that looks like a
     secret is skipped permanently, never copied, never read.
  2. Only filenames that look like a device log export are candidates.
  3. Only files modified within --max-age minutes, so a stale download is not
     mistaken for this run's output.
  4. The user is shown the pick before anything leaves the folder.

    python router_log_grab.py                    # list candidates
    python router_log_grab.py --pick 1           # copy it into logs/
    python router_log_grab.py --pick 1 --scan    # copy, then run the pipeline
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
DEST_DIR = os.path.join(HERE, "logs")
HOME = os.path.expanduser("~")
DEFAULT_SOURCES = [
    os.path.join(HOME, "Downloads"),
    os.path.join(HOME, "Desktop"),
]

# Checked FIRST and unconditionally. A filename carrying any of these is never
# a device log, whatever else it matches.
SECRET_HINTS = (
    "recovery", "phrase", "seed", "mnemonic", "backup-code", "backup_code",
    "backup-codes", "backup_codes", "password", "passwd", "private",
    "privkey", "secret", "api-key", "apikey", "token", "2fa", "otp",
    "wallet", "keystore", "credential", "auth", "cert", "pem", "key",
)

# A device log export looks like this.
LOG_HINTS = ("syslog", "systemlog", "system_log", "system-log", "devicelog",
             "device_log", "routerlog", "router_log", "traffic", "diagnostic")
LOG_EXTS = (".log", ".txt", ".csv")


def is_secret(name: str) -> str | None:
    """Return the hint that flagged this filename, or None if it is clean."""
    low = name.lower()
    for hint in SECRET_HINTS:
        if hint in low:
            return hint
    return None


def looks_like_log(name: str) -> bool:
    low = name.lower()
    if not low.endswith(LOG_EXTS):
        return False
    if low.endswith(".fix.txt"):        # our own output
        return False
    return any(h in low for h in LOG_HINTS) or low.endswith(".log")


def find_candidates(sources: list[str], max_age_min: float) -> tuple[list[dict], list[str]]:
    """(candidates, refused). `refused` is reported, never silently dropped."""
    cutoff = time.time() - max_age_min * 60
    found, refused = [], []
    for d in sources:
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            path = os.path.join(d, name)
            if not os.path.isfile(path):
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            age_min = (time.time() - st.st_mtime) / 60
            if age_min > max_age_min or st.st_mtime < cutoff:
                continue

            hint = is_secret(name)
            if hint:
                # Report the refusal so a skipped real log is visible, but
                # never read, copy or hash the file.
                refused.append(f"{name}  (ditolak: mirip rahasia '{hint}')")
                continue
            if not looks_like_log(name):
                continue
            found.append({
                "path": path, "name": name, "size": st.st_size,
                "mtime": st.st_mtime,
                "age_min": round(age_min, 1),
                "modified": datetime.fromtimestamp(st.st_mtime)
                                    .strftime("%Y-%m-%d %H:%M"),
            })
    found.sort(key=lambda c: c["mtime"], reverse=True)
    return found, refused


def grab(src: str, dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    base = os.path.splitext(os.path.basename(src))[0]
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in base)[:40]
    dest = os.path.join(dest_dir, f"router_{stamp}_{safe}.log")
    shutil.copy2(src, dest)
    return dest


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Ambil log hasil export router ke folder logs/ (aman)")
    ap.add_argument("--from", dest="sources", action="append", default=None,
                    help="folder sumber (bisa diulang; default Downloads+Desktop)")
    ap.add_argument("--max-age", type=float, default=60,
                    help="hanya file yang diubah dalam N menit terakhir")
    ap.add_argument("--pick", type=int, default=None,
                    help="nomor kandidat yang diambil")
    ap.add_argument("--scan", action="store_true",
                    help="jalankan pipeline setelah menyalin")
    ap.add_argument("--llm", action="store_true", help="sertakan analisis LLM")
    args = ap.parse_args()

    sources = args.sources or DEFAULT_SOURCES
    found, refused = find_candidates(sources, args.max_age)

    print(f"\n  sumber   : {', '.join(sources)}")
    print(f"  window   : {args.max_age:.0f} menit terakhir")
    print(f"  kandidat : {len(found)}\n")

    if refused:
        print("  DITOLAK karena mirip berkas rahasia (tidak dibaca sama sekali):")
        for r in refused:
            print(f"    x {r}")
        print()

    if not found:
        print("  tidak ada kandidat log. Export dulu dari router (System Log → "
              "SAVE TO LOCAL),\n  lalu jalankan lagi.")
        return 1

    for i, c in enumerate(found, 1):
        kb = c["size"] / 1024
        print(f"   [{i}] {c['name']}")
        print(f"       {kb:,.1f} KB · diubah {c['modified']} ({c['age_min']} menit lalu)")
        print(f"       {c['path']}")
    print()

    if args.pick is None:
        print("  jalankan lagi dengan --pick <nomor> untuk menyalin ke logs/.")
        return 0

    if not (1 <= args.pick <= len(found)):
        print(f"  nomor di luar rentang 1..{len(found)}", file=sys.stderr)
        return 2

    chosen = found[args.pick - 1]
    dest = grab(chosen["path"], DEST_DIR)
    print(f"  ✓ disalin -> {dest}")

    if args.scan:
        cmd = [sys.executable, "auto_scan.py", dest]
        if args.llm:
            cmd += ["--llm", "--lang", "id"]
        print()
        return subprocess.run(cmd, cwd=HERE).returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())