"""
router_log_poller.py — Tier 3 poller for MERCUSYS MR3000X (LuCI API).

Recon-verified endpoints (2026-10-24, live probe):
  base   : http://192.168.1.1/cgi-bin/luci/;stok=<TOKEN>/
  log    : /admin/syslog?form=list        -> {"data":"..."} when authed
           /admin/syslog?form=save_log    -> {"success":false,"errorcode":"timeout"} unauth
  auth   : /login?form=auth | keys | get_token | password | vercode
  crypt  : RSA challenge-response (nn=modulus, ee=exponent, seq) via tpEncrypt.js

CREDENTIALS: never hardcode. Password is read from the ROUTER_PASS env var
at runtime, or typed into the local prompt. Nothing is written to disk.

Usage:
  # A) one-shot poll with a token you copied from the browser URL
  python router_log_poller.py --mode token --token <STOK> --once

  # B) full login then continuous poll (needs valid handshake; see Step 1)
  set ROUTER_PASS=yourpassword
  python router_log_poller.py --mode login --interval 30

  # C) dry run — show raw API responses only (no analyzer call)
  python router_log_poller.py --mode recon
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

ROUTER_IP = os.environ.get("ROUTER_IP", "192.168.1.1")
BASE = f"http://{ROUTER_IP}/cgi-bin/luci/;stok="
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".poller_seen.json")
ANALYZER_DIR = r"C:\Users\taufi\Desktop\LogAnalyzer_V1"


# ── HTTP helpers ────────────────────────────────────────────────────────────

def _req(path: str, token: str = "", data: dict | None = None,
         timeout: int = 8) -> tuple[int, str]:
    """POST/GET a LuCI callback. Returns (status, body). Never swallows errors."""
    url = BASE + (f"{token}/" if token else "/") + path.lstrip("/")
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "User-Agent": UA,
            "Referer": f"http://{ROUTER_IP}/webpages/index.html",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode(errors="replace")


def _json(path: str, token: str = "", data: dict | None = None) -> dict:
    try:
        _, body = _req(path, token, data)
        return json.loads(body)
    except Exception as exc:
        return {"_error": f"{type(exc).__name__}: {exc}"}


# ── auth ────────────────────────────────────────────────────────────────────

def fetch_challenge() -> dict:
    """Step 1 of the TP-Link/Mercusys handshake: the RSA modulus/exponent + seq."""
    for form in ("auth", "keys", "get_token"):
        r = _json(f"/login?form={form}")
        if r and r.get("success") and r.get("data"):
            return r["data"]
        # also try POST — some firmware only dispatches login callbacks on POST
        r = _json(f"/login?form={form}", data={})
        if r and r.get("success") and r.get("data"):
            return r["data"]
    return {}


def _rsa_encrypt_hex(password: str, nn_hex: str, ee_hex: str) -> str:
    """Raw RSA encrypt of the password using the router's modulus/exponent.

    Pure-python pow() — no external RSA lib needed. Router sends nn/ee as hex.
    """
    nn = int(nn_hex, 16)
    ee = int(ee_hex, 16)
    msg = int.from_bytes(password.encode(), "big")
    # PKCS#1-ish left pad so the block is shorter than the modulus
    k = (nn.bit_length() + 7) // 8
    if msg >= nn:
        msg = int.from_bytes(hashlib.sha256(password.encode()).digest(), "big")
    enc = pow(msg, ee, nn)
    return f"{enc:0{2 * k}x}"


def login(password: str) -> str:
    """Return a stok token, or '' on failure (never raises — caller decides)."""
    challenge = fetch_challenge()
    if not challenge:
        print("[login] no challenge returned — capture the real request from the "
              "browser (F12 > Network > login?form=auth > Copy as cURL).")
        return ""

    # Challenge shape varies: {"seq":N,"key":[["nn",..],["ee",..]]} or flat "nn"/"ee"
    key = challenge.get("key") or []
    nn = ee = None
    if isinstance(key, list):
        kv = {k: v for k, v in key}
        nn, ee = kv.get("nn"), kv.get("ee")
    nn = nn or challenge.get("nn")
    ee = ee or challenge.get("ee")
    seq = challenge.get("seq", "")

    if not (nn and ee):
        print(f"[login] unexpected challenge shape: {json.dumps(challenge)[:300]}")
        return ""

    sign = _rsa_encrypt_hex(password, nn, ee)
    for payload in (
        {"sign": sign, "seq": seq},          # digest variant
        {"password": sign, "seq": seq, "confirm": "true"},  # plain variant
    ):
        r = _json("/login?form=auth", data=payload)
        stok = (r.get("data") or {}).get("stok") if isinstance(r.get("data"), dict) else None
        if r.get("success") and stok:
            return stok
        print(f"[login] attempt -> {json.dumps(r)[:200]}")
    return ""


# ── log fetch ───────────────────────────────────────────────────────────────

def fetch_log(token: str) -> str:
    """Return the router's syslog text (may be JSON-wrapped).'' for nothing."""
    for form in ("list", "save_log", "export"):
        r = _json(f"/admin/syslog?form={form}", token)
        data = r.get("data")
        if isinstance(data, str) and data.strip():
            return data
        if isinstance(data, list) and data:
            return "\n".join(str(x) for x in data)
    return ""


# ── dedupe + pipeline ───────────────────────────────────────────────────────

def load_seen() -> set[str]:
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            return set(json.load(fh))
    except Exception:
        return set()


def save_seen(seen: set[str]) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(sorted(seen), fh)


def analyze(log_text: str) -> None:
    """Hand the new log lines to LogAnalyzer_V1's CLI."""
    tmp = os.path.join(ANALYZER_DIR, "router_syslog_live.txt")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(log_text)
    print(f"[analyze] {len(log_text.splitlines())} lines -> {tmp}\n")
    subprocess.run(
        [sys.executable, "cli.py", tmp, "--lang", "id"],
        cwd=ANALYZER_DIR,
    )


# ── modes ───────────────────────────────────────────────────────────────────

def mode_recon() -> None:
    print("=== unauthenticated recon ===")
    print("challenge:", json.dumps(fetch_challenge())[:400])
    print("syslog list :", json.dumps(_json("/admin/syslog?form=list"))[:200])
    print("syslog save :", json.dumps(_json("/admin/syslog?form=save_log"))[:200])


def main() -> int:
    ap = argparse.ArgumentParser(description="MR3000X LuCI log poller")
    ap.add_argument("--mode", choices=["recon", "token", "login"], default="recon")
    ap.add_argument("--token", default="", help="stok copied from the browser URL")
    ap.add_argument("--interval", type=int, default=30, help="poll seconds")
    ap.add_argument("--once", action="store_true", help="single pass then exit")
    args = ap.parse_args()

    if args.mode == "recon":
        mode_recon()
        return 0

    token = args.token
    if args.mode == "login":
        pw = os.environ.get("ROUTER_PASS", "")
        if not pw:
            import getpass
            pw = getpass.getpass("router admin password (not stored): ")
        token = login(pw)
        if not token:
            print("login failed — see Step 1 of the Tier 3 plan (capture handshake).")
            return 2
        print(f"[login] token acquired: {token[:8]}…")

    seen = load_seen()
    while True:
        raw = fetch_log(token)
        if not raw:
            print("[poll] no data (token expired or no log entries)")
        else:
            fresh = [ln for ln in raw.splitlines() if ln.strip() and
                     hashlib.sha1(ln.encode()).hexdigest()[:16] not in seen]
            if fresh:
                for ln in fresh:
                    seen.add(hashlib.sha1(ln.encode()).hexdigest()[:16])
                save_seen(seen)
                analyze("\n".join(fresh))
            else:
                print(f"[poll] {time.strftime('%H:%M:%S')} — no new events")
        if args.once:
            break
        time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())