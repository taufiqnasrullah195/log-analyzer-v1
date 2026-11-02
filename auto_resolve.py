"""auto_resolve.py — apply generated fixes automatically, behind hard gates.

Turning "here is the fix script" into "the fix is applied" is where an
analysis tool becomes something that can take a network down. The design keeps
that risk visible and bounded:

  * DRY-RUN IS THE DEFAULT. Nothing executes without an explicit --apply.
  * ONLY `auto_safe` PLANS RUN. `fix_generator.auto_applicable()` decides;
    memory exhaustion, admin-shutdown and everything else stays manual.
  * ONE DEVICE IS LOCKED WHILE A RUN IS IN FLIGHT, so two collectors cannot
    apply the same fix to the same box concurrently.
  * EVERY RUN IS AUDITED to an append-only JSONL file, including dry-runs —
    "what did the tool do at 03:00" must always have an answer.
  * THE TRANSPORT IS PLUGGABLE. dry-run and clipboard need no dependency and
    work today; ssh needs paramiko and is marked untested until a device with
    SSH actually exists.

    python auto_resolve.py logs/01_pt_router.log                 # dry-run
    python auto_resolve.py logs/01_pt_router.log --transport clipboard
    python auto_resolve.py logs/01_pt_router.log --transport ssh --host 10.0.0.1 --apply
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import fix_generator
import issue_rules

HERE = os.path.dirname(os.path.abspath(__file__))
AUDIT = os.path.join(HERE, "auto_resolve_audit.jsonl")
LOCK_DIR = os.path.join(HERE, ".locks")
MAX_COMMANDS = 60           # a fix plan that renders more than this is a bug
PROMPT_WAIT = 0.45          # seconds between CLI commands on a slow console


# ── plan ────────────────────────────────────────────────────────────────────

@dataclass
class ResolvePlan:
    device: str
    severity: str
    commands: list[str] = field(default_factory=list)
    applied_ids: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def build_plan(log_text: str, device: str = "") -> ResolvePlan:
    """Decide what, if anything, may be applied unattended."""
    issues = issue_rules.scan(log_text)
    severity = issue_rules.worst_severity(issues)
    plan = ResolvePlan(device=device or "(unknown)", severity=severity)

    if not issues:
        plan.skipped.append("tidak ada pola masalah yang cocok")
        return plan

    safe = fix_generator.auto_applicable(issues)
    if not safe:
        plan.skipped.append(
            "semua masalah butuh manusia (tidak ada fix plan yang auto_safe)")
        return plan

    # Refuse to touch a device that is already in a critical state. The
    # auto_safe plans are individually reversible, but "reversible" is not the
    # same as "safe to do while the box is failing" — a memory-starved or
    # crash-looping device needs a human looking at it.
    if severity == "CRITICAL":
        plan.skipped.append(
            "severity CRITICAL — auto-apply dimatikan; yang sebenarnya auto_safe "
            f"({', '.join(i.rule.id for i in safe)}) sengaja ditahan sampai "
            "seorang manusia sudah melihat perangkatnya")
        return plan

    for issue in safe:
        fp = fix_generator.FIX_LIBRARY[issue.rule.id]
        # Reuse the generator's own substitution so executed commands are
        # byte-identical to what the operator was shown.
        values = fix_generator._entity_map(issue)
        for cmd in fp.fix:
            plan.commands.append(fix_generator._fill(cmd, values))
        plan.applied_ids.append(issue.rule.id)

    not_safe = [i for i in issues if i not in safe]
    for issue in not_safe:
        fp = fix_generator.FIX_LIBRARY.get(issue.rule.id)
        why = "tidak ada fix plan" if fp is None else (
            "tidak auto_safe" if not fp.auto_safe else "tidak ada perintah")
        plan.skipped.append(f"{issue.rule.id} ({why})")

    return plan


# ── lock ────────────────────────────────────────────────────────────────────

def _lock_path(device: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in device)
    return os.path.join(LOCK_DIR, f"{safe}.lock")


def acquire_lock(device: str) -> bool:
    os.makedirs(LOCK_DIR, exist_ok=True)
    path = _lock_path(device)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    os.write(fd, f"{os.getpid()} {datetime.now(timezone.utc).isoformat()}\n".encode())
    os.close(fd)
    return True


def release_lock(device: str) -> None:
    try:
        os.remove(_lock_path(device))
    except OSError:
        pass


# ── audit ───────────────────────────────────────────────────────────────────

def audit(record: dict) -> None:
    """Append-only. Never raises — losing an audit line must not abort a fix."""
    record["ts"] = datetime.now(timezone.utc).isoformat()
    try:
        with open(AUDIT, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"[audit] gagal tulis: {exc}", file=sys.stderr)


# ── transports ──────────────────────────────────────────────────────────────

class DryRun:
    name = "dry-run"
    needs_apply = False

    def send(self, plan: ResolvePlan, opts) -> tuple[bool, str]:
        print(f"\n  [DRY-RUN] {plan.device} — {len(plan.commands)} perintah "
              f"TIDAK dijalankan:")
        for c in plan.commands:
            print(f"      | {c}")
        return True, "dry-run"


class Clipboard:
    """Real, testable transport: push the fix to the clipboard for pasting
    into a console/Packet Tracer CLI. No SSH, no dependency, no device needed."""
    name = "clipboard"
    needs_apply = False

    def send(self, plan: ResolvePlan, opts) -> tuple[bool, str]:
        payload = "\r\n".join(plan.commands) + "\r\n"
        if shutil.which("clip.exe"):
            p = subprocess.run("clip.exe", input=payload.encode("utf-16-le"),
                               shell=False)
            if p.returncode != 0:
                return False, f"clip.exe exit {p.returncode}"
        elif shutil.which("xclip"):
            subprocess.run(["xclip", "-selection", "clipboard"],
                           input=payload.encode())
        else:
            return False, "tidak ada clip.exe/xclip di PATH"
        print(f"\n  [CLIPBOARD] {len(plan.commands)} perintah siap. "
              f"Fokuskan CLI device lalu klik Paste / Ctrl+V.")
        return True, "clipboard"


class SSH:
    """paramiko transport. UNTESTED — no device with SSH:22 exists in this
    environment yet. Kept behind an explicit --transport ssh and --apply."""
    name = "ssh"
    needs_apply = True

    def send(self, plan: ResolvePlan, opts) -> tuple[bool, str]:
        try:
            import paramiko
        except ImportError:
            return False, "paramiko belum terpasang (pip install paramiko)"

        user = opts.user or os.environ.get("DEVICE_USER", "")
        password = opts.password or os.environ.get("DEVICE_PASS", "")
        if not user:
            return False, "user device kosong (--user atau DEVICE_USER)"
        if not password:
            import getpass
            password = getpass.getpass(f"password SSH untuk {user}@{opts.host}: ")

        client = paramiko.SSHClient()
        if opts.ssh_strict:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            # Lab convenience. Documented, not silent.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(opts.host, port=opts.port, username=user,
                           password=password, look_for_keys=False,
                           allow_agent=False, timeout=15)
        except Exception as exc:
            return False, f"connect gagal: {type(exc).__name__}: {exc}"

        sent = []
        try:
            shell = client.invoke_shell()
            time.sleep(PROMPT_WAIT)
            shell.recv(65535)
            for cmd in plan.commands:
                shell.send((cmd + "\n").encode())
                time.sleep(PROMPT_WAIT)
                chunk = shell.recv(65535).decode(errors="replace")
                sent.append(cmd)
                low = chunk.lower()
                if "% invalid input" in low or "error" in low or "incomplete" in low:
                    return False, f"perintah ditolak: {cmd!r} -> {chunk.strip()[:160]}"
        except Exception as exc:
            return False, f"eksekusi gagal setelah {len(sent)} perintah: {exc}"
        finally:
            client.close()

        return True, f"{len(sent)} perintah terkirim via ssh"


TRANSPORTS = {t.name: t for t in (DryRun(), Clipboard(), SSH())}


# ── orchestration ───────────────────────────────────────────────────────────

def resolve(log_text: str, device: str, transport_name: str,
            opts) -> int:
    plan = build_plan(log_text, device)
    transport = TRANSPORTS[transport_name]

    print(f"\n{'=' * 66}")
    print(f"  DEVICE    : {plan.device}")
    print(f"  SEVERITY  : {plan.severity}")
    print(f"  TRANSPORT : {transport.name}")
    print(f"  MODE      : {'APPLY' if (opts.apply and transport.needs_apply) else 'DRY-RUN'}")
    print(f"{'=' * 66}")

    if plan.applied_ids:
        print(f"  auto-fix  : {', '.join(plan.applied_ids)}")
    if plan.skipped:
        for s in plan.skipped:
            print(f"  manual    : {s}")

    if not plan.commands:
        print("\n  >> tidak ada yang bisa di-auto-solve untuk log ini.")
        audit({"device": plan.device, "transport": transport.name,
               "mode": "noop", "severity": plan.severity,
               "commands": [], "ok": True, "detail": "no applicable fix"})
        return 0

    if len(plan.commands) > MAX_COMMANDS:
        print(f"\n  !! {len(plan.commands)} perintah > batas {MAX_COMMANDS} — dibatalkan.")
        audit({"device": plan.device, "transport": transport.name,
               "mode": "aborted", "severity": plan.severity,
               "commands": plan.commands, "ok": False,
               "detail": "command count over cap"})
        return 3

    # The gate that matters: SSH changes a real box, so it needs --apply.
    if transport.needs_apply and not opts.apply:
        print("\n  >> transport ssh butuh --apply. Menampilkan dry-run dulu:\n")
        TRANSPORTS["dry-run"].send(plan, opts)
        audit({"device": plan.device, "transport": "dry-run(gated)",
               "mode": "dry-run", "severity": plan.severity,
               "commands": plan.commands, "ok": True,
               "detail": "--apply not given"})
        return 0

    if transport.needs_apply:
        if not acquire_lock(plan.device):
            print(f"\n  !! lock aktif untuk {plan.device} — ada run lain. Dibatalkan.")
            audit({"device": plan.device, "transport": transport.name,
                   "mode": "aborted", "severity": plan.severity,
                   "commands": plan.commands, "ok": False,
                   "detail": "device locked"})
            return 4
        try:
            ok, detail = transport.send(plan, opts)
        finally:
            release_lock(plan.device)
    else:
        ok, detail = transport.send(plan, opts)

    print(f"\n  >> {'OK' if ok else 'GAGAL'}: {detail}")
    audit({"device": plan.device, "transport": transport.name,
           "mode": "apply" if transport.needs_apply else "dry-run",
           "severity": plan.severity, "commands": plan.commands,
           "ok": ok, "detail": detail})
    return 0 if ok else 5


def main() -> int:
    ap = argparse.ArgumentParser(
        description="LogAnalyzer V1 — auto-resolve (dry-run by default)")
    ap.add_argument("logfile", help="log file to scan")
    ap.add_argument("--device", default="", help="device name for the audit trail")
    ap.add_argument("--transport", choices=sorted(TRANSPORTS), default="dry-run")
    ap.add_argument("--apply", action="store_true",
                    help="actually execute (required for ssh)")
    ap.add_argument("--host", default="", help="ssh target host")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--user", default="")
    ap.add_argument("--password", default="", help="prefer DEVICE_PASS env var")
    ap.add_argument("--ssh-strict", action="store_true",
                    help="require the host key in known_hosts")
    args = ap.parse_args()

    if args.transport == "ssh" and not args.host:
        print("error: --transport ssh butuh --host", file=sys.stderr)
        return 2

    try:
        with open(args.logfile, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return resolve(text, args.device or os.path.basename(args.logfile),
                   args.transport, args)


if __name__ == "__main__":
    raise SystemExit(main())