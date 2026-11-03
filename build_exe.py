"""build_exe.py — PyInstaller onefile/windowed build for LogAnalyzer.

The exe embeds the local rule engine + GUI; the AI analysis path reads the
vleee key from %LOCALAPPDATA%/hermes/.env (or a .env next to the exe) at
runtime, so no secret is ever baked into the binary.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile", "--windowed",
    "--name=LogAnalyzer",
    f"--distpath={HERE / 'dist'}",
    f"--workpath={HERE / 'build'}",
    f"--specpath={HERE}",
    # openai>=1.x lazily imports httpx/certifi submodules; collect them so
    # the frozen client does not ImportError at first API call.
    "--collect-submodules=openai",
    "--hidden-import=dotenv",
    "--exclude-module=pytest",
    "--exclude-module=gradio",
    "--exclude-module=PIL",
    "--icon=assets/icon.ico",
    "--noconfirm",
    str(HERE / "desktop.py"),
]
r = subprocess.run(cmd, cwd=HERE)
sys.exit(r.returncode)
