# 🥔 LogAnalyzer V1

AI-powered network log analyzer for 1st-level support. Paste a switch/router/firewall
log → get severity, summary, ranked root causes, and the exact next CLI commands.

## Setup

```bash
cd LogAnalyzer_V1
pip install -r requirements.txt
```

API key: the app reads `HERMES_CUSTOM_API_VLEEE_NET_API_KEY` from a project `.env`,
the environment, or the Hermes `.env` (`%LOCALAPPDATA%\hermes\.env`). Never hardcode it.

## Usage

**Web UI** (recommended):
```bash
python app.py
# open http://127.0.0.1:7860
```

**CLI:**
```bash
python cli.py samples/cisco_flapping.log --lang id
cat some.log | python cli.py --lang de
python cli.py samples/bgp_down.log --detect-only   # vendor detection only, no LLM call
```

## Features

- Vendor auto-detection: Cisco IOS/NX-OS, FortiGate, Juniper, Palo Alto, generic syslog
- Output in Bahasa Indonesia, English, or Deutsch
- Structured analysis: Severity / Summary / Possible Causes / Next Commands / Recommendation
- Stateless: each analysis is one API call, nothing is stored
- Inputs over ~12k chars are head+tail truncated (first errors + latest state kept)

## Files

| File | Purpose |
|---|---|
| `analyzer.py` | core engine: detection + LLM call |
| `cli.py` | terminal front-end |
| `app.py` | Gradio web UI |
| `samples/` | test logs (Cisco flapping, FortiGate deny, Juniper BGP down) |
| `mockup.html` / `mockup.png` | UI design mockup |
