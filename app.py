"""Gradio web UI — dark theme, mirrors mockup.html. Run: python app.py -> http://127.0.0.1:7860"""
from __future__ import annotations

import gradio as gr

from analyzer import analyze, detect_vendor

SAMPLES = {
    "Cisco flapping": "samples/cisco_flapping.log",
    "FortiGate deny": "samples/fortigate_deny.log",
    "BGP down": "samples/bgp_down.log",
}


def run_analysis(log_text: str, lang: str):
    if not log_text or not log_text.strip():
        return "⚠ Paste a log first.", "", ""
    det = detect_vendor(log_text)
    detect_md = f"🔍 **Detected:** {det.vendor} · {det.event_count} events · {det.confidence_hits} pattern hits"
    try:
        res = analyze(log_text, lang=lang)
    except Exception as exc:
        return detect_md, f"**ERROR** `{type(exc).__name__}`: {exc}", ""
    stats = f"model: `{res.model}` · tokens: {res.prompt_tokens}+{res.completion_tokens}" \
            + (" · ⚠ input truncated" if res.truncated else "")
    return detect_md, res.analysis, stats


def load_sample(name: str) -> str:
    path = SAMPLES.get(name)
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        return f"-- could not load {path}: {exc}"


CSS = """
body, .gradio-container { background:#0f1117 !important; }
#header { text-align:center; padding:12px 0 4px; }
#header h1 { color:#e6e8ee; font-size:26px; }
#header p { color:#667085; font-size:13px; }
"""

with gr.Blocks(title="LogAnalyzer V1") as demo:
    gr.HTML('<div id="header"><h1>🥔 Log<span style="color:#4f8cff">Analyzer</span> '
            '<small>v1.0</small></h1><p>model: deepseek-flash · via vleee · stateless, nothing stored</p></div>')
    with gr.Row():
        with gr.Column():
            log_in = gr.Textbox(label="📥 Paste Log", lines=18, max_lines=30,
                                placeholder="Paste syslog / console output here...")
            with gr.Row():
                lang = gr.Dropdown([("🇮🇩 Bahasa Indonesia", "id"), ("🇬🇧 English", "en"),
                                    ("🇩🇪 Deutsch", "de")], value="id", label="Output language")
                sample = gr.Dropdown(["(none)", *SAMPLES.keys()], value="(none)",
                                     label="Load sample")
            with gr.Row():
                btn = gr.Button("⚡ Analyze", variant="primary")
                clear = gr.ClearButton([log_in], value="Clear")
            detect_out = gr.Markdown()
        with gr.Column():
            result_out = gr.Markdown(label="🧠 AI Analysis")
            stats_out = gr.Markdown()

    sample.change(load_sample, inputs=sample, outputs=log_in)
    btn.click(run_analysis, inputs=[log_in, lang],
              outputs=[detect_out, result_out, stats_out])

if __name__ == "__main__":
    demo.launch(server_name="127.0.0.1", server_port=7860, theme=gr.themes.Base(), css=CSS)
