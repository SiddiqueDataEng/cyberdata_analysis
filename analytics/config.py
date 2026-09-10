"""
Shared configuration.
Works on Streamlit Cloud (/mount/src/<repo>/analytics/app.py)
and locally (E:\\Cyberdata\\analytics\\app.py).
"""
import os
from pathlib import Path

# ── Resolve paths robustly ────────────────────────────────────────────────────
APP_DIR  = Path(__file__).resolve().parent   # .../analytics/
ROOT_DIR = APP_DIR.parent                    # repo root

# NDJSON source data
DATA_DIR = ROOT_DIR / "historical_data"

# DuckDB warehouse — /tmp is writable on Streamlit Cloud; local uses analytics/
_on_cloud = str(APP_DIR).startswith("/mount") or os.environ.get("STREAMLIT_SHARING_MODE")
DB_PATH   = "/tmp/cyber_warehouse.duckdb" if _on_cloud else str(APP_DIR / "cyber_warehouse.duckdb")

# ── OpenAI API key ────────────────────────────────────────────────────────────
def _get_openai_key():
    # 1. Streamlit secrets (cloud)
    try:
        import streamlit as st
        return st.secrets["OPENAI_API_KEY"]
    except Exception:
        pass
    # 2. Environment variable
    key = os.environ.get("OPENAI_API_KEY", "")
    if key:
        return key
    # 3. Hardcoded fallback
    return "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"

OPENAI_API_KEY = _get_openai_key()

# ── Colour palettes ───────────────────────────────────────────────────────────
COLORS = {
    "primary": "#58a6ff", "danger":  "#f85149", "warning": "#ffa657",
    "success": "#3fb950", "info":    "#1abc9c", "purple":  "#d2a8ff",
    "muted":   "#8b949e",
}
ATTACK_COLORS = {
    "apt": "#d2a8ff", "ransomware": "#f85149",
    "data_exfil": "#ffa657", "cred_theft": "#58a6ff",
}
SEVERITY_COLORS = {
    "critical": "#f85149", "high": "#ffa657",
    "medium":   "#e3b341", "low":  "#3fb950",
}
