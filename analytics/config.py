"""Shared configuration — works locally and on Streamlit Cloud."""
import os
import streamlit as st
from pathlib import Path

# ── Detect environment ────────────────────────────────────────────────────────
# On Streamlit Cloud the app root is /mount/src/<repo>/analytics/
# Locally it's E:\Cyberdata\analytics\
APP_DIR  = Path(__file__).parent          # .../analytics/
ROOT_DIR = APP_DIR.parent                 # .../  (repo root)

# ── Data paths ────────────────────────────────────────────────────────────────
# NDJSON source — on cloud these are committed to the repo or downloaded
DATA_DIR = ROOT_DIR / "historical_data"

# DuckDB warehouse — always in /tmp on cloud (writable), local analytics/ dir
if os.environ.get("HOME", "").startswith("/home") or \
   str(APP_DIR).startswith("/mount"):
    # Cloud / Linux
    DB_PATH = "/tmp/cyber_warehouse.duckdb"
else:
    # Local Windows
    DB_PATH = str(APP_DIR / "cyber_warehouse.duckdb")

# ── OpenAI API Key ────────────────────────────────────────────────────────────
try:
    OPENAI_API_KEY = st.secrets["OPENAI_API_KEY"]
except Exception:
    OPENAI_API_KEY = os.environ.get(
        "OPENAI_API_KEY",
        "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"
    )

# ── Chart colours ─────────────────────────────────────────────────────────────
COLORS = {
    "primary": "#58a6ff", "danger": "#f85149", "warning": "#ffa657",
    "success": "#3fb950", "info":   "#1abc9c", "purple":  "#d2a8ff",
    "muted":   "#8b949e",
}
ATTACK_COLORS = {
    "apt": "#d2a8ff", "ransomware": "#f85149",
    "data_exfil": "#ffa657", "cred_theft": "#58a6ff",
}
SEVERITY_COLORS = {
    "critical": "#f85149", "high": "#ffa657",
    "medium": "#e3b341",   "low":  "#3fb950",
}
