"""
Downloads cyber_warehouse.duckdb from Google Drive using gdown.
File ID: 17TOT65H_Zml2FKRJbi-tfPMay0n4XzUu
"""
import os, sys
from pathlib import Path

# Hardcoded Google Drive file ID for cyber_warehouse.duckdb
DUCKDB_FILE_ID = "17TOT65H_Zml2FKRJbi-tfPMay0n4XzUu"


def download_warehouse(db_path: str, progress_cb=None) -> bool:
    """
    Download the DuckDB warehouse to db_path using gdown.
    Returns True on success.
    """
    def _p(pct, msg):
        if progress_cb:
            progress_cb(pct, msg)

    # Allow override via secrets/env
    file_id = _get_secret("GDRIVE_DUCKDB_ID") or DUCKDB_FILE_ID

    _p(10, "⬇️  Connecting to Google Drive…")

    try:
        import gdown
    except ImportError:
        _p(10, "📦 Installing gdown…")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "gdown", "-q"])
        import gdown

    url = f"https://drive.google.com/uc?id={file_id}"
    _p(20, "⬇️  Downloading warehouse (~200 MB). Please wait…")

    try:
        out = gdown.download(url, db_path, quiet=False, fuzzy=True)
        if out and os.path.exists(db_path) and os.path.getsize(db_path) > 50_000:
            size_mb = os.path.getsize(db_path) / 1e6
            _p(100, f"✅ Download complete — {size_mb:.0f} MB")
            return True
        else:
            _p(100, "❌ Download produced empty file")
            return False
    except Exception as e:
        raise RuntimeError(f"gdown download failed: {e}") from e


def _get_secret(key: str) -> str:
    try:
        import streamlit as st
        v = st.secrets.get(key, "")
        if v:
            return v
    except Exception:
        pass
    return os.environ.get(key, "")
