"""Shared configuration — works locally and on Streamlit Cloud."""
import os
from pathlib import Path

ROOT     = Path(__file__).parent.parent
_HERE    = Path(__file__).parent

# On Streamlit Cloud → /tmp (downloaded at startup)
# Locally → analytics/cyber_warehouse.duckdb
if os.environ.get("STREAMLIT_SHARING_MODE") or os.path.exists("/mount/src"):
    DB_PATH = "/tmp/cyber_warehouse.duckdb"
else:
    # Local path — always use the file sitting next to this config.py
    _local = _HERE / "cyber_warehouse.duckdb"
    DB_PATH = str(_local)

DATA_DIR    = ROOT / "historical_data"
REPORT_DIR  = _HERE / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

OPENAI_API_KEY = os.environ.get(
    "OPENAI_API_KEY",
    "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"
)

COLORS = {
    "primary": "#4F8EF7", "danger": "#E74C3C", "warning": "#F39C12",
    "success": "#2ECC71", "info": "#1ABC9C", "purple": "#9B59B6",
    "dark": "#2C3E50", "muted": "#95A5A6",
}
ATTACK_COLORS = {
    "apt": "#9B59B6", "ransomware": "#E74C3C",
    "data_exfil": "#E67E22", "cred_theft": "#3498DB",
}
SEVERITY_COLORS = {
    "critical": "#E74C3C", "high": "#E67E22",
    "medium": "#F1C40F", "low": "#2ECC71",
}
