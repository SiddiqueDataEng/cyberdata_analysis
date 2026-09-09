"""Shared configuration for the cybersecurity analytics pipeline."""

import os
from pathlib import Path

# Paths
ROOT        = Path(__file__).parent.parent
DATA_DIR    = ROOT / "historical_data"
DB_PATH     = str(ROOT / "analytics" / "cyber_warehouse.duckdb")
REPORT_DIR  = ROOT / "analytics" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# OpenAI
OPENAI_API_KEY = os.environ.get(
    "OPENAI_API_KEY",
    "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"
)

# Colour palette — consistent across all charts
COLORS = {
    "primary":   "#4F8EF7",
    "danger":    "#E74C3C",
    "warning":   "#F39C12",
    "success":   "#2ECC71",
    "info":      "#1ABC9C",
    "purple":    "#9B59B6",
    "dark":      "#2C3E50",
    "muted":     "#95A5A6",
}

SEVERITY_COLORS = {
    "critical": "#E74C3C",
    "high":     "#E67E22",
    "medium":   "#F1C40F",
    "low":      "#2ECC71",
    "info":     "#3498DB",
}

ATTACK_COLORS = {
    "apt":             "#9B59B6",
    "ransomware":      "#E74C3C",
    "data_exfil":      "#E67E22",
    "cred_theft":      "#3498DB",
    "brute_force":     "#F39C12",
    "lateral_movement":"#1ABC9C",
}
