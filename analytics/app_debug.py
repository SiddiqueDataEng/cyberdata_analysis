"""Debug wrapper — shows exactly where app.py crashes."""
import streamlit as st
st.set_page_config(page_title="DEBUG", layout="wide")

import traceback, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

steps = []

def step(label, fn):
    try:
        result = fn()
        steps.append(("✅", label))
        return result
    except Exception as e:
        steps.append(("❌", f"{label} → {e}"))
        for s, l in steps:
            st.write(f"{s} {l}")
        st.error(f"**CRASHED AT: {label}**\n\n```\n{traceback.format_exc()}\n```")
        st.stop()

step("import duckdb",         lambda: __import__("duckdb"))
step("import pandas",         lambda: __import__("pandas"))
step("import plotly",         lambda: __import__("plotly"))
step("import config",         lambda: __import__("config"))
step("import analytics_helpers", lambda: __import__("analytics_helpers"))
step("import tooltips",       lambda: __import__("tooltips"))

import duckdb, pandas as pd
from config import DB_PATH

con = step("duckdb.connect",  lambda: duckdb.connect(DB_PATH, read_only=True))

step("session_state con",     lambda: setattr(st.session_state, "con", con))

step("query mart_kpi_daily",  lambda: con.execute("SELECT MIN(event_date)::DATE AS mn, MAX(event_date)::DATE AS mx FROM mart_kpi_daily").df())

dr  = step("get date range",  lambda: con.execute("SELECT MIN(event_date)::DATE AS mn, MAX(event_date)::DATE AS mx FROM mart_kpi_daily").df())
mn  = step("parse mn",        lambda: pd.to_datetime(dr["mn"].iloc[0]).date())
mx  = step("parse mx",        lambda: pd.to_datetime(dr["mx"].iloc[0]).date())

step("inject_css",            lambda: __import__("tooltips").inject_css())

from analytics_helpers import fmt_number, color_risk, render_nlp_page, render_story_dss
step("fmt_number",            lambda: fmt_number(12345))
step("color_risk",            lambda: color_risk(55.0))

step("sidebar radio",         lambda: st.sidebar.radio("Nav", ["A","B"]))

DRANGE = f"event_date BETWEEN '{mn}' AND '{mx}'"
step("kpi query",             lambda: con.execute(f"SELECT SUM(total_events) AS te FROM mart_kpi_daily WHERE {DRANGE}").df())

# All passed
for s, l in steps:
    st.write(f"{s} {l}")
st.success("ALL STEPS PASSED — app.py should work. Check for Streamlit version conflict.")
