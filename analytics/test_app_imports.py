"""Run every import and top-level call from app.py WITHOUT streamlit."""
import sys, traceback
sys.path.insert(0, '.')

errors = []

def test(label, fn):
    try:
        fn()
        print(f"  OK  {label}")
    except Exception as e:
        print(f"  FAIL {label}: {e}")
        traceback.print_exc()
        errors.append(label)

test("config",            lambda: __import__("config"))
test("analytics_helpers", lambda: __import__("analytics_helpers"))
test("nlp_sql_helper",    lambda: __import__("nlp_sql_helper"))
test("tooltips",          lambda: __import__("tooltips"))

import duckdb, pandas as pd
from config import DB_PATH

test("db connect", lambda: duckdb.connect(DB_PATH, read_only=True).close())

con = duckdb.connect(DB_PATH, read_only=True)

test("mart_kpi_daily",        lambda: con.execute("SELECT * FROM mart_kpi_daily LIMIT 1").df())
test("mart_risk_score_daily", lambda: con.execute("SELECT * FROM mart_risk_score_daily LIMIT 1").df())
test("fact_events",           lambda: con.execute("SELECT * FROM fact_events LIMIT 1").df())
test("mart_attack_summary",   lambda: con.execute("SELECT * FROM mart_attack_summary LIMIT 1").df())
test("mart_host_anomaly",     lambda: con.execute("SELECT * FROM mart_host_anomaly LIMIT 1").df())
test("mart_external_traffic", lambda: con.execute("SELECT * FROM mart_external_traffic LIMIT 1").df())
test("mart_web_error_trend",  lambda: con.execute("SELECT * FROM mart_web_error_trend LIMIT 1").df())

# Test the exact sidebar query that app.py runs first
test("sidebar date query", lambda: con.execute(
    "SELECT MIN(event_date)::DATE AS mn, MAX(event_date)::DATE AS mx FROM mart_kpi_daily"
).df())

# Simulate what happens with DRANGE
dr = con.execute("SELECT MIN(event_date)::DATE AS mn, MAX(event_date)::DATE AS mx FROM mart_kpi_daily").df()
mn = pd.to_datetime(dr["mn"].iloc[0]).date()
mx = pd.to_datetime(dr["mx"].iloc[0]).date()
DRANGE = f"event_date BETWEEN '{mn}' AND '{mx}'"
print(f"\n  DRANGE = {DRANGE}")

test("kpi query with DRANGE", lambda: con.execute(f"""
    SELECT SUM(total_events) AS te, SUM(ids_alerts) AS ia,
    SUM(attack_events) AS ae, SUM(auth_failures) AS af, SUM(fw_drops) AS fd,
    ROUND(AVG(active_hosts),0) AS ah, ROUND(SUM(total_bytes)/1e9,2) AS gb,
    SUM(external_connections) AS ec, SUM(ps_executions) AS ps
    FROM mart_kpi_daily WHERE {DRANGE}""").df())

test("render_story_dss import", lambda: None)
from analytics_helpers import render_nlp_page, render_story_dss
print("  render_nlp_page:", render_nlp_page)
print("  render_story_dss:", render_story_dss)

con.close()

print(f"\n{'='*40}")
if errors:
    print(f"FAILED: {errors}")
else:
    print("ALL PASSED — issue is in Streamlit rendering itself")
