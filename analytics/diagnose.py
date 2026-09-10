"""Diagnose what's failing in the Streamlit app."""
import sys, traceback
sys.path.insert(0, "E:/Cyberdata/analytics")

print("=== Step 1: config ===")
try:
    from config import DB_PATH, COLORS
    print(f"  DB_PATH = {DB_PATH}")
except Exception:
    traceback.print_exc(); sys.exit(1)

print("\n=== Step 2: DuckDB connection ===")
try:
    import duckdb
    con = duckdb.connect(DB_PATH, read_only=True)
    tables = [r[0] for r in con.execute("SHOW TABLES").fetchall()]
    print(f"  Tables ({len(tables)}): {tables}")
    for t in tables:
        n = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"    {t}: {n:,} rows")
    con.close()
except Exception:
    traceback.print_exc(); sys.exit(1)

print("\n=== Step 3: analytics_helpers import ===")
try:
    from analytics_helpers import fmt_number, color_risk, kpi_card
    print("  OK")
except Exception:
    traceback.print_exc()

print("\n=== Step 4: nlp_sql_helper import ===")
try:
    from nlp_sql_helper import EXAMPLE_QUERIES, run_query
    print(f"  OK  ({len(EXAMPLE_QUERIES)} example queries)")
except Exception:
    traceback.print_exc()

print("\n=== Step 5: app.py syntax check ===")
try:
    import ast
    src = open("app.py").read()
    ast.parse(src)
    print("  Syntax OK")
except SyntaxError as e:
    print(f"  SYNTAX ERROR: {e}")
except Exception:
    traceback.print_exc()

print("\n=== Step 6: quick KPI query ===")
try:
    from nlp_sql_helper import run_query
    df, err = run_query("SELECT COUNT(*) AS n FROM mart_kpi_daily")
    if err:
        print(f"  ERROR: {err}")
    else:
        print(f"  mart_kpi_daily rows: {df.iloc[0,0]}")
except Exception:
    traceback.print_exc()

print("\nDone.")
