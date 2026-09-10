import sys, traceback
sys.path.insert(0, '.')

print("=== DB CHECK ===")
try:
    import duckdb
    from config import DB_PATH
    con = duckdb.connect(DB_PATH, read_only=True)
    tables = [r[0] for r in con.execute("SHOW TABLES").fetchall()]
    print(f"Tables ({len(tables)}): {tables}")

    for t in ["mart_kpi_daily", "mart_risk_score_daily", "fact_events"]:
        if t in tables:
            n = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            print(f"  {t}: {n:,} rows")
        else:
            print(f"  MISSING: {t}")
    con.close()
    print("DB OK")
except Exception:
    traceback.print_exc()

print("\n=== IMPORT CHECK ===")
for mod in ["analytics_helpers", "nlp_sql_helper", "tooltips"]:
    try:
        __import__(mod)
        print(f"  {mod}: OK")
    except Exception as e:
        print(f"  {mod}: FAIL — {e}")

print("\n=== QUERY CHECK ===")
try:
    import duckdb, pandas as pd
    from config import DB_PATH
    con = duckdb.connect(DB_PATH, read_only=True)
    df = con.execute("SELECT MIN(event_date) AS mn, MAX(event_date) AS mx FROM mart_kpi_daily").df()
    print(f"  Date range: {df.iloc[0]['mn']} → {df.iloc[0]['mx']}")
    con.close()
    print("  Query OK")
except Exception:
    traceback.print_exc()
