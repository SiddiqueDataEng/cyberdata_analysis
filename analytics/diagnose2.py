"""Check timestamp parsing."""
import sys, duckdb
sys.path.insert(0, "E:/Cyberdata/analytics")
from config import DB_PATH

con = duckdb.connect(DB_PATH, read_only=True)

# Check what _timestamp looks like in raw tables
print("=== raw_network sample timestamps ===")
rows = con.execute("SELECT _timestamp, typeof(_timestamp) FROM raw_network LIMIT 5").fetchall()
for r in rows:
    print(f"  value={r[0]!r}  type={r[1]}")

print("\n=== fact_events event_time sample ===")
rows = con.execute("SELECT event_time, typeof(event_time) FROM fact_events LIMIT 5").fetchall()
for r in rows:
    print(f"  value={r[0]!r}  type={r[1]}")

print("\n=== mart_kpi_daily ===")
rows = con.execute("SELECT * FROM mart_kpi_daily").fetchall()
for r in rows:
    print(f"  {r}")

print("\n=== distinct event_dates in fact_events ===")
rows = con.execute("SELECT DISTINCT DATE_TRUNC('day', event_time)::DATE AS d FROM fact_events ORDER BY d LIMIT 10").fetchall()
for r in rows:
    print(f"  {r[0]}")

print("\n=== fact_events count by log_source ===")
rows = con.execute("SELECT log_source, COUNT(*) FROM fact_events GROUP BY 1 ORDER BY 2 DESC").fetchall()
for r in rows:
    print(f"  {r[0]:20s} {r[1]:>10,}")

con.close()
