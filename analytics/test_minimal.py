import streamlit as st
import duckdb, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from config import DB_PATH

st.title("TEST - Can you see this?")

try:
    con = duckdb.connect(DB_PATH, read_only=True)
    n = con.execute("SELECT COUNT(*) FROM fact_events").fetchone()[0]
    st.success(f"DB connected. fact_events: {n:,} rows")
    df = con.execute("SELECT * FROM mart_kpi_daily LIMIT 5").df()
    st.dataframe(df)
    con.close()
except Exception as e:
    st.error(f"ERROR: {e}")
