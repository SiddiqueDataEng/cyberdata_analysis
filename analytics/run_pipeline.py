"""
Master pipeline runner.
Run this once to build the full warehouse + all analytical marts.
"""
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

def main():
    print("\n" + "="*65)
    print("  CYBERSECURITY DATA ENGINEERING PIPELINE")
    print("="*65)

    t_total = datetime.now()

    # ── ETL ────────────────────────────────────────────────────────────────
    print("\n[1/2] ETL: Loading NDJSON → DuckDB Warehouse...")
    t0 = datetime.now()
    from analytics_01_etl import run_etl
    summary = run_etl(verbose=True)
    print(f"      Completed in {(datetime.now()-t0).total_seconds():.1f}s")

    # ── Analytical ─────────────────────────────────────────────────────────
    print("\n[2/2] Analytical Engineering: Building Data Marts...")
    t0 = datetime.now()
    from analytics_02_analytical import run_analytical
    run_analytical(verbose=True)
    print(f"      Completed in {(datetime.now()-t0).total_seconds():.1f}s")

    print("\n" + "="*65)
    print(f"  Pipeline complete! Total time: {(datetime.now()-t_total).total_seconds():.1f}s")
    print(f"  Warehouse: E:\\Cyberdata\\analytics\\cyber_warehouse.duckdb")
    print("\n  Launch dashboard with:")
    print("  > streamlit run E:\\Cyberdata\\analytics\\app.py")
    print("="*65 + "\n")


# Alias modules so they're importable without analytics. prefix
import importlib.util, sys

def _alias(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / file)
    mod  = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

_alias("analytics_01_etl",        "01_etl.py")
_alias("analytics_02_analytical",  "02_analytical.py")


if __name__ == "__main__":
    main()
