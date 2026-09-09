"""
LAYER 1 — DATA ENGINEERING (ETL)
Loads all NDJSON files from historical_data/ into a DuckDB warehouse.
Creates raw tables + staging views for every log type.
"""

import duckdb
import json
import os
import sys
import pandas as pd
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from config import DATA_DIR, DB_PATH

# ── helpers ───────────────────────────────────────────────────────────────────

def flatten(obj, prefix="", sep="__"):
    items = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}{sep}{k}" if prefix else k
            if isinstance(v, (dict, list)):
                items.update(flatten(v, new_key, sep))
            else:
                items[new_key] = v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            items.update(flatten(v, f"{prefix}{sep}{i}", sep))
        if not obj:
            items[prefix] = None
    else:
        items[prefix] = obj
    return items


def load_ndjson(filepath: Path) -> list:
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw  = json.loads(line)
                flat = flatten(raw)
                # Normalise timestamp to a single _ts field (string ISO8601)
                ts = (flat.get("@timestamp")
                      or flat.get("event__created")
                      or "")
                flat["_ts"]          = ts
                flat["_source_file"] = filepath.name
                records.append(flat)
            except Exception:
                continue
    return records


def records_to_df(records: list) -> pd.DataFrame:
    if not records:
        return pd.DataFrame()
    all_cols = sorted({k for r in records for k in r.keys()})
    df = pd.DataFrame([{c: r.get(c) for c in all_cols} for r in records])
    # Parse _ts to datetime
    if "_ts" in df.columns:
        df["_ts"] = pd.to_datetime(df["_ts"], errors="coerce", utc=True)
    return df


# ── main ETL ──────────────────────────────────────────────────────────────────

def run_etl(verbose: bool = True):
    con = duckdb.connect(DB_PATH)

    log_types = {
        "network":       "network_*.ndjson",
        "zeek_dns":      "zeek_dns_*.ndjson",
        "suricata":      "suricata_*.ndjson",
        "windows":       "windows_*.ndjson",
        "sysmon":        "sysmon_*.ndjson",
        "powershell":    "powershell_*.ndjson",
        "linux_syslog":  "linux_syslog_*.ndjson",
        "rsyslog":       "rsyslog_structured_*.ndjson",
        "firewall":      "firewall_*.ndjson",
        "threat_intel":  "threat_intel_*.ndjson",
        "application":   "application_*.ndjson",
        "attack_events": "attack_*.ndjson",
    }

    summary = {}
    for table_name, pattern in log_types.items():
        files = sorted(DATA_DIR.glob(pattern))
        if not files:
            if verbose:
                print(f"  [SKIP] {table_name}: no files matching {pattern}")
            continue

        all_records = []
        for fp in files:
            all_records.extend(load_ndjson(fp))

        if not all_records:
            continue

        df = records_to_df(all_records)
        raw_table = f"raw_{table_name}"
        con.execute(f"DROP TABLE IF EXISTS {raw_table}")
        con.execute(f"CREATE TABLE {raw_table} AS SELECT * FROM df")
        n = con.execute(f"SELECT COUNT(*) FROM {raw_table}").fetchone()[0]
        summary[table_name] = n
        if verbose:
            print(f"  [OK] {raw_table:30s} {n:>8,} rows  ({len(files)} files)")

    _build_unified_table(con, verbose)
    _build_staging(con, verbose)

    con.close()
    if verbose:
        print(f"\n  Total rows loaded: {sum(summary.values()):,}")
        print(f"  DuckDB warehouse:  {DB_PATH}")
    return summary


# ── unified fact table ────────────────────────────────────────────────────────

def _col(available: set, *names, default="''"):
    """Return the first available column name cast to VARCHAR, else default."""
    for n in names:
        if n in available:
            return f"COALESCE(CAST({n} AS VARCHAR), '')"
    return default


def _col_ts(available: set):
    """Return TIMESTAMPTZ expression using _ts (our normalised column)."""
    if "_ts" in available:
        return "COALESCE(_ts, NOW())"
    return "NOW()"


def _col_int(available: set, *names):
    for n in names:
        if n in available:
            return f"COALESCE(TRY_CAST({n} AS BIGINT), 0)"
    return "0"


def _get_cols(con, table: str) -> set:
    try:
        rows = con.execute(f"PRAGMA table_info('{table}')").fetchall()
        return {r[1] for r in rows}   # column name is index 1 in PRAGMA result
    except Exception:
        return set()


def _build_unified_table(con, verbose):
    table_specs = [
        # (raw_table,   log_source,    category_hint)
        ("raw_network",       "network",      "network"),
        ("raw_zeek_dns",      "zeek_dns",     "network"),
        ("raw_suricata",      "suricata",     "intrusion_detection"),
        ("raw_windows",       "windows",      "authentication"),
        ("raw_sysmon",        "sysmon",       "process"),
        ("raw_powershell",    "powershell",   "process"),
        ("raw_linux_syslog",  "linux_syslog", "system"),
        ("raw_rsyslog",       "rsyslog",      "system"),
        ("raw_firewall",      "firewall",     "network"),
        ("raw_threat_intel",  "threat_intel", "threat"),
        ("raw_application",   "application",  "web"),
        ("raw_attack_events", "attack",       "attack"),
    ]

    parts = []
    for table, src, cat_hint in table_specs:
        tc = _get_cols(con, table)
        if not tc:
            continue

        ts      = _col_ts(tc)
        dataset = _col(tc, "event__dataset",    default=f"'{src}'")
        kind    = _col(tc, "event__kind",        default="'event'")
        action  = _col(tc, "event__action",      default="''")
        cat     = _col(tc, "event__category__0", "event__category", default=f"'{cat_hint}'")
        src_ip  = _col(tc, "source__ip", "winlog__event_data__IpAddress", default="''")
        dst_ip  = _col(tc, "destination__ip",    default="''")
        src_p   = _col(tc, "source__port",       default="''")
        dst_p   = _col(tc, "destination__port", "http__response__status_code", default="''")
        proto   = _col(tc, "network__protocol",  default="''")
        trans   = _col(tc, "network__transport", default="''")
        dirn    = _col(tc, "network__direction", default="''")
        byt     = _col_int(tc, "network__bytes", "http__response__bytes")
        host    = _col(tc, "host__name", "winlog__computer_name", default="''")
        uname   = _col(tc, "user__name",         default="''")
        atk     = _col(tc, "labels__attack_type",     default="NULL::VARCHAR")
        mitre   = _col(tc, "labels__mitre_technique", default="NULL::VARCHAR")

        parts.append(f"""
    SELECT
        {ts}      AS event_time,
        {dataset} AS dataset,
        {kind}    AS event_kind,
        {action}  AS event_action,
        {cat}     AS event_category,
        {src_ip}  AS src_ip,
        {dst_ip}  AS dst_ip,
        {src_p}   AS src_port,
        {dst_p}   AS dst_port,
        {proto}   AS protocol,
        {trans}   AS transport,
        {dirn}    AS direction,
        {byt}     AS bytes_transferred,
        {host}    AS hostname,
        {uname}   AS username,
        {atk}     AS attack_type,
        {mitre}   AS mitre_technique,
        _source_file AS source_file,
        '{src}'   AS log_source
    FROM {table}""")

    if not parts:
        if verbose:
            print("  [WARN] No raw tables — fact_events not built")
        return

    sql = "CREATE OR REPLACE TABLE fact_events AS\n" + "\n    UNION ALL\n".join(parts)
    con.execute(sql)
    n = con.execute("SELECT COUNT(*) FROM fact_events").fetchone()[0]
    # verify timestamps
    sample = con.execute(
        "SELECT COUNT(DISTINCT DATE_TRUNC('day', event_time)::DATE) FROM fact_events"
    ).fetchone()[0]
    if verbose:
        print(f"\n  [OK] fact_events: {n:,} rows across {sample} distinct days")


# ── staging / dimension tables ────────────────────────────────────────────────

def _build_staging(con, verbose):
    con.execute("""
    CREATE OR REPLACE TABLE dim_time AS
    SELECT DISTINCT
        DATE_TRUNC('day',  event_time)::DATE AS event_date,
        DATE_TRUNC('hour', event_time)       AS event_hour,
        EXTRACT(year   FROM event_time)::INT AS year,
        EXTRACT(month  FROM event_time)::INT AS month,
        EXTRACT(day    FROM event_time)::INT AS day,
        EXTRACT(hour   FROM event_time)::INT AS hour,
        EXTRACT(dow    FROM event_time)::INT AS day_of_week,
        CASE EXTRACT(dow FROM event_time)::INT
            WHEN 0 THEN 'Sunday'   WHEN 1 THEN 'Monday'
            WHEN 2 THEN 'Tuesday'  WHEN 3 THEN 'Wednesday'
            WHEN 4 THEN 'Thursday' WHEN 5 THEN 'Friday'
            WHEN 6 THEN 'Saturday'
        END AS day_name,
        CASE WHEN EXTRACT(dow FROM event_time)::INT IN (0,6)
             THEN FALSE ELSE TRUE END AS is_business_day
    FROM fact_events
    """)

    con.execute("""
    CREATE OR REPLACE TABLE dim_host AS
    SELECT DISTINCT
        hostname,
        CASE
            WHEN hostname LIKE 'WIN%' THEN 'Windows'
            WHEN hostname LIKE 'ubuntu%' OR hostname LIKE 'centos%' THEN 'Linux'
            WHEN hostname LIKE 'web%' OR hostname LIKE 'db%' OR hostname LIKE 'app%' THEN 'Server'
            ELSE 'Unknown'
        END AS os_type,
        CASE
            WHEN hostname LIKE 'web%' THEN 'Web Server'
            WHEN hostname LIKE 'db%'  THEN 'Database'
            WHEN hostname LIKE 'app%' THEN 'App Server'
            WHEN hostname LIKE 'WIN%' THEN 'Workstation'
            ELSE 'General'
        END AS host_role
    FROM fact_events WHERE hostname != ''
    """)

    con.execute("""
    CREATE OR REPLACE VIEW stg_network AS
    SELECT f.*,
        DATE_TRUNC('day', event_time)::DATE AS event_date,
        EXTRACT(hour FROM event_time)::INT  AS hour,
        CASE WHEN src_ip LIKE '192.168.%' OR src_ip LIKE '10.%'
             THEN 'internal' ELSE 'external' END AS src_zone,
        CASE WHEN dst_ip LIKE '192.168.%' OR dst_ip LIKE '10.%'
             THEN 'internal' ELSE 'external' END AS dst_zone
    FROM fact_events f
    WHERE log_source IN ('network','firewall','zeek_dns','suricata')
    """)

    con.execute("""
    CREATE OR REPLACE VIEW stg_auth AS
    SELECT f.*,
        DATE_TRUNC('day', event_time)::DATE AS event_date,
        EXTRACT(hour FROM event_time)::INT  AS hour,
        CASE WHEN event_action LIKE '%Failed%' OR event_action LIKE '%fail%'
             THEN TRUE ELSE FALSE END AS is_failure
    FROM fact_events f
    WHERE log_source IN ('windows','sysmon','powershell')
    """)

    if verbose:
        print("  [OK] dim_time, dim_host, stg_network, stg_auth built")


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("LAYER 1 — ETL: Loading NDJSON → DuckDB Warehouse")
    print("=" * 60)
    t0 = datetime.now()
    run_etl(verbose=True)
    print(f"\nETL completed in {(datetime.now()-t0).total_seconds():.1f}s")
