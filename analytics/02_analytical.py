"""
LAYER 2 — ANALYTICAL ENGINEERING
Builds all data marts, KPI tables, aggregations and ML-based anomaly detection.
All results stored back into DuckDB as mart_* tables.
"""

import duckdb
import pandas as pd
import numpy as np
from datetime import datetime
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from config import DB_PATH


def get_con():
    return duckdb.connect(DB_PATH)


# ─────────────────────────────────────────────────────────────────────────────
# MART 1 — Daily KPI Summary
# ─────────────────────────────────────────────────────────────────────────────

def build_kpi_daily(con):
    con.execute("""
    CREATE OR REPLACE TABLE mart_kpi_daily AS
    SELECT
        DATE_TRUNC('day', event_time)           AS event_date,
        COUNT(*)                                AS total_events,
        COUNT(DISTINCT src_ip)                  AS unique_src_ips,
        COUNT(DISTINCT hostname)                AS active_hosts,
        COUNT(DISTINCT username) FILTER (WHERE username != '') AS active_users,
        SUM(bytes_transferred)                  AS total_bytes,
        COUNT(*) FILTER (WHERE log_source='suricata')    AS ids_alerts,
        COUNT(*) FILTER (WHERE log_source='threat_intel') AS threat_intel_hits,
        COUNT(*) FILTER (WHERE log_source='attack')       AS attack_events,
        COUNT(*) FILTER (WHERE log_source='firewall' AND event_action='drop') AS fw_drops,
        COUNT(*) FILTER (WHERE log_source='windows'
            AND event_action LIKE '%Failed%')             AS auth_failures,
        COUNT(*) FILTER (WHERE log_source='windows'
            AND event_action LIKE '%Logon%'
            AND event_action NOT LIKE '%Failed%')         AS successful_logins,
        COUNT(*) FILTER (WHERE log_source='powershell')   AS ps_executions,
        COUNT(*) FILTER (WHERE log_source='zeek_dns')     AS dns_queries,
        COUNT(*) FILTER (WHERE log_source IN ('network','firewall')
            AND dst_ip NOT LIKE '192.168.%'
            AND dst_ip NOT LIKE '10.%')                   AS external_connections
    FROM fact_events
    GROUP BY 1
    ORDER BY 1
    """)


# ─────────────────────────────────────────────────────────────────────────────
# MART 2 — Threat Landscape
# ─────────────────────────────────────────────────────────────────────────────

def build_threat_landscape(con):
    # Attack type summary
    con.execute("""
    CREATE OR REPLACE TABLE mart_attack_summary AS
    SELECT
        attack_type,
        mitre_technique,
        COUNT(*)                                     AS event_count,
        COUNT(DISTINCT hostname)                     AS hosts_affected,
        COUNT(DISTINCT username) FILTER(WHERE username!='') AS users_affected,
        MIN(event_time)                              AS first_seen,
        MAX(event_time)                              AS last_seen,
        DATE_DIFF('minute', MIN(event_time), MAX(event_time)) AS duration_minutes
    FROM fact_events
    WHERE attack_type IS NOT NULL AND attack_type != ''
    GROUP BY 1, 2
    ORDER BY 3 DESC
    """)

    # Suricata alert severity distribution
    con.execute("""
    CREATE OR REPLACE TABLE mart_ids_alerts AS
    SELECT
        DATE_TRUNC('day', event_time) AS event_date,
        event_action                  AS signature,
        COUNT(*)                      AS alert_count,
        COUNT(DISTINCT src_ip)        AS unique_sources,
        COUNT(DISTINCT dst_ip)        AS unique_targets
    FROM fact_events
    WHERE log_source = 'suricata'
    GROUP BY 1, 2
    ORDER BY 1, 3 DESC
    """)

    # Threat intel indicator types
    con.execute("""
    CREATE OR REPLACE TABLE mart_threat_intel AS
    SELECT
        DATE_TRUNC('day', event_time) AS event_date,
        COUNT(*)                      AS indicator_count,
        COUNT(*) FILTER(WHERE source_file LIKE '%threat_intel%') AS ti_feed_events
    FROM fact_events
    WHERE log_source = 'threat_intel'
    GROUP BY 1
    ORDER BY 1
    """)


# ─────────────────────────────────────────────────────────────────────────────
# MART 3 — Network Analytics
# ─────────────────────────────────────────────────────────────────────────────

def build_network_analytics(con):
    # Top talkers
    con.execute("""
    CREATE OR REPLACE TABLE mart_top_talkers AS
    SELECT
        src_ip,
        COUNT(*)                 AS connection_count,
        SUM(bytes_transferred)   AS total_bytes,
        COUNT(DISTINCT dst_ip)   AS unique_destinations,
        COUNT(DISTINCT dst_port) AS unique_dest_ports,
        COUNT(DISTINCT protocol) AS protocols_used,
        MIN(event_time)          AS first_seen,
        MAX(event_time)          AS last_seen
    FROM fact_events
    WHERE log_source IN ('network','firewall')
      AND src_ip != ''
    GROUP BY 1
    ORDER BY 2 DESC
    """)

    # Protocol distribution
    con.execute("""
    CREATE OR REPLACE TABLE mart_protocol_dist AS
    SELECT
        protocol,
        DATE_TRUNC('day', event_time) AS event_date,
        COUNT(*)                      AS event_count,
        SUM(bytes_transferred)        AS total_bytes,
        AVG(bytes_transferred)        AS avg_bytes
    FROM fact_events
    WHERE protocol != ''
    GROUP BY 1, 2
    ORDER BY 2, 3 DESC
    """)

    # Port scan detection: IPs hitting many ports
    con.execute("""
    CREATE OR REPLACE TABLE mart_port_scan_suspects AS
    SELECT
        src_ip,
        DATE_TRUNC('hour', event_time) AS hour_window,
        COUNT(DISTINCT dst_port)       AS unique_ports_targeted,
        COUNT(DISTINCT dst_ip)         AS unique_hosts_targeted,
        COUNT(*)                       AS total_attempts,
        CASE WHEN COUNT(DISTINCT dst_port) > 20 THEN 'HIGH'
             WHEN COUNT(DISTINCT dst_port) > 10 THEN 'MEDIUM'
             ELSE 'LOW' END            AS scan_risk_level
    FROM fact_events
    WHERE log_source IN ('network','firewall')
      AND src_ip != '' AND dst_port != ''
    GROUP BY 1, 2
    HAVING COUNT(DISTINCT dst_port) > 5
    ORDER BY 3 DESC
    """)

    # External traffic flow
    con.execute("""
    CREATE OR REPLACE TABLE mart_external_traffic AS
    SELECT
        DATE_TRUNC('hour', event_time)  AS hour_window,
        COUNT(*) FILTER(WHERE src_ip NOT LIKE '192.168.%'
                        AND src_ip NOT LIKE '10.%') AS inbound_external,
        COUNT(*) FILTER(WHERE dst_ip NOT LIKE '192.168.%'
                        AND dst_ip NOT LIKE '10.%') AS outbound_external,
        SUM(bytes_transferred)          AS total_bytes
    FROM fact_events
    WHERE log_source IN ('network','firewall')
    GROUP BY 1
    ORDER BY 1
    """)


# ─────────────────────────────────────────────────────────────────────────────
# MART 4 — Authentication & Identity
# ─────────────────────────────────────────────────────────────────────────────

def build_auth_analytics(con):
    # Brute force suspects: many failures from same IP
    con.execute("""
    CREATE OR REPLACE TABLE mart_brute_force AS
    SELECT
        src_ip,
        username,
        DATE_TRUNC('hour', event_time)  AS hour_window,
        COUNT(*)                        AS failure_count,
        COUNT(DISTINCT hostname)        AS targets,
        CASE WHEN COUNT(*) > 50 THEN 'CRITICAL'
             WHEN COUNT(*) > 20 THEN 'HIGH'
             WHEN COUNT(*) > 10 THEN 'MEDIUM'
             ELSE 'LOW' END             AS severity
    FROM fact_events
    WHERE log_source = 'windows'
      AND event_action LIKE '%Failed%'
      AND src_ip != ''
    GROUP BY 1, 2, 3
    HAVING COUNT(*) > 3
    ORDER BY 4 DESC
    """)

    # Login success vs failure over time
    con.execute("""
    CREATE OR REPLACE TABLE mart_auth_trend AS
    SELECT
        DATE_TRUNC('day', event_time)   AS event_date,
        hostname,
        COUNT(*) FILTER(WHERE event_action LIKE '%Failed%') AS failures,
        COUNT(*) FILTER(WHERE event_action LIKE '%Logon%'
            AND event_action NOT LIKE '%Failed%')           AS successes,
        ROUND(
            COUNT(*) FILTER(WHERE event_action LIKE '%Failed%') * 100.0
            / NULLIF(COUNT(*), 0), 2
        )                               AS failure_rate_pct
    FROM fact_events
    WHERE log_source = 'windows'
    GROUP BY 1, 2
    ORDER BY 1, 5 DESC
    """)

    # After-hours logins
    con.execute("""
    CREATE OR REPLACE TABLE mart_afterhours_logins AS
    SELECT
        username,
        hostname,
        event_time,
        EXTRACT(hour FROM event_time)::INT AS login_hour,
        event_action
    FROM fact_events
    WHERE log_source = 'windows'
      AND event_action LIKE '%Logon%'
      AND event_action NOT LIKE '%Failed%'
      AND (EXTRACT(hour FROM event_time)::INT < 7
           OR EXTRACT(hour FROM event_time)::INT > 20)
      AND username != ''
    ORDER BY event_time
    """)


# ─────────────────────────────────────────────────────────────────────────────
# MART 5 — Endpoint / Process Analytics
# ─────────────────────────────────────────────────────────────────────────────

def build_endpoint_analytics(con):
    # Suspicious process execution from Sysmon raw
    con.execute("""
    CREATE OR REPLACE TABLE mart_suspicious_processes AS
    SELECT
        DATE_TRUNC('day', _timestamp)       AS event_date,
        winlog__computer_name               AS hostname,
        user__name                          AS username,
        winlog__event_data__Image           AS process_image,
        winlog__event_data__CommandLine     AS command_line,
        winlog__event_data__ParentImage     AS parent_image,
        COUNT(*)                            AS execution_count,
        CASE
            WHEN winlog__event_data__Image LIKE '%mimikatz%'
              OR winlog__event_data__Image LIKE '%backdoor%'
              OR winlog__event_data__Image LIKE '%evil%'
              OR winlog__event_data__CommandLine LIKE '%-enc%'
              OR winlog__event_data__CommandLine LIKE '%Invoke-%'
              OR winlog__event_data__CommandLine LIKE '%DownloadString%'
            THEN 'MALICIOUS'
            WHEN winlog__event_data__Image LIKE '%powershell%'
              OR winlog__event_data__Image LIKE '%cmd%'
              OR winlog__event_data__Image LIKE '%wscript%'
            THEN 'SUSPICIOUS'
            ELSE 'NORMAL'
        END AS risk_classification
    FROM raw_sysmon
    WHERE winlog__event_id = 1
      AND winlog__event_data__Image IS NOT NULL
    GROUP BY 1,2,3,4,5,6
    ORDER BY 7 DESC, 6 DESC
    """)

    # PowerShell risky commands
    con.execute("""
    CREATE OR REPLACE TABLE mart_risky_powershell AS
    SELECT
        DATE_TRUNC('day', _timestamp)              AS event_date,
        host__name                                 AS hostname,
        user__name                                 AS username,
        winlog__event_data__ScriptBlockText        AS script_block,
        CASE
            WHEN winlog__event_data__ScriptBlockText LIKE '%DownloadString%'
              OR winlog__event_data__ScriptBlockText LIKE '%IEX%'
              OR winlog__event_data__ScriptBlockText LIKE '%Invoke-Expression%'
            THEN 'CRITICAL'
            WHEN winlog__event_data__ScriptBlockText LIKE '%-enc%'
              OR winlog__event_data__ScriptBlockText LIKE '%FromBase64%'
            THEN 'HIGH'
            WHEN winlog__event_data__ScriptBlockText LIKE '%backdoor%'
              OR winlog__event_data__ScriptBlockText LIKE '%New-LocalUser%'
            THEN 'HIGH'
            ELSE 'INFORMATIONAL'
        END AS risk_level
    FROM raw_powershell
    WHERE winlog__event_data__ScriptBlockText IS NOT NULL
    ORDER BY 5 DESC, 1 DESC
    """)


# ─────────────────────────────────────────────────────────────────────────────
# MART 6 — Firewall Analytics
# ─────────────────────────────────────────────────────────────────────────────

def build_firewall_analytics(con):
    con.execute("""
    CREATE OR REPLACE TABLE mart_firewall_summary AS
    SELECT
        DATE_TRUNC('day', event_time)        AS event_date,
        event_action,
        protocol,
        dst_port,
        COUNT(*)                             AS event_count,
        COUNT(DISTINCT src_ip)               AS unique_sources,
        ROUND(COUNT(*) * 100.0 /
            SUM(COUNT(*)) OVER(PARTITION BY DATE_TRUNC('day',event_time)), 2
        )                                    AS pct_of_day
    FROM fact_events
    WHERE log_source = 'firewall'
    GROUP BY 1, 2, 3, 4
    ORDER BY 1, 5 DESC
    """)

    # Top blocked sources
    con.execute("""
    CREATE OR REPLACE TABLE mart_fw_blocked_sources AS
    SELECT
        src_ip,
        COUNT(*)                AS block_count,
        COUNT(DISTINCT dst_port) AS targeted_ports,
        COUNT(DISTINCT dst_ip)   AS targeted_hosts,
        MIN(event_time)          AS first_blocked,
        MAX(event_time)          AS last_blocked
    FROM fact_events
    WHERE log_source = 'firewall'
      AND event_action IN ('drop','reject')
      AND src_ip != ''
    GROUP BY 1
    ORDER BY 2 DESC
    """)


# ─────────────────────────────────────────────────────────────────────────────
# MART 7 — Application / Web Analytics
# ─────────────────────────────────────────────────────────────────────────────

def build_application_analytics(con):
    con.execute("""
    CREATE OR REPLACE TABLE mart_http_status AS
    SELECT
        DATE_TRUNC('day', _timestamp)            AS event_date,
        http__response__status_code::VARCHAR      AS status_code,
        http__request__method                     AS method,
        COUNT(*)                                  AS request_count,
        AVG(http__response__bytes)                AS avg_response_bytes,
        COUNT(*) FILTER(WHERE http__response__status_code >= 400
                        AND http__response__status_code < 500) AS client_errors,
        COUNT(*) FILTER(WHERE http__response__status_code >= 500) AS server_errors
    FROM raw_application
    WHERE http__response__status_code IS NOT NULL
    GROUP BY 1, 2, 3
    ORDER BY 1, 4 DESC
    """)

    con.execute("""
    CREATE OR REPLACE TABLE mart_web_error_trend AS
    SELECT
        DATE_TRUNC('hour', _timestamp)           AS hour_window,
        COUNT(*) FILTER(WHERE http__response__status_code >= 400) AS errors,
        COUNT(*) FILTER(WHERE http__response__status_code < 400)  AS successes,
        COUNT(*)                                  AS total_requests,
        ROUND(COUNT(*) FILTER(WHERE http__response__status_code >= 400) * 100.0
            / NULLIF(COUNT(*), 0), 2)             AS error_rate_pct
    FROM raw_application
    GROUP BY 1
    ORDER BY 1
    """)


# ─────────────────────────────────────────────────────────────────────────────
# MART 8 — Anomaly Scores (ML / Statistical)
# ─────────────────────────────────────────────────────────────────────────────

def build_anomaly_scores(con):
    """Z-score based anomaly detection on hourly event counts per host."""
    df = con.execute("""
    SELECT
        hostname,
        DATE_TRUNC('hour', event_time) AS hour_window,
        COUNT(*) AS event_count
    FROM fact_events
    WHERE hostname != ''
    GROUP BY 1, 2
    """).df()

    if df.empty:
        return

    # Z-score per host
    df["mean"]    = df.groupby("hostname")["event_count"].transform("mean")
    df["std"]     = df.groupby("hostname")["event_count"].transform("std").fillna(1)
    df["z_score"] = (df["event_count"] - df["mean"]) / df["std"]
    df["anomaly_label"] = pd.cut(
        df["z_score"],
        bins=[-np.inf, -2, 2, 3, np.inf],
        labels=["Low Activity", "Normal", "Elevated", "Anomalous"]
    ).astype(str)  # convert Categorical → plain string before DuckDB insert

    con.execute("DROP TABLE IF EXISTS mart_host_anomaly")
    con.execute("CREATE TABLE mart_host_anomaly AS SELECT * FROM df")


# ─────────────────────────────────────────────────────────────────────────────
# MART 9 — Kill Chain Coverage (MITRE ATT&CK mapping)
# ─────────────────────────────────────────────────────────────────────────────

def build_kill_chain(con):
    con.execute("""
    CREATE OR REPLACE TABLE mart_mitre_coverage AS
    SELECT
        mitre_technique,
        attack_type,
        COUNT(*)                AS event_count,
        COUNT(DISTINCT hostname) AS hosts_affected,
        MIN(event_time)         AS first_observed,
        MAX(event_time)         AS last_observed,
        CASE
            WHEN mitre_technique LIKE '%T1566%' THEN 'Initial Access'
            WHEN mitre_technique LIKE '%T1059%' THEN 'Execution'
            WHEN mitre_technique LIKE '%T1105%' THEN 'Command & Control'
            WHEN mitre_technique LIKE '%T1021%' THEN 'Lateral Movement'
            WHEN mitre_technique LIKE '%T1041%' THEN 'Exfiltration'
            WHEN mitre_technique LIKE '%T1003%' THEN 'Credential Access'
            WHEN mitre_technique LIKE '%T1558%' THEN 'Credential Access'
            WHEN mitre_technique LIKE '%T1048%' THEN 'Exfiltration'
            WHEN mitre_technique LIKE '%T1486%' THEN 'Impact'
            WHEN mitre_technique LIKE '%T1490%' THEN 'Impact'
            WHEN mitre_technique LIKE '%T1078%' THEN 'Privilege Escalation'
            WHEN mitre_technique LIKE '%T1071%' THEN 'Command & Control'
            WHEN mitre_technique LIKE '%T1550%' THEN 'Lateral Movement'
            ELSE 'Unknown'
        END AS kill_chain_phase
    FROM fact_events
    WHERE mitre_technique IS NOT NULL AND mitre_technique != ''
    GROUP BY 1, 2
    ORDER BY 3 DESC
    """)


# ─────────────────────────────────────────────────────────────────────────────
# MART 10 — Executive Risk Score
# ─────────────────────────────────────────────────────────────────────────────

def build_risk_score(con):
    con.execute("""
    CREATE OR REPLACE TABLE mart_risk_score_daily AS
    WITH base AS (
        SELECT
            DATE_TRUNC('day', event_time) AS event_date,
            COUNT(*) FILTER(WHERE log_source='suricata')        AS ids_alerts,
            COUNT(*) FILTER(WHERE log_source='attack')          AS attack_events,
            COUNT(*) FILTER(WHERE log_source='windows'
                AND event_action LIKE '%Failed%')               AS auth_fails,
            COUNT(*) FILTER(WHERE log_source='firewall'
                AND event_action='drop')                        AS fw_blocks,
            COUNT(*) FILTER(WHERE log_source='powershell')      AS ps_events,
            COUNT(*) FILTER(WHERE log_source='threat_intel')    AS ti_events
        FROM fact_events
        GROUP BY 1
    )
    SELECT
        event_date,
        ids_alerts,
        attack_events,
        auth_fails,
        fw_blocks,
        ps_events,
        ti_events,
        -- Weighted risk score 0-100
        LEAST(100, ROUND(
            (ids_alerts    * 0.30 +
             attack_events * 0.25 +
             auth_fails    * 0.15 +
             fw_blocks     * 0.10 +
             ps_events     * 0.10 +
             ti_events     * 0.10) / 10.0, 1
        )) AS risk_score,
        CASE
            WHEN (ids_alerts*0.30 + attack_events*0.25 + auth_fails*0.15
                  + fw_blocks*0.10 + ps_events*0.10 + ti_events*0.10) / 10.0 >= 70
            THEN 'CRITICAL'
            WHEN (ids_alerts*0.30 + attack_events*0.25 + auth_fails*0.15
                  + fw_blocks*0.10 + ps_events*0.10 + ti_events*0.10) / 10.0 >= 40
            THEN 'HIGH'
            WHEN (ids_alerts*0.30 + attack_events*0.25 + auth_fails*0.15
                  + fw_blocks*0.10 + ps_events*0.10 + ti_events*0.10) / 10.0 >= 20
            THEN 'MEDIUM'
            ELSE 'LOW'
        END AS risk_level
    FROM base
    ORDER BY 1
    """)


# ─────────────────────────────────────────────────────────────────────────────
# MART 11 — DNS Analytics (data exfil detection)
# ─────────────────────────────────────────────────────────────────────────────

def build_dns_analytics(con):
    con.execute("""
    CREATE OR REPLACE TABLE mart_dns_summary AS
    SELECT
        DATE_TRUNC('day', _timestamp)     AS event_date,
        source__ip                        AS src_ip,
        COUNT(*)                          AS query_count,
        COUNT(DISTINCT dns__question__name) AS unique_domains,
        COUNT(*) FILTER(WHERE dns__response_code = 'NXDOMAIN') AS nxdomain_count,
        COUNT(*) FILTER(WHERE dns__question__type = 'TXT')     AS txt_queries,
        -- High TXT queries suggest DNS tunnelling
        CASE
            WHEN COUNT(*) FILTER(WHERE dns__question__type='TXT') > 20
            THEN TRUE ELSE FALSE
        END AS possible_dns_tunnel,
        -- Many NXDOMAINs suggest DGA (domain generation algorithm)
        CASE
            WHEN COUNT(*) FILTER(WHERE dns__response_code='NXDOMAIN') > 50
            THEN TRUE ELSE FALSE
        END AS possible_dga
    FROM raw_zeek_dns
    WHERE source__ip IS NOT NULL
    GROUP BY 1, 2
    ORDER BY 3 DESC
    """)


# ─────────────────────────────────────────────────────────────────────────────
# MART 12 — Linux Syslog Summary
# ─────────────────────────────────────────────────────────────────────────────

def build_syslog_analytics(con):
    con.execute("""
    CREATE OR REPLACE TABLE mart_syslog_summary AS
    SELECT
        DATE_TRUNC('day', _timestamp)          AS event_date,
        host__name                             AS hostname,
        process__name                          AS process_name,
        COALESCE(log__syslog__severity__name, 'unknown') AS severity,
        COALESCE(log__syslog__facility__name,  'unknown') AS facility,
        COUNT(*)                               AS event_count
    FROM raw_linux_syslog
    GROUP BY 1, 2, 3, 4, 5
    ORDER BY 1, 6 DESC
    """)

    con.execute("""
    CREATE OR REPLACE TABLE mart_ssh_attempts AS
    SELECT
        DATE_TRUNC('day', _timestamp)   AS event_date,
        host__name                      AS hostname,
        COUNT(*) FILTER(WHERE message LIKE '%Failed password%'
                        OR message LIKE '%Invalid user%') AS failed_ssh,
        COUNT(*) FILTER(WHERE message LIKE '%Accepted%')  AS successful_ssh,
        COUNT(*) FILTER(WHERE message LIKE '%sudo%')      AS sudo_uses
    FROM raw_linux_syslog
    GROUP BY 1, 2
    ORDER BY 1
    """)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def run_analytical(verbose: bool = True):
    con = get_con()
    steps = [
        ("KPI Daily",              build_kpi_daily),
        ("Threat Landscape",       build_threat_landscape),
        ("Network Analytics",      build_network_analytics),
        ("Auth Analytics",         build_auth_analytics),
        ("Endpoint Analytics",     build_endpoint_analytics),
        ("Firewall Analytics",     build_firewall_analytics),
        ("Application Analytics",  build_application_analytics),
        ("Anomaly Scores",         build_anomaly_scores),
        ("Kill Chain / MITRE",     build_kill_chain),
        ("Risk Score",             build_risk_score),
        ("DNS Analytics",          build_dns_analytics),
        ("Syslog Analytics",       build_syslog_analytics),
    ]
    for name, fn in steps:
        try:
            fn(con)
            if verbose:
                print(f"  [OK] {name}")
        except Exception as e:
            if verbose:
                print(f"  [WARN] {name}: {e}")
    con.close()


if __name__ == "__main__":
    print("=" * 60)
    print("LAYER 2 — Analytical Engineering: Building Data Marts")
    print("=" * 60)
    t0 = datetime.now()
    run_analytical(verbose=True)
    print(f"\nAnalytical layer built in {(datetime.now()-t0).total_seconds():.1f}s")
