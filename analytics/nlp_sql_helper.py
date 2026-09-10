"""
NLP-to-SQL helper — importable by Streamlit pages.
Wraps 03_nlp_sql.py for clean import without __main__ side-effects.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import duckdb
import pandas as pd
from typing import Tuple, Optional
from config import DB_PATH, OPENAI_API_KEY

# ── Schema context for OpenAI ─────────────────────────────────────────────────

SCHEMA_CONTEXT = """
You are a cybersecurity data analyst. You have access to a DuckDB database.
Write a single SQL SELECT query (no DDL, no trailing semicolons).

TABLES:
- fact_events(event_time, dataset, event_kind, event_action, event_category,
  src_ip, dst_ip, src_port, dst_port, protocol, transport, direction,
  bytes_transferred, hostname, username, attack_type, mitre_technique,
  source_file, log_source)
- mart_kpi_daily(event_date, total_events, unique_src_ips, active_hosts,
  active_users, total_bytes, ids_alerts, threat_intel_hits, attack_events,
  fw_drops, auth_failures, successful_logins, ps_executions, dns_queries,
  external_connections)
- mart_attack_summary(attack_type, mitre_technique, event_count, hosts_affected,
  users_affected, first_seen, last_seen, duration_minutes)
- mart_brute_force(src_ip, username, hour_window, failure_count, targets, severity)
- mart_top_talkers(src_ip, connection_count, total_bytes, unique_destinations,
  unique_dest_ports, protocols_used, first_seen, last_seen)
- mart_host_anomaly(hostname, hour_window, event_count, mean, std, z_score,
  anomaly_label)
- mart_risk_score_daily(event_date, ids_alerts, attack_events, auth_fails,
  fw_blocks, ps_events, ti_events, risk_score, risk_level)
- mart_mitre_coverage(mitre_technique, attack_type, event_count, hosts_affected,
  first_observed, last_observed, kill_chain_phase)
- mart_suspicious_processes(event_date, hostname, username, process_image,
  command_line, parent_image, execution_count, risk_classification)
- mart_risky_powershell(event_date, hostname, username, script_block, risk_level)
- mart_dns_summary(event_date, src_ip, query_count, unique_domains, nxdomain_count,
  txt_queries, possible_dns_tunnel, possible_dga)
- mart_firewall_summary(event_date, event_action, protocol, dst_port, event_count,
  unique_sources, pct_of_day)
- mart_fw_blocked_sources(src_ip, block_count, targeted_ports, targeted_hosts,
  first_blocked, last_blocked)
- mart_ids_alerts(event_date, signature, alert_count, unique_sources, unique_targets)
- mart_http_status(event_date, status_code, method, request_count,
  avg_response_bytes, client_errors, server_errors)
- mart_auth_trend(event_date, hostname, failures, successes, failure_rate_pct)
- mart_syslog_summary(event_date, hostname, process_name, severity, facility,
  event_count)
- mart_ssh_attempts(event_date, hostname, failed_ssh, successful_ssh, sudo_uses)
- mart_port_scan_suspects(src_ip, hour_window, unique_ports_targeted,
  unique_hosts_targeted, total_attempts, scan_risk_level)
- mart_afterhours_logins(username, hostname, event_time, login_hour, event_action)

RULES:
- DuckDB SQL syntax only
- Return ONLY the SQL query, no explanations
- Use LIMIT 100 unless the user asks for all data
"""

# ── Pre-built example queries ─────────────────────────────────────────────────

EXAMPLE_QUERIES = {
    # ── Basic ──────────────────────────────────────────────────────────────
    "Show daily risk scores": """
SELECT event_date, risk_score, risk_level,
       ids_alerts, attack_events, auth_fails
FROM mart_risk_score_daily ORDER BY event_date""",

    "Count events by log source": """
SELECT log_source, COUNT(*) AS event_count
FROM fact_events GROUP BY 1 ORDER BY 2 DESC""",

    "Top 10 most active source IPs": """
SELECT src_ip, connection_count, total_bytes,
       unique_destinations, unique_dest_ports
FROM mart_top_talkers ORDER BY connection_count DESC LIMIT 10""",

    "IDS alerts trend by day": """
SELECT event_date, SUM(alert_count) AS total_alerts,
       COUNT(DISTINCT signature) AS unique_signatures
FROM mart_ids_alerts GROUP BY event_date ORDER BY event_date""",

    "Failed SSH logins by host": """
SELECT event_date, hostname, failed_ssh, successful_ssh,
       ROUND(failed_ssh*100.0/NULLIF(failed_ssh+successful_ssh,0),1) AS fail_pct
FROM mart_ssh_attempts ORDER BY event_date, failed_ssh DESC""",

    # ── Intermediate ───────────────────────────────────────────────────────
    "Weekly KPI summary with totals": """
SELECT DATE_TRUNC('week', event_date) AS week,
       SUM(total_events) AS total_events,
       ROUND(AVG(ids_alerts),1) AS avg_daily_ids,
       SUM(attack_events) AS total_attacks,
       SUM(auth_failures) AS total_auth_failures,
       ROUND(AVG(active_hosts),0) AS avg_active_hosts
FROM mart_kpi_daily GROUP BY 1 ORDER BY 1""",

    "7-day rolling auth failure average": """
SELECT event_date, auth_failures,
       ROUND(AVG(auth_failures) OVER (
           ORDER BY event_date ROWS 6 PRECEDING), 1) AS rolling_7d_avg,
       ROUND(auth_failures - AVG(auth_failures) OVER (
           ORDER BY event_date ROWS 6 PRECEDING), 0) AS deviation_from_avg
FROM mart_kpi_daily ORDER BY event_date""",

    "Brute force suspects ranked by severity": """
SELECT src_ip, username, failure_count, severity, targets
FROM mart_brute_force
WHERE severity IN ('CRITICAL','HIGH')
ORDER BY failure_count DESC LIMIT 20""",

    "Authentication failure rate by host (high risk)": """
SELECT event_date, hostname, failures, successes, failure_rate_pct
FROM mart_auth_trend WHERE failure_rate_pct > 30
ORDER BY failure_rate_pct DESC LIMIT 30""",

    "Firewall DROP rate by protocol per day": """
SELECT event_date, protocol,
       SUM(event_count) FILTER(WHERE event_action='drop') AS dropped,
       SUM(event_count) AS total,
       ROUND(SUM(event_count) FILTER(WHERE event_action='drop') * 100.0
             / NULLIF(SUM(event_count),0), 2) AS drop_pct
FROM mart_firewall_summary
GROUP BY event_date, protocol ORDER BY event_date, drop_pct DESC""",

    # ── Advanced ───────────────────────────────────────────────────────────
    "Rank hosts by anomaly z-score with percentile": """
SELECT hostname, z_score, event_count,
       ROUND(PERCENT_RANK() OVER (ORDER BY z_score) * 100, 1) AS percentile,
       NTILE(4) OVER (ORDER BY z_score DESC) AS risk_quartile,
       anomaly_label
FROM mart_host_anomaly WHERE anomaly_label = 'Anomalous'
ORDER BY z_score DESC""",

    "Attack timeline with lag — time between events": """
SELECT attack_type, mitre_technique, event_time,
       LAG(event_time) OVER (
           PARTITION BY attack_type ORDER BY event_time
       ) AS prev_event_time,
       DATE_DIFF('second',
           LAG(event_time) OVER (PARTITION BY attack_type ORDER BY event_time),
           event_time
       ) AS seconds_since_last
FROM fact_events WHERE attack_type IS NOT NULL AND attack_type != ''
ORDER BY attack_type, event_time LIMIT 100""",

    "Top blocked IPs with attack persistence score": """
SELECT src_ip, block_count, targeted_ports, targeted_hosts,
       first_blocked, last_blocked,
       DATE_DIFF('day', first_blocked::DATE, last_blocked::DATE) AS active_days,
       ROUND(block_count * 1.0 /
           NULLIF(DATE_DIFF('day', first_blocked::DATE, last_blocked::DATE)+1, 0),
           1) AS blocks_per_day
FROM mart_fw_blocked_sources
ORDER BY blocks_per_day DESC LIMIT 20""",

    "DNS tunnelling suspects with exfil risk score": """
SELECT event_date, src_ip, query_count, unique_domains,
       nxdomain_count, txt_queries,
       ROUND(
           (txt_queries * 0.5 + nxdomain_count * 0.3 + query_count * 0.002),
           1) AS exfil_risk_score,
       possible_dns_tunnel, possible_dga
FROM mart_dns_summary
ORDER BY exfil_risk_score DESC LIMIT 30""",

    # ── Very Complex ───────────────────────────────────────────────────────
    "Hosts with brute-force AND malicious processes (correlated threat)": """
WITH bf_hosts AS (
    SELECT DISTINCT src_ip AS hostname
    FROM mart_brute_force WHERE severity IN ('CRITICAL','HIGH')
),
mal_proc_hosts AS (
    SELECT DISTINCT hostname
    FROM mart_suspicious_processes WHERE risk_classification='MALICIOUS'
)
SELECT
    f.hostname,
    COUNT(*) AS total_events,
    COUNT(*) FILTER(WHERE log_source='windows') AS win_events,
    COUNT(*) FILTER(WHERE log_source='sysmon')  AS sysmon_events,
    COUNT(*) FILTER(WHERE attack_type IS NOT NULL AND attack_type != '') AS attack_events,
    MIN(event_time) AS first_seen,
    MAX(event_time) AS last_seen
FROM fact_events f
WHERE f.hostname IN (SELECT hostname FROM mal_proc_hosts)
GROUP BY 1 HAVING total_events > 50
ORDER BY attack_events DESC, total_events DESC""",

    "Multi-stage attack detection: recon → execution → exfil chain": """
WITH stage_counts AS (
    SELECT
        hostname,
        attack_type,
        COUNT(*) FILTER(WHERE mitre_technique LIKE '%T1046%'
                        OR mitre_technique LIKE '%T1595%') AS recon_events,
        COUNT(*) FILTER(WHERE mitre_technique LIKE '%T1059%'
                        OR mitre_technique LIKE '%T1204%') AS execution_events,
        COUNT(*) FILTER(WHERE mitre_technique LIKE '%T1041%'
                        OR mitre_technique LIKE '%T1048%') AS exfil_events,
        COUNT(*) FILTER(WHERE mitre_technique LIKE '%T1021%'
                        OR mitre_technique LIKE '%T1550%') AS lateral_events
    FROM fact_events
    WHERE attack_type IS NOT NULL AND attack_type != ''
    GROUP BY 1, 2
)
SELECT *,
       recon_events + execution_events + exfil_events + lateral_events AS total_kill_chain_events,
       CASE
           WHEN recon_events > 0 AND execution_events > 0
                AND exfil_events > 0 THEN 'FULL CHAIN'
           WHEN recon_events > 0 AND execution_events > 0 THEN 'PARTIAL (no exfil)'
           WHEN execution_events > 0 AND exfil_events > 0 THEN 'PARTIAL (no recon)'
           ELSE 'SINGLE STAGE'
       END AS kill_chain_completeness
FROM stage_counts
WHERE total_kill_chain_events > 0
ORDER BY total_kill_chain_events DESC""",

    "NLP: Users logged in after-hours AND ran critical PowerShell": """
WITH ah_users AS (
    SELECT DISTINCT username
    FROM mart_afterhours_logins
    WHERE username != ''
),
risky_ps_users AS (
    SELECT DISTINCT username
    FROM mart_risky_powershell
    WHERE risk_level IN ('CRITICAL','HIGH') AND username != ''
)
SELECT
    f.username,
    COUNT(DISTINCT f.hostname)  AS hosts_accessed,
    COUNT(*) FILTER(WHERE f.log_source = 'windows') AS win_events,
    COUNT(*) FILTER(WHERE f.log_source = 'powershell') AS ps_events,
    MIN(f.event_time) AS first_activity,
    MAX(f.event_time) AS last_activity
FROM fact_events f
WHERE f.username IN (SELECT username FROM ah_users)
  AND f.username IN (SELECT username FROM risky_ps_users)
GROUP BY 1
ORDER BY hosts_accessed DESC, ps_events DESC""",

    "NLP: Which log sources show spikes above 2x their average daily volume?": """
WITH daily_counts AS (
    SELECT log_source,
           DATE_TRUNC('day', event_time)::DATE AS day,
           COUNT(*) AS daily_events
    FROM fact_events GROUP BY 1, 2
),
averages AS (
    SELECT log_source,
           AVG(daily_events)    AS avg_events,
           STDDEV(daily_events) AS std_events
    FROM daily_counts GROUP BY 1
)
SELECT d.log_source, d.day, d.daily_events,
       ROUND(a.avg_events, 0) AS avg_events,
       ROUND(d.daily_events / NULLIF(a.avg_events, 0), 2) AS ratio_to_avg,
       ROUND((d.daily_events - a.avg_events) / NULLIF(a.std_events,0), 2) AS z_score
FROM daily_counts d
JOIN averages a USING (log_source)
WHERE d.daily_events > a.avg_events * 2
ORDER BY ratio_to_avg DESC, d.day""",
}


# ── Core functions ────────────────────────────────────────────────────────────

def nl_to_sql(question: str) -> Tuple[str, str]:
    try:
        import openai
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SCHEMA_CONTEXT},
                {"role": "user", "content": f"Question: {question}\n\nSQL:"}
            ],
            temperature=0, max_tokens=600
        )
        sql = resp.choices[0].message.content.strip()
        if sql.startswith("```"):
            parts = sql.split("```")
            sql = parts[1].strip()
            if sql.lower().startswith("sql"):
                sql = sql[3:].strip()
        return sql, "GPT-4o-mini"
    except Exception as e:
        return "", f"OpenAI error: {e}"


def run_query(sql: str) -> Tuple[Optional[pd.DataFrame], str]:
    try:
        con = duckdb.connect(DB_PATH, read_only=True)
        df = con.execute(sql.strip().rstrip(";")).df()
        con.close()
        return df, ""
    except Exception as e:
        return None, str(e)


def ask(question: str) -> Tuple[str, Optional[pd.DataFrame], str]:
    """question → sql → (sql, df, error)"""
    if question in EXAMPLE_QUERIES:
        sql = EXAMPLE_QUERIES[question].strip()
        df, err = run_query(sql)
        return sql, df, err
    sql, note = nl_to_sql(question)
    if not sql:
        return "", None, note
    df, err = run_query(sql)
    return sql, df, err
