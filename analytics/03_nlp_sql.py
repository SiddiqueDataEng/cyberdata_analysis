"""
LAYER 3 — NLP-to-SQL via OpenAI
Translates natural language questions into DuckDB SQL and executes them.
"""

import duckdb
import pandas as pd
import json
import sys
from pathlib import Path
from typing import Tuple, Optional

sys.path.insert(0, str(Path(__file__).parent))
from config import DB_PATH, OPENAI_API_KEY

# ── Schema catalogue sent to LLM as context ──────────────────────────────────

SCHEMA_CONTEXT = """
You are a cybersecurity data analyst. You have access to a DuckDB database with
these tables. Write a single SQL SELECT query (no DDL, no semicolons at end).

TABLES:
- fact_events(event_time TIMESTAMP, dataset VARCHAR, event_kind, event_action,
  event_category, src_ip, dst_ip, src_port, dst_port, protocol, transport,
  direction, bytes_transferred BIGINT, hostname, username, attack_type,
  mitre_technique, source_file, log_source)

- mart_kpi_daily(event_date DATE, total_events, unique_src_ips, active_hosts,
  active_users, total_bytes, ids_alerts, threat_intel_hits, attack_events,
  fw_drops, auth_failures, successful_logins, ps_executions, dns_queries,
  external_connections)

- mart_attack_summary(attack_type, mitre_technique, event_count, hosts_affected,
  users_affected, first_seen, last_seen, duration_minutes)

- mart_brute_force(src_ip, username, hour_window, failure_count, targets, severity)

- mart_top_talkers(src_ip, connection_count, total_bytes, unique_destinations,
  unique_dest_ports, protocols_used, first_seen, last_seen)

- mart_host_anomaly(hostname, hour_window, event_count, mean, std, z_score, anomaly_label)

- mart_risk_score_daily(event_date, ids_alerts, attack_events, auth_fails,
  fw_blocks, ps_events, ti_events, risk_score FLOAT, risk_level VARCHAR)

- mart_mitre_coverage(mitre_technique, attack_type, event_count, hosts_affected,
  first_observed, last_observed, kill_chain_phase)

- mart_suspicious_processes(event_date, hostname, username, process_image,
  command_line, parent_image, execution_count, risk_classification)

- mart_risky_powershell(event_date, hostname, username, script_block, risk_level)

- mart_dns_summary(event_date, src_ip, query_count, unique_domains, nxdomain_count,
  txt_queries, possible_dns_tunnel BOOLEAN, possible_dga BOOLEAN)

- mart_firewall_summary(event_date, event_action, protocol, dst_port, event_count,
  unique_sources, pct_of_day)

- mart_fw_blocked_sources(src_ip, block_count, targeted_ports, targeted_hosts,
  first_blocked, last_blocked)

- mart_ids_alerts(event_date, signature, alert_count, unique_sources, unique_targets)

- mart_http_status(event_date, status_code, method, request_count, avg_response_bytes,
  client_errors, server_errors)

- mart_auth_trend(event_date, hostname, failures, successes, failure_rate_pct)

- mart_syslog_summary(event_date, hostname, process_name, severity, facility, event_count)

- mart_ssh_attempts(event_date, hostname, failed_ssh, successful_ssh, sudo_uses)

- mart_port_scan_suspects(src_ip, hour_window, unique_ports_targeted,
  unique_hosts_targeted, total_attempts, scan_risk_level)

RULES:
- Always use DuckDB SQL syntax
- Return only the SQL query, nothing else
- For time ranges use: event_date BETWEEN 'YYYY-MM-DD' AND 'YYYY-MM-DD'
- Use LIMIT 100 unless user asks for all
- Log sources: network, zeek_dns, suricata, windows, sysmon, powershell,
  linux_syslog, rsyslog, firewall, threat_intel, application, attack
"""

# ── Pre-built example queries (no API needed) ─────────────────────────────────

EXAMPLE_QUERIES = {
    "Show daily risk scores": """
SELECT event_date, risk_score, risk_level,
       ids_alerts, attack_events, auth_fails
FROM mart_risk_score_daily
ORDER BY event_date""",

    "Top 10 most active source IPs": """
SELECT src_ip, connection_count, total_bytes,
       unique_destinations, unique_dest_ports
FROM mart_top_talkers
ORDER BY connection_count DESC
LIMIT 10""",

    "Attack type breakdown with MITRE techniques": """
SELECT attack_type, mitre_technique, kill_chain_phase,
       event_count, hosts_affected
FROM mart_mitre_coverage
ORDER BY event_count DESC""",

    "Brute force suspects above HIGH severity": """
SELECT src_ip, username, hour_window, failure_count, severity
FROM mart_brute_force
WHERE severity IN ('CRITICAL','HIGH')
ORDER BY failure_count DESC
LIMIT 20""",

    "IDS alerts trend by day": """
SELECT event_date, SUM(alert_count) AS total_alerts,
       COUNT(DISTINCT signature) AS unique_signatures,
       SUM(unique_sources) AS unique_attackers
FROM mart_ids_alerts
GROUP BY event_date ORDER BY event_date""",

    "PowerShell risk — critical executions": """
SELECT event_date, hostname, username,
       LEFT(script_block, 120) AS script_preview, risk_level
FROM mart_risky_powershell
WHERE risk_level IN ('CRITICAL','HIGH')
ORDER BY event_date DESC LIMIT 30""",

    "Hosts with anomalous event spikes": """
SELECT hostname, hour_window, event_count,
       ROUND(z_score,2) AS z_score, anomaly_label
FROM mart_host_anomaly
WHERE anomaly_label = 'Anomalous'
ORDER BY z_score DESC LIMIT 30""",

    "DNS tunnelling suspects": """
SELECT event_date, src_ip, query_count, txt_queries,
       nxdomain_count, possible_dns_tunnel, possible_dga
FROM mart_dns_summary
WHERE possible_dns_tunnel OR possible_dga
ORDER BY txt_queries DESC""",

    "Failed SSH logins by host over time": """
SELECT event_date, hostname, failed_ssh, successful_ssh,
       ROUND(failed_ssh*100.0/NULLIF(failed_ssh+successful_ssh,0),1) AS fail_pct
FROM mart_ssh_attempts
ORDER BY event_date, failed_ssh DESC""",

    "Firewall DROP rate by protocol per day": """
SELECT event_date, protocol,
       SUM(event_count) FILTER(WHERE event_action='drop') AS dropped,
       SUM(event_count) AS total,
       ROUND(SUM(event_count) FILTER(WHERE event_action='drop')*100.0
             /NULLIF(SUM(event_count),0),2) AS drop_pct
FROM mart_firewall_summary
GROUP BY event_date, protocol
ORDER BY event_date, drop_pct DESC""",

    "Suspicious process executions ranked by risk": """
SELECT event_date, hostname, username, process_image,
       LEFT(command_line,100) AS cmd, execution_count, risk_classification
FROM mart_suspicious_processes
WHERE risk_classification IN ('MALICIOUS','SUSPICIOUS')
ORDER BY risk_classification, execution_count DESC
LIMIT 50""",

    "Weekly KPI summary": """
SELECT DATE_TRUNC('week', event_date) AS week,
       SUM(total_events)    AS total_events,
       AVG(ids_alerts)      AS avg_daily_ids_alerts,
       SUM(attack_events)   AS total_attacks,
       SUM(auth_failures)   AS total_auth_failures,
       ROUND(AVG(active_hosts),0) AS avg_active_hosts
FROM mart_kpi_daily
GROUP BY 1 ORDER BY 1""",

    "Top blocked IPs with port targeting detail": """
SELECT src_ip, block_count, targeted_ports, targeted_hosts,
       first_blocked, last_blocked,
       DATE_DIFF('day', first_blocked::DATE, last_blocked::DATE) AS active_days
FROM mart_fw_blocked_sources
ORDER BY block_count DESC
LIMIT 20""",

    "HTTP error rate trend (hourly)": """
SELECT DATE_TRUNC('hour', hour_window) AS hour,
       SUM(errors) AS errors, SUM(total_requests) AS requests,
       ROUND(AVG(error_rate_pct),2) AS avg_error_pct
FROM mart_web_error_trend
GROUP BY 1 ORDER BY 1""",

    "Authentication failure rate by host (high risk)": """
SELECT event_date, hostname, failures, successes, failure_rate_pct
FROM mart_auth_trend
WHERE failure_rate_pct > 30
ORDER BY failure_rate_pct DESC, event_date DESC
LIMIT 30""",
}

# ── OpenAI NLP-to-SQL ─────────────────────────────────────────────────────────

def nl_to_sql(question: str) -> Tuple[str, str]:
    """
    Convert a natural language question to SQL using OpenAI.
    Returns (sql, explanation).
    """
    try:
        import openai
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SCHEMA_CONTEXT},
                {"role": "user", "content": f"Question: {question}\n\nSQL:"}
            ],
            temperature=0,
            max_tokens=500
        )
        sql = response.choices[0].message.content.strip()
        # Strip markdown code blocks if present
        if sql.startswith("```"):
            sql = sql.split("```")[1].strip()
            if sql.startswith("sql"):
                sql = sql[3:].strip()
        return sql, "Generated by GPT-4o-mini"
    except Exception as e:
        return "", f"OpenAI error: {e}"


def run_query(sql: str, con=None) -> Tuple[Optional[pd.DataFrame], str]:
    """Execute SQL against DuckDB, return (dataframe, error_message)."""
    close_after = con is None
    if con is None:
        con = duckdb.connect(DB_PATH)
    try:
        df = con.execute(sql).df()
        return df, ""
    except Exception as e:
        return None, str(e)
    finally:
        if close_after:
            con.close()


def ask(question: str) -> Tuple[str, Optional[pd.DataFrame], str]:
    """
    Full NLP pipeline: question → SQL → result.
    Returns (sql, dataframe, error).
    """
    # Check example queries first (exact match)
    if question in EXAMPLE_QUERIES:
        sql = EXAMPLE_QUERIES[question].strip()
        df, err = run_query(sql)
        return sql, df, err

    # Try OpenAI
    sql, note = nl_to_sql(question)
    if not sql:
        return "", None, note

    df, err = run_query(sql)
    return sql, df, err


if __name__ == "__main__":
    q = sys.argv[1] if len(sys.argv) > 1 else "Show daily risk scores"
    print(f"\nQuestion: {q}")
    sql, df, err = ask(q)
    print(f"\nSQL:\n{sql}")
    if err:
        print(f"Error: {err}")
    elif df is not None:
        print(f"\nResults ({len(df)} rows):")
        print(df.to_string(max_rows=20))
