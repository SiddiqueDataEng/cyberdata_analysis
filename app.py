# CyberData Analytics — Self-contained, no external module deps
# Cloud: synthetic demo data | Local: full DuckDB warehouse
import streamlit as st
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

st.set_page_config(page_title="CyberData Analytics", page_icon=":shield:",
                   layout="wide", initial_sidebar_state="expanded")
st.markdown("""<style>
[data-testid="stAppViewContainer"]{background:#0d1117}
[data-testid="stSidebar"]{background:#161b22;border-right:1px solid #30363d}
[data-testid="stSidebar"] *{color:#e6edf3!important}
h1,h2,h3,h4{color:#58a6ff!important}
.kpi-card{background:linear-gradient(135deg,#161b22,#21262d);border:1px solid #30363d;
  border-radius:12px;padding:20px 14px;text-align:center;margin:4px 2px}
.kpi-value{font-size:1.9rem;font-weight:800;color:#58a6ff}
.kpi-label{font-size:.8rem;color:#8b949e;margin-top:5px;text-transform:uppercase}
[data-testid="stMetric"]{background:#161b22;border:1px solid #30363d;
  border-radius:8px;padding:12px!important}
[data-testid="stMetricValue"]{color:#58a6ff!important}
.story-box{background:#161b22;border-left:4px solid #58a6ff;border-radius:8px;
  padding:18px 22px;margin:10px 0}
.dss-box{background:#161b22;border:1px solid #30363d;border-radius:8px;
  padding:14px 18px;margin:8px 0}
</style>""", unsafe_allow_html=True)

import duckdb
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import date, timedelta

# ── Try optional helpers (won't fail if missing) ─────────────────────────────
try:
    from tooltips import inject_css, add_chart_tooltip
    inject_css()
    _HAS_TOOLTIPS = True
except Exception:
    _HAS_TOOLTIPS = False
    def add_chart_tooltip(fig, key=None): return fig

try:
    from analytics_helpers import render_nlp_page, render_story_dss
    _HAS_HELPERS = True
except Exception:
    _HAS_HELPERS = False

try:
    from config import DB_PATH as _DB_PATH
    _LOCAL_DB = os.path.exists(_DB_PATH)
except Exception:
    _DB_PATH = ""
    _LOCAL_DB = False

IS_CLOUD = not _LOCAL_DB

def fmt_number(v):
    try:
        n = float(v) if v is not None else 0
        if n >= 1_000_000: return f"{n/1_000_000:.1f}M"
        if n >= 1_000:     return f"{n/1_000:.1f}K"
        return f"{n:.0f}"
    except: return "0"

def color_risk(s):
    return "#f85149" if s>=75 else "#ffa657" if s>=50 else "#e3b341" if s>=25 else "#3fb950"

ROW_LIMIT = "LIMIT 500" if IS_CLOUD else ""
TOP_N     = 25          if IS_CLOUD else 100


# ─────────────────────────────────────────────────────────────────────────────
# DEMO WAREHOUSE
# ─────────────────────────────────────────────────────────────────────────────
def _build_demo():
    """Build a compact in-memory DuckDB warehouse with synthetic data."""
    con = duckdb.connect(":memory:")
    rng = np.random.default_rng(42)
    dates = [date(2024, 1, 1) + timedelta(days=i) for i in range(30)]
    n = 30

    # --- helper: register df as view then create table from it ---
    def create(name, df):
        view = f"_tmp_{name}"
        con.register(view, df)
        con.execute(f"CREATE TABLE {name} AS SELECT * FROM {view}")
        con.unregister(view)

    sc = rng.uniform(10, 90, n).tolist()
    create("mart_kpi_daily", pd.DataFrame({
        "event_date":          dates,
        "total_events":        rng.integers(8000, 15000, n).tolist(),
        "unique_src_ips":      rng.integers(100, 500, n).tolist(),
        "active_hosts":        rng.integers(20, 60, n).tolist(),
        "active_users":        rng.integers(10, 40, n).tolist(),
        "total_bytes":         rng.integers(100_000_000, 5_000_000_000, n).tolist(),
        "ids_alerts":          rng.integers(50, 800, n).tolist(),
        "threat_intel_hits":   rng.integers(10, 200, n).tolist(),
        "attack_events":       rng.integers(0, 50, n).tolist(),
        "fw_drops":            rng.integers(100, 2000, n).tolist(),
        "auth_failures":       rng.integers(50, 500, n).tolist(),
        "successful_logins":   rng.integers(200, 1000, n).tolist(),
        "ps_executions":       rng.integers(20, 300, n).tolist(),
        "dns_queries":         rng.integers(500, 5000, n).tolist(),
        "external_connections":rng.integers(100, 1000, n).tolist(),
    }))
    create("mart_risk_score_daily", pd.DataFrame({
        "event_date":   dates,
        "ids_alerts":   rng.integers(50, 800, n).tolist(),
        "attack_events":rng.integers(0, 50, n).tolist(),
        "auth_fails":   rng.integers(50, 500, n).tolist(),
        "fw_blocks":    rng.integers(100, 2000, n).tolist(),
        "ps_events":    rng.integers(20, 300, n).tolist(),
        "ti_events":    rng.integers(10, 200, n).tolist(),
        "risk_score":   sc,
        "risk_level":   ["CRITICAL" if s>=75 else "HIGH" if s>=50 else "MEDIUM" if s>=25 else "LOW" for s in sc],
    }))
    create("mart_attack_summary", pd.DataFrame({
        "attack_type":      ["apt","ransomware","data_exfil","cred_theft"],
        "mitre_technique":  ["T1021","T1486","T1048","T1003"],
        "event_count":      [35,70,100,30],
        "hosts_affected":   [5,12,3,8],
        "users_affected":   [3,8,2,5],
        "first_seen":       pd.to_datetime(["2024-01-05","2024-01-12","2024-01-18","2024-01-22"]),
        "last_seen":        pd.to_datetime(["2024-01-06","2024-01-12","2024-01-18","2024-01-23"]),
        "duration_minutes": [480,120,30,360],
    }))
    create("mart_mitre_coverage", pd.DataFrame({
        "mitre_technique":  ["T1059.001","T1021","T1041","T1003.001","T1566.001","T1486","T1048.003","T1078","T1071"],
        "attack_type":      ["apt","apt","apt","cred_theft","ransomware","ransomware","data_exfil","cred_theft","apt"],
        "event_count":      [15,20,8,12,25,45,30,10,18],
        "hosts_affected":   [3,5,2,4,8,12,3,6,4],
        "first_observed":   pd.to_datetime(["2024-01-05"]*9),
        "last_observed":    pd.to_datetime(["2024-01-25"]*9),
        "kill_chain_phase": ["Execution","Lateral Movement","Exfiltration","Credential Access",
                             "Initial Access","Impact","Exfiltration","Privilege Escalation","Command & Control"],
    }))
    hosts = [f"WIN{i:03d}" for i in range(1,8)] + [f"ubuntu{i:02d}" for i in range(1,4)]
    n_ha  = len(hosts)*24
    zs    = rng.normal(0,1.5,n_ha).tolist()
    create("mart_host_anomaly", pd.DataFrame({
        "hostname":      [h for h in hosts for _ in range(24)],
        "hour_window":   pd.date_range("2024-01-15",periods=n_ha,freq="h"),
        "event_count":   rng.integers(10,500,n_ha).tolist(),
        "mean":          rng.uniform(50,200,n_ha).tolist(),
        "std":           rng.uniform(10,50,n_ha).tolist(),
        "z_score":       zs,
        "anomaly_label": ["Anomalous" if z>3 else "Elevated" if z>2 else "Low Activity" if z<-2 else "Normal" for z in zs],
    }))
    create("mart_brute_force", pd.DataFrame({
        "src_ip":        [f"10.0.0.{i}" for i in range(1,21)],
        "username":      rng.choice(["admin","root","alice","bob"],20).tolist(),
        "hour_window":   pd.date_range("2024-01-10 02:00",periods=20,freq="h"),
        "failure_count": rng.integers(5,200,20).tolist(),
        "targets":       rng.integers(1,10,20).tolist(),
        "severity":      rng.choice(["CRITICAL","HIGH","MEDIUM","LOW"],20).tolist(),
    }))
    create("mart_top_talkers", pd.DataFrame({
        "src_ip":              [f"192.168.1.{i}" for i in range(1,31)],
        "connection_count":    rng.integers(100,5000,n).tolist(),
        "total_bytes":         rng.integers(1_000_000,1_000_000_000,n).tolist(),
        "unique_destinations": rng.integers(5,100,n).tolist(),
        "unique_dest_ports":   rng.integers(1,50,n).tolist(),
        "protocols_used":      rng.integers(1,4,n).tolist(),
        "first_seen":          pd.to_datetime(["2024-01-01"]*n),
        "last_seen":           pd.to_datetime(["2024-01-30"]*n),
    }))
    create("mart_ids_alerts", pd.DataFrame({
        "event_date":     dates,
        "signature":      rng.choice(["ET SCAN Port Scan","ET MALWARE Trojan","ET EXPLOIT","ET POLICY"],n).tolist(),
        "alert_count":    rng.integers(5,200,n).tolist(),
        "unique_sources": rng.integers(1,20,n).tolist(),
        "unique_targets": rng.integers(1,10,n).tolist(),
    }))
    create("mart_threat_intel", pd.DataFrame({
        "event_date":      dates,
        "indicator_count": rng.integers(10,300,n).tolist(),
        "ti_feed_events":  rng.integers(5,100,n).tolist(),
    }))
    create("mart_auth_trend", pd.DataFrame({
        "event_date":       [d for d in dates for _ in range(5)],
        "hostname":         [f"WIN{i:03d}" for _ in dates for i in range(1,6)],
        "failures":         rng.integers(0,100,150).tolist(),
        "successes":        rng.integers(50,500,150).tolist(),
        "failure_rate_pct": rng.uniform(0,40,150).tolist(),
    }))
    create("mart_afterhours_logins", pd.DataFrame({
        "username":     rng.choice(["alice","bob","admin","charlie"],50).tolist(),
        "hostname":     [f"WIN{int(rng.integers(1,20)):03d}" for _ in range(50)],
        "event_time":   pd.date_range("2024-01-01 22:00",periods=50,freq="3h"),
        "login_hour":   rng.choice([22,23,0,1,2,3,4,5],50).tolist(),
        "event_action": ["Successful Logon"]*50,
    }))
    create("mart_suspicious_processes", pd.DataFrame({
        "event_date":          [d for d in dates[:10] for _ in range(3)],
        "hostname":            [f"WIN{i:03d}" for i in range(1,31)],
        "username":            rng.choice(["alice","bob","admin"],30).tolist(),
        "process_image":       rng.choice(["powershell.exe","mimikatz.exe","cmd.exe"],30).tolist(),
        "command_line":        rng.choice(["powershell -enc ABC","mimikatz.exe","cmd /c whoami"],30).tolist(),
        "parent_image":        ["svchost.exe"]*30,
        "execution_count":     rng.integers(1,20,30).tolist(),
        "risk_classification": rng.choice(["MALICIOUS","SUSPICIOUS","NORMAL"],30).tolist(),
    }))
    create("mart_risky_powershell", pd.DataFrame({
        "event_date":   [d for d in dates[:10] for _ in range(2)],
        "hostname":     [f"WIN{i:03d}" for i in range(1,21)],
        "username":     rng.choice(["alice","admin","bob"],20).tolist(),
        "script_block": rng.choice(["IEX DownloadString(...)","Get-Process","New-LocalUser"],20).tolist(),
        "risk_level":   rng.choice(["CRITICAL","HIGH","INFORMATIONAL"],20).tolist(),
    }))
    create("mart_firewall_summary", pd.DataFrame({
        "event_date":    [d for d in dates for _ in range(3)],
        "event_action":  rng.choice(["accept","drop","reject"],90).tolist(),
        "protocol":      rng.choice(["tcp","udp","icmp"],90).tolist(),
        "dst_port":      rng.choice(["80","443","22","53"],90).tolist(),
        "event_count":   rng.integers(10,500,90).tolist(),
        "unique_sources":rng.integers(1,50,90).tolist(),
        "pct_of_day":    rng.uniform(1,60,90).tolist(),
    }))
    create("mart_fw_blocked_sources", pd.DataFrame({
        "src_ip":         [f"{int(rng.integers(1,200))}.{int(rng.integers(0,255))}.0.1" for _ in range(20)],
        "block_count":    rng.integers(10,1000,20).tolist(),
        "targeted_ports": rng.integers(1,30,20).tolist(),
        "targeted_hosts": rng.integers(1,10,20).tolist(),
        "first_blocked":  pd.to_datetime(["2024-01-01"]*20),
        "last_blocked":   pd.to_datetime(["2024-01-30"]*20),
    }))
    create("mart_port_scan_suspects", pd.DataFrame({
        "src_ip":                [f"10.0.{i}.1" for i in range(15)],
        "hour_window":           pd.date_range("2024-01-10 01:00",periods=15,freq="2h"),
        "unique_ports_targeted": rng.integers(6,100,15).tolist(),
        "unique_hosts_targeted": rng.integers(1,20,15).tolist(),
        "total_attempts":        rng.integers(50,2000,15).tolist(),
        "scan_risk_level":       rng.choice(["HIGH","MEDIUM","LOW"],15).tolist(),
    }))
    n_et = n*24
    create("mart_external_traffic", pd.DataFrame({
        "hour_window":       pd.date_range("2024-01-01",periods=n_et,freq="h"),
        "inbound_external":  rng.integers(10,500,n_et).tolist(),
        "outbound_external": rng.integers(50,1000,n_et).tolist(),
        "total_bytes":       rng.integers(100_000,100_000_000,n_et).tolist(),
    }))
    create("mart_protocol_dist", pd.DataFrame({
        "protocol":    rng.choice(["tcp","udp","icmp","dns","http","https"],90).tolist(),
        "event_date":  [d for d in dates for _ in range(3)],
        "event_count": rng.integers(100,5000,90).tolist(),
        "total_bytes": rng.integers(10_000,100_000_000,90).tolist(),
        "avg_bytes":   rng.uniform(100,50000,90).tolist(),
    }))
    create("mart_syslog_summary", pd.DataFrame({
        "event_date":   [d for d in dates for _ in range(5)],
        "hostname":     [f"ubuntu{i:02d}" for _ in dates for i in range(1,6)],
        "process_name": rng.choice(["sshd","sudo","cron","systemd","rsyslogd"],150).tolist(),
        "severity":     rng.choice(["info","warning","err","debug"],150).tolist(),
        "facility":     rng.choice(["auth","daemon","kern","cron"],150).tolist(),
        "event_count":  rng.integers(1,200,150).tolist(),
    }))
    create("mart_ssh_attempts", pd.DataFrame({
        "event_date":     dates,
        "hostname":       [f"ubuntu{(i%5)+1:02d}" for i in range(n)],
        "failed_ssh":     rng.integers(0,100,n).tolist(),
        "successful_ssh": rng.integers(5,50,n).tolist(),
        "sudo_uses":      rng.integers(0,20,n).tolist(),
    }))
    create("mart_dns_summary", pd.DataFrame({
        "event_date":          dates,
        "src_ip":              [f"192.168.1.{int(rng.integers(1,50))}" for _ in range(n)],
        "query_count":         rng.integers(10,500,n).tolist(),
        "unique_domains":      rng.integers(5,100,n).tolist(),
        "nxdomain_count":      rng.integers(0,80,n).tolist(),
        "txt_queries":         rng.integers(0,50,n).tolist(),
        "possible_dns_tunnel": rng.choice([True,False,False,False],n).tolist(),
        "possible_dga":        rng.choice([True,False,False,False],n).tolist(),
    }))
    create("mart_http_status", pd.DataFrame({
        "event_date":         [d for d in dates for _ in range(4)],
        "status_code":        rng.choice([200,201,301,400,401,403,404,500],120).tolist(),
        "method":             rng.choice(["GET","POST","PUT","DELETE"],120).tolist(),
        "request_count":      rng.integers(10,1000,120).tolist(),
        "avg_response_bytes": rng.uniform(200,50000,120).tolist(),
        "client_errors":      rng.integers(0,100,120).tolist(),
        "server_errors":      rng.integers(0,50,120).tolist(),
    }))
    n_wet = n*24
    create("mart_web_error_trend", pd.DataFrame({
        "hour_window":    pd.date_range("2024-01-01",periods=n_wet,freq="h"),
        "errors":         rng.integers(0,100,n_wet).tolist(),
        "successes":      rng.integers(100,2000,n_wet).tolist(),
        "total_requests": rng.integers(200,3000,n_wet).tolist(),
        "error_rate_pct": rng.uniform(0,15,n_wet).tolist(),
    }))
    n_fe  = 500
    ap    = rng.choice(["apt","ransomware","data_exfil","cred_theft","","",""],n_fe).tolist()
    mp    = rng.choice(["T1059.001","T1021","T1041","T1003","T1566","",""],n_fe).tolist()
    create("fact_events", pd.DataFrame({
        "event_time":        pd.date_range("2024-01-01",periods=n_fe,freq="1h"),
        "dataset":           rng.choice(["zeek.connection","windows.security","suricata.alert"],n_fe).tolist(),
        "event_kind":        rng.choice(["event","alert"],n_fe).tolist(),
        "event_action":      rng.choice(["Successful Logon","Failed Logon","DROP","ACCEPT"],n_fe).tolist(),
        "event_category":    rng.choice(["network","authentication","process"],n_fe).tolist(),
        "src_ip":            [f"192.168.1.{int(rng.integers(1,254))}" for _ in range(n_fe)],
        "dst_ip":            [f"10.0.0.{int(rng.integers(1,254))}" for _ in range(n_fe)],
        "src_port":          [str(int(x)) for x in rng.integers(1024,65535,n_fe)],
        "dst_port":          rng.choice(["80","443","22","53"],n_fe).tolist(),
        "protocol":          rng.choice(["tcp","udp"],n_fe).tolist(),
        "transport":         rng.choice(["tcp","udp"],n_fe).tolist(),
        "direction":         rng.choice(["inbound","outbound"],n_fe).tolist(),
        "bytes_transferred": rng.integers(64,65535,n_fe).tolist(),
        "hostname":          [f"WIN{int(rng.integers(1,20)):03d}" for _ in range(n_fe)],
        "username":          rng.choice(["alice","bob","admin"],n_fe).tolist(),
        "attack_type":       [x if x.strip() else None for x in ap],
        "mitre_technique":   [x if x.strip() else None for x in mp],
        "source_file":       ["demo"]*n_fe,
        "log_source":        rng.choice(["network","windows","suricata","firewall"],n_fe).tolist(),
    }))
    return con


# ─────────────────────────────────────────────────────────────────────────────
# DB CONNECTION
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner=False)
def get_con():
    if _LOCAL_DB:
        try:
            return duckdb.connect(_DB_PATH, read_only=True)
        except Exception:
            pass
    with st.spinner("Building demo warehouse..."):
        return _build_demo()


CON = get_con()
if CON is None:
    st.error("Could not connect to database.")
    st.stop()


def qdf(sql):
    try:
        return CON.execute(sql).df()
    except Exception as e:
        st.error(f"Query error: {e}")
        return pd.DataFrame()


def qlim(sql):
    q = sql.rstrip().rstrip(";")
    if ROW_LIMIT and "LIMIT" not in q.upper():
        q += f" {ROW_LIMIT}"
    return qdf(q)


PT = dict(template="plotly_dark", paper_bgcolor="#0d1117", plot_bgcolor="#0d1117")


def show(fig, h=350):
    fig.update_layout(height=h, **PT)
    st.plotly_chart(fig, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## :shield: CyberData Analytics")
    st.caption("Data Engineering for Cybersecurity")
    if IS_CLOUD:
        st.info("Demo mode (synthetic data)", icon="i")
    st.divider()
    page = st.radio("Navigation", [
        "Executive Summary", "KPI Dashboard", "Network & Firewall",
        "Threat Intelligence", "Auth & Identity", "Endpoint & Process",
        "Attack & Kill Chain", "Anomaly Detection", "Application Analytics",
        "NLP SQL Explorer", "Story & DSS",
    ])
    st.divider()
    dr = qdf("SELECT CAST(MIN(event_date) AS DATE) AS mn, CAST(MAX(event_date) AS DATE) AS mx FROM mart_kpi_daily")
    if not dr.empty and dr["mn"].iloc[0] is not None:
        mn = pd.to_datetime(dr["mn"].iloc[0]).date()
        mx = pd.to_datetime(dr["mx"].iloc[0]).date()
    else:
        mn, mx = date(2024, 1, 1), date(2024, 1, 30)
    d_start, d_end = st.date_input("Date Range", value=(mn, mx), min_value=mn, max_value=mx)

DR = f"event_date BETWEEN '{d_start}' AND '{d_end}'"


# =============================================================================
# EXECUTIVE SUMMARY
# =============================================================================
if page == "Executive Summary":
    st.title(":shield: Executive Summary")
    st.caption(f"Period: {d_start} to {d_end}" + (" | Demo data" if IS_CLOUD else ""))

    kpi = qdf(f"""SELECT SUM(total_events) AS te, SUM(ids_alerts) AS ia,
        SUM(attack_events) AS ae, SUM(auth_failures) AS af, SUM(fw_drops) AS fd,
        ROUND(AVG(active_hosts),0) AS ah, ROUND(SUM(total_bytes)/1e9,2) AS gb,
        SUM(external_connections) AS ec, SUM(ps_executions) AS ps
        FROM mart_kpi_daily WHERE {DR}""")
    rdf = qdf(f"SELECT AVG(risk_score) AS rs FROM mart_risk_score_daily WHERE {DR}")
    avg_risk = float(rdf["rs"].iloc[0]) if not rdf.empty and pd.notna(rdf["rs"].iloc[0]) else 0

    c1,c2,c3,c4,c5 = st.columns(5)
    for col,val,lbl in [
        (c1, fmt_number(kpi["te"].iloc[0]), "Total Events"),
        (c2, fmt_number(kpi["ia"].iloc[0]), "IDS Alerts"),
        (c3, fmt_number(kpi["ae"].iloc[0]), "Attack Events"),
        (c4, fmt_number(kpi["af"].iloc[0]), "Auth Failures"),
        (c5, fmt_number(kpi["fd"].iloc[0]), "FW Blocks"),
    ]:
        col.markdown(f'<div class="kpi-card"><div class="kpi-value">{val}</div>'
                     f'<div class="kpi-label">{lbl}</div></div>', unsafe_allow_html=True)

    st.divider()
    m1,m2,m3,m4 = st.columns(4)
    m1.metric("Avg Active Hosts",      f"{kpi['ah'].iloc[0]:.0f}")
    m2.metric("Data Volume",           f"{kpi['gb'].iloc[0]:.1f} GB")
    m3.metric("External Connections",  fmt_number(kpi["ec"].iloc[0]))
    m4.metric("PowerShell Executions", fmt_number(kpi["ps"].iloc[0]))

    st.divider()
    cl, cr = st.columns([3,1])
    with cl:
        tr = qlim(f"SELECT event_date,total_events,ids_alerts,attack_events,auth_failures FROM mart_kpi_daily WHERE {DR} ORDER BY event_date")
        if not tr.empty:
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=tr["event_date"], y=tr["total_events"], name="Total Events",
                fill="tozeroy", fillcolor="rgba(88,166,255,0.08)", line=dict(color="#58a6ff",width=2)))
            fig.add_trace(go.Scatter(x=tr["event_date"], y=tr["ids_alerts"], name="IDS Alerts", line=dict(color="#f85149",width=2)))
            fig.add_trace(go.Scatter(x=tr["event_date"], y=tr["attack_events"], name="Attacks", line=dict(color="#d2a8ff",width=2,dash="dot")))
            fig.add_trace(go.Scatter(x=tr["event_date"], y=tr["auth_failures"], name="Auth Failures", line=dict(color="#ffa657",width=1.5)))
            fig.update_layout(title="Daily Security Event Trends", legend=dict(orientation="h",y=-0.2))
            show(fig, h=320)
    with cr:
        rl  = "CRITICAL" if avg_risk>=75 else "HIGH" if avg_risk>=50 else "MEDIUM" if avg_risk>=25 else "LOW"
        clr = {"CRITICAL":"#f85149","HIGH":"#ffa657","MEDIUM":"#e3b341","LOW":"#3fb950"}[rl]
        fig_g = go.Figure(go.Indicator(mode="gauge+number", value=avg_risk,
            title={"text":"Risk Score","font":{"color":"#e6edf3"}},
            number={"font":{"color":"#58a6ff"}},
            gauge={"axis":{"range":[0,100]},"bar":{"color":clr},"bgcolor":"#161b22",
                   "steps":[{"range":[0,25],"color":"rgba(46,204,113,0.12)"},
                             {"range":[25,50],"color":"rgba(241,196,15,0.12)"},
                             {"range":[50,75],"color":"rgba(230,126,34,0.12)"},
                             {"range":[75,100],"color":"rgba(231,76,60,0.12)"}]}))
        fig_g.update_layout(height=280,**PT,margin=dict(t=40,b=0,l=10,r=10))
        st.plotly_chart(fig_g, use_container_width=True)
        st.markdown(f"<p style='text-align:center;font-size:1.4rem;color:{clr};font-weight:700'>{rl}</p>", unsafe_allow_html=True)

    ca,cb = st.columns(2)
    with ca:
        atk = qdf("SELECT attack_type, SUM(event_count) AS cnt FROM mart_attack_summary GROUP BY 1")
        if not atk.empty:
            fig=px.pie(atk,values="cnt",names="attack_type",title="Attack Type Distribution",
                       color_discrete_sequence=px.colors.qualitative.Bold,hole=0.45)
            show(fig,h=300)
    with cb:
        kc = qdf("SELECT kill_chain_phase, SUM(event_count) AS cnt FROM mart_mitre_coverage GROUP BY 1 ORDER BY 2 DESC")
        if not kc.empty:
            fig=px.bar(kc,x="cnt",y="kill_chain_phase",orientation="h",
                       title="MITRE Kill Chain Phases",color="cnt",color_continuous_scale="Reds")
            show(fig,h=300)


# =============================================================================
# KPI DASHBOARD
# =============================================================================
elif page == "KPI Dashboard":
    st.title("KPI Dashboard")
    kpi_df = qlim(f"SELECT * FROM mart_kpi_daily WHERE {DR} ORDER BY event_date")
    if kpi_df.empty:
        st.warning("No data in selected range.")
        st.stop()
    kpi_df["week"] = pd.to_datetime(kpi_df["event_date"]).dt.isocalendar().week.astype(int)
    kpi_df["dow"]  = pd.to_datetime(kpi_df["event_date"]).dt.day_name()
    fig=px.density_heatmap(kpi_df,x="week",y="dow",z="total_events",title="Activity Heatmap",
        color_continuous_scale="Blues",
        category_orders={"dow":["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]})
    show(fig,h=280)
    c1,c2=st.columns(2)
    with c1:
        fig=go.Figure()
        for col2,clr in [("ids_alerts","#f85149"),("auth_failures","#ffa657"),("fw_drops","#58a6ff"),("attack_events","#d2a8ff")]:
            fig.add_trace(go.Scatter(x=kpi_df["event_date"],y=kpi_df[col2],name=col2.replace("_"," ").title(),line=dict(color=clr,width=1.8)))
        fig.update_layout(title="Security Signal Trends",legend=dict(orientation="h",y=-0.2))
        show(fig,h=300)
    with c2:
        fig=go.Figure()
        fig.add_trace(go.Bar(x=kpi_df["event_date"],y=kpi_df["successful_logins"],name="Successful",marker_color="#3fb950"))
        fig.add_trace(go.Bar(x=kpi_df["event_date"],y=kpi_df["auth_failures"],name="Failed",marker_color="#f85149"))
        fig.update_layout(title="Login Success vs Failure",barmode="stack",legend=dict(orientation="h",y=-0.2))
        show(fig,h=300)
    rsk=qlim(f"SELECT * FROM mart_risk_score_daily WHERE {DR} ORDER BY event_date")
    if not rsk.empty:
        clrs={"CRITICAL":"#f85149","HIGH":"#ffa657","MEDIUM":"#e3b341","LOW":"#3fb950"}
        fig=go.Figure()
        for lvl,grp in rsk.groupby("risk_level"):
            fig.add_trace(go.Scatter(x=grp["event_date"],y=grp["risk_score"],mode="markers",name=lvl,marker=dict(color=clrs.get(lvl,"#aaa"),size=9)))
        fig.add_trace(go.Scatter(x=rsk["event_date"],y=rsk["risk_score"],mode="lines",showlegend=False,line=dict(color="white",width=1,dash="dot")))
        fig.update_layout(title="Daily Risk Score",legend=dict(orientation="h",y=-0.2))
        show(fig,h=280)
    st.markdown("#### Raw KPI Table")
    st.dataframe(kpi_df.drop(columns=["week","dow"],errors="ignore"),use_container_width=True,height=300)


# =============================================================================
# NETWORK & FIREWALL
# =============================================================================
elif page == "Network & Firewall":
    st.title("Network & Firewall Analytics")
    t1,t2,t3,t4=st.tabs(["Traffic","Top Talkers","Port Scans","Firewall"])
    with t1:
        ext=qlim(f"SELECT CAST(DATE_TRUNC('day',hour_window) AS DATE) AS dt,SUM(inbound_external) AS inb,SUM(outbound_external) AS out FROM mart_external_traffic WHERE CAST(DATE_TRUNC('day',hour_window) AS DATE) BETWEEN '{d_start}' AND '{d_end}' GROUP BY 1 ORDER BY 1")
        if not ext.empty:
            fig=go.Figure()
            fig.add_trace(go.Scatter(x=ext["dt"],y=ext["inb"],name="Inbound",fill="tozeroy",line=dict(color="#f85149")))
            fig.add_trace(go.Scatter(x=ext["dt"],y=ext["out"],name="Outbound",fill="tozeroy",line=dict(color="#58a6ff")))
            fig.update_layout(title="External Traffic Flow")
            show(fig,h=280)
        proto=qdf(f"SELECT protocol,SUM(event_count) AS cnt FROM mart_protocol_dist WHERE {DR} GROUP BY 1 ORDER BY 2 DESC LIMIT 10")
        if not proto.empty:
            p1,p2=st.columns(2)
            with p1:
                fig=px.pie(proto,values="cnt",names="protocol",title="Protocol Distribution",hole=0.4,color_discrete_sequence=px.colors.qualitative.Set3)
                show(fig,h=260)
            with p2:
                fig=px.bar(proto,x="protocol",y="cnt",title="Events by Protocol",color="cnt",color_continuous_scale="Blues")
                show(fig,h=260)
    with t2:
        tk=qdf(f"SELECT src_ip,connection_count,total_bytes,unique_destinations,unique_dest_ports FROM mart_top_talkers ORDER BY connection_count DESC LIMIT {TOP_N}")
        if not tk.empty:
            fig=px.scatter(tk,x="connection_count",y="unique_destinations",size="total_bytes",color="unique_dest_ports",hover_data=["src_ip"],title="Top Talkers",color_continuous_scale="Reds",size_max=40)
            show(fig,h=360)
            st.dataframe(tk,use_container_width=True)
    with t3:
        sc=qdf(f"SELECT src_ip,SUM(unique_ports_targeted) AS ports,scan_risk_level FROM mart_port_scan_suspects GROUP BY 1,3 ORDER BY 2 DESC LIMIT {TOP_N}")
        if not sc.empty:
            fig=px.bar(sc,x="src_ip",y="ports",color="scan_risk_level",color_discrete_map={"HIGH":"#f85149","MEDIUM":"#ffa657","LOW":"#3fb950"},title="Port Scan Suspects")
            fig.update_layout(xaxis_tickangle=-45)
            show(fig,h=320)
    with t4:
        fw=qlim(f"SELECT event_date,event_action,SUM(event_count) AS ev FROM mart_firewall_summary WHERE {DR} GROUP BY 1,2 ORDER BY 1")
        if not fw.empty:
            fig=px.area(fw,x="event_date",y="ev",color="event_action",title="Firewall Actions",color_discrete_map={"drop":"#f85149","accept":"#3fb950","reject":"#ffa657"})
            show(fig,h=280)
        bl=qdf(f"SELECT src_ip,block_count,targeted_ports,targeted_hosts FROM mart_fw_blocked_sources ORDER BY block_count DESC LIMIT {TOP_N}")
        if not bl.empty:
            fig=px.treemap(bl,path=["src_ip"],values="block_count",color="targeted_ports",title="Top Blocked IPs",color_continuous_scale="Reds")
            show(fig,h=320)


# =============================================================================
# THREAT INTELLIGENCE
# =============================================================================
elif page == "Threat Intelligence":
    st.title("Threat Intelligence")
    ids=qlim(f"SELECT event_date,SUM(alert_count) AS alerts,SUM(unique_sources) AS srcs FROM mart_ids_alerts WHERE {DR} GROUP BY 1 ORDER BY 1")
    ti=qlim(f"SELECT * FROM mart_threat_intel WHERE {DR} ORDER BY event_date")
    c1,c2=st.columns(2)
    with c1:
        if not ids.empty:
            fig=make_subplots(specs=[[{"secondary_y":True}]])
            fig.add_trace(go.Bar(x=ids["event_date"],y=ids["alerts"],name="IDS Alerts",marker_color="#f85149"),secondary_y=False)
            fig.add_trace(go.Scatter(x=ids["event_date"],y=ids["srcs"],name="Attacker IPs",line=dict(color="#ffa657")),secondary_y=True)
            fig.update_layout(title="IDS Alerts",legend=dict(orientation="h",y=-0.2),height=300,**PT)
            st.plotly_chart(fig,use_container_width=True)
    with c2:
        if not ti.empty:
            fig=px.area(ti,x="event_date",y="indicator_count",title="Threat Intel Indicators",color_discrete_sequence=["#d2a8ff"])
            show(fig,h=300)
    sigs=qdf(f"SELECT signature,SUM(alert_count) AS cnt FROM mart_ids_alerts WHERE {DR} GROUP BY 1 ORDER BY 2 DESC LIMIT 12")
    if not sigs.empty:
        fig=px.bar(sigs,x="cnt",y="signature",orientation="h",title="Top IDS Signatures",color="cnt",color_continuous_scale="Reds")
        show(fig,h=380)
    dns_t=qdf(f"SELECT * FROM mart_dns_summary WHERE possible_dns_tunnel OR possible_dga ORDER BY txt_queries DESC LIMIT {TOP_N}")
    if not dns_t.empty:
        st.markdown("#### DNS Tunnelling / DGA Suspects")
        st.dataframe(dns_t,use_container_width=True)


# =============================================================================
# AUTH & IDENTITY
# =============================================================================
elif page == "Auth & Identity":
    st.title("Authentication & Identity")
    t1,t2,t3=st.tabs(["Login Trends","Brute Force","After-Hours"])
    with t1:
        auth=qlim(f"SELECT event_date,SUM(failures) AS failures,SUM(successes) AS successes,ROUND(AVG(failure_rate_pct),2) AS rate FROM mart_auth_trend WHERE {DR} GROUP BY 1 ORDER BY 1")
        if not auth.empty:
            fig=make_subplots(specs=[[{"secondary_y":True}]])
            fig.add_trace(go.Bar(x=auth["event_date"],y=auth["successes"],name="Successes",marker_color="#3fb950"),secondary_y=False)
            fig.add_trace(go.Bar(x=auth["event_date"],y=auth["failures"],name="Failures",marker_color="#f85149"),secondary_y=False)
            fig.add_trace(go.Scatter(x=auth["event_date"],y=auth["rate"],name="Failure Rate %",line=dict(color="#e3b341",width=2)),secondary_y=True)
            fig.update_layout(title="Login Trends",barmode="group",legend=dict(orientation="h",y=-0.2),height=340,**PT)
            st.plotly_chart(fig,use_container_width=True)
    with t2:
        bf=qdf(f"SELECT src_ip,username,failure_count,severity,targets FROM mart_brute_force ORDER BY failure_count DESC LIMIT {TOP_N}")
        if not bf.empty:
            fig=px.scatter(bf,x="failure_count",y="username",size="failure_count",color="severity",
                color_discrete_map={"CRITICAL":"#f85149","HIGH":"#ffa657","MEDIUM":"#e3b341","LOW":"#3fb950"},
                title="Brute Force Suspects",hover_data=["src_ip"])
            show(fig,h=360)
        else:
            st.info("No brute-force data.")
    with t3:
        ah=qdf(f"SELECT username,login_hour,COUNT(*) AS cnt FROM mart_afterhours_logins GROUP BY 1,2 ORDER BY 3 DESC LIMIT {TOP_N}")
        if not ah.empty:
            fig=px.density_heatmap(ah,x="login_hour",y="username",z="cnt",title="After-Hours Login Heatmap",color_continuous_scale="Reds")
            show(fig,h=360)


# =============================================================================
# ENDPOINT & PROCESS
# =============================================================================
elif page == "Endpoint & Process":
    st.title("Endpoint & Process Analytics")
    t1,t2,t3=st.tabs(["Process Risk","PowerShell","Linux / SSH"])
    with t1:
        risk=qdf("SELECT risk_classification,COUNT(*) AS cnt FROM mart_suspicious_processes GROUP BY 1")
        if not risk.empty:
            c1,c2=st.columns(2)
            with c1:
                fig=px.pie(risk,values="cnt",names="risk_classification",title="Process Risk",hole=0.45,
                    color="risk_classification",color_discrete_map={"MALICIOUS":"#f85149","SUSPICIOUS":"#ffa657","NORMAL":"#3fb950"})
                show(fig,h=280)
            with c2:
                tp=qdf(f"SELECT process_image,SUM(execution_count) AS cnt,risk_classification FROM mart_suspicious_processes WHERE risk_classification!='NORMAL' GROUP BY 1,3 ORDER BY 2 DESC LIMIT {TOP_N}")
                if not tp.empty:
                    fig=px.bar(tp,x="cnt",y="process_image",orientation="h",color="risk_classification",
                        color_discrete_map={"MALICIOUS":"#f85149","SUSPICIOUS":"#ffa657"},title="Risky Processes")
                    show(fig,h=280)
        sp=qdf(f"SELECT event_date,hostname,username,process_image,LEFT(command_line,60) AS cmd,risk_classification FROM mart_suspicious_processes WHERE risk_classification IN ('MALICIOUS','SUSPICIOUS') ORDER BY risk_classification LIMIT {TOP_N}")
        st.markdown("#### Suspicious Processes")
        st.dataframe(sp,use_container_width=True,height=240)
    with t2:
        ps=qdf("SELECT risk_level,COUNT(*) AS cnt FROM mart_risky_powershell GROUP BY 1 ORDER BY cnt DESC")
        if not ps.empty:
            fig=px.funnel(ps,x="cnt",y="risk_level",title="PowerShell Risk Funnel",color="risk_level",
                color_discrete_map={"CRITICAL":"#f85149","HIGH":"#ffa657","INFORMATIONAL":"#58a6ff"})
            show(fig,h=280)
        psd=qdf(f"SELECT event_date,hostname,username,LEFT(script_block,100) AS preview,risk_level FROM mart_risky_powershell WHERE risk_level IN ('CRITICAL','HIGH') LIMIT {TOP_N}")
        st.markdown("#### High Risk PowerShell")
        st.dataframe(psd,use_container_width=True)
    with t3:
        sl=qdf(f"SELECT process_name,SUM(event_count) AS cnt,severity FROM mart_syslog_summary WHERE {DR} GROUP BY 1,3 ORDER BY 2 DESC LIMIT 15")
        if not sl.empty:
            fig=px.bar(sl,x="process_name",y="cnt",color="severity",
                color_discrete_map={"err":"#f85149","warning":"#ffa657","info":"#58a6ff","debug":"#8b949e"},
                title="Linux Syslog by Severity")
            fig.update_layout(xaxis_tickangle=-45)
            show(fig,h=300)
        ssh=qlim(f"SELECT * FROM mart_ssh_attempts WHERE {DR} ORDER BY event_date")
        if not ssh.empty:
            fig=go.Figure()
            fig.add_trace(go.Bar(x=ssh["event_date"],y=ssh["failed_ssh"],name="Failed SSH",marker_color="#f85149"))
            fig.add_trace(go.Bar(x=ssh["event_date"],y=ssh["successful_ssh"],name="Successful SSH",marker_color="#3fb950"))
            fig.add_trace(go.Scatter(x=ssh["event_date"],y=ssh["sudo_uses"],name="Sudo Uses",line=dict(color="#e3b341")))
            fig.update_layout(title="SSH Activity",barmode="stack",legend=dict(orientation="h",y=-0.2))
            show(fig,h=280)


# =============================================================================
# ATTACK & KILL CHAIN
# =============================================================================
elif page == "Attack & Kill Chain":
    st.title("Attack Scenarios & MITRE ATT&CK")
    atk=qdf("SELECT * FROM mart_attack_summary ORDER BY event_count DESC")
    mit=qdf("SELECT * FROM mart_mitre_coverage ORDER BY event_count DESC")
    if not atk.empty:
        c1,c2=st.columns(2)
        with c1:
            fig=px.bar(atk,x="attack_type",y="event_count",color="attack_type",title="Events by Attack Type",color_discrete_sequence=px.colors.qualitative.Bold)
            show(fig,h=280)
        with c2:
            fig=px.scatter(atk,x="duration_minutes",y="hosts_affected",size="event_count",color="attack_type",title="Duration vs Hosts",color_discrete_sequence=px.colors.qualitative.Bold)
            show(fig,h=280)
    if not mit.empty:
        agg=mit.groupby(["kill_chain_phase","attack_type"])["event_count"].sum().reset_index()
        fig=px.density_heatmap(agg,x="attack_type",y="kill_chain_phase",z="event_count",title="Kill Chain Phase x Attack Type",color_continuous_scale="RdYlGn_r")
        show(fig,h=360)
        fig=px.sunburst(mit,path=["kill_chain_phase","mitre_technique"],values="event_count",title="MITRE ATT&CK Kill Chain",color="event_count",color_continuous_scale="Reds")
        show(fig,h=480)
    tl=qdf(f"SELECT event_time,attack_type,mitre_technique,hostname FROM fact_events WHERE attack_type IS NOT NULL AND attack_type!='' ORDER BY event_time LIMIT {TOP_N}")
    if not tl.empty:
        fig=px.scatter(tl,x="event_time",y="attack_type",color="mitre_technique",symbol="hostname",title="Attack Event Timeline")
        show(fig,h=320)


# =============================================================================
# ANOMALY DETECTION
# =============================================================================
elif page == "Anomaly Detection":
    st.title("Statistical Anomaly Detection")
    anom=qlim("SELECT * FROM mart_host_anomaly ORDER BY z_score DESC")
    if anom.empty:
        st.warning("No anomaly data.")
        st.stop()
    c1,c2,c3,c4=st.columns(4)
    for col,lbl in zip([c1,c2,c3,c4],["Anomalous","Elevated","Normal","Low Activity"]):
        col.metric(lbl,int(anom[anom["anomaly_label"]==lbl].shape[0]))
    ca,cb=st.columns(2)
    with ca:
        fig=px.histogram(anom,x="z_score",color="anomaly_label",title="Z-Score Distribution",
            color_discrete_map={"Anomalous":"#f85149","Elevated":"#ffa657","Normal":"#3fb950","Low Activity":"#8b949e"},nbins=40)
        show(fig,h=300)
    with cb:
        top=anom[anom["anomaly_label"]=="Anomalous"].nlargest(15,"z_score")
        if not top.empty:
            fig=px.bar(top,x="hostname",y="z_score",color="event_count",title="Top Anomalous Hosts",color_continuous_scale="Reds")
            fig.update_layout(xaxis_tickangle=-45)
            show(fig,h=300)
    fig=px.scatter(anom,x="mean",y="event_count",color="anomaly_label",size="z_score",
        hover_data=["hostname"],title="Expected vs Actual Events",
        color_discrete_map={"Anomalous":"#f85149","Elevated":"#ffa657","Normal":"#3fb950","Low Activity":"#8b949e"})
    show(fig,h=380)
    st.dataframe(anom[anom["anomaly_label"]=="Anomalous"].nlargest(25,"z_score"),use_container_width=True,height=280)


# =============================================================================
# APPLICATION ANALYTICS
# =============================================================================
elif page == "Application Analytics":
    st.title("Web Application Analytics")
    http=qlim(f"SELECT * FROM mart_http_status WHERE {DR} ORDER BY event_date")
    err=qlim(f"SELECT * FROM mart_web_error_trend WHERE CAST(DATE_TRUNC('day',hour_window) AS DATE) BETWEEN '{d_start}' AND '{d_end}' ORDER BY hour_window")
    if not http.empty:
        http["group"]=http["status_code"].astype(str).apply(
            lambda x:"2xx OK" if x.startswith("2") else "3xx Redirect" if x.startswith("3") else "4xx Client Error" if x.startswith("4") else "5xx Server Error")
        c1,c2=st.columns(2)
        with c1:
            agg=http.groupby("group")["request_count"].sum().reset_index()
            fig=px.pie(agg,values="request_count",names="group",title="HTTP Response Groups",hole=0.4,
                color="group",color_discrete_map={"2xx OK":"#3fb950","3xx Redirect":"#58a6ff","4xx Client Error":"#ffa657","5xx Server Error":"#f85149"})
            show(fig,h=280)
        with c2:
            ma=http.groupby("method")["request_count"].sum().reset_index()
            fig=px.bar(ma,x="method",y="request_count",title="HTTP Methods",color="request_count",color_continuous_scale="Blues")
            show(fig,h=280)
    if not err.empty:
        fig=go.Figure()
        fig.add_trace(go.Scatter(x=err["hour_window"],y=err["total_requests"],name="Requests",fill="tozeroy",line=dict(color="#58a6ff")))
        fig.add_trace(go.Scatter(x=err["hour_window"],y=err["errors"],name="Errors",fill="tozeroy",line=dict(color="#f85149")))
        fig.update_layout(title="Hourly Requests & Errors",legend=dict(orientation="h",y=-0.2))
        show(fig,h=300)


# =============================================================================
# NLP SQL EXPLORER
# =============================================================================
elif page == "NLP SQL Explorer":
    st.title("Natural Language SQL Explorer")
    if _HAS_HELPERS:
        render_nlp_page()
    else:
        st.info("NLP module available in local mode only.")
        st.markdown("### Direct SQL Query")
        sql = st.text_area("Enter SQL:", "SELECT * FROM mart_kpi_daily ORDER BY event_date LIMIT 10")
        if st.button("Run"):
            st.dataframe(qdf(sql), use_container_width=True)


# =============================================================================
# STORY & DSS
# =============================================================================
elif page == "Story & DSS":
    st.title("Security Story & Decision Support")
    if _HAS_HELPERS:
        kpi=qdf(f"SELECT SUM(k.total_events) AS te,SUM(k.ids_alerts) AS ia,SUM(k.attack_events) AS ae,SUM(k.auth_failures) AS af,AVG(r.risk_score) AS rs FROM mart_kpi_daily k JOIN mart_risk_score_daily r USING(event_date) WHERE k.{DR}")
        atks=qdf("SELECT * FROM mart_attack_summary")
        brt=qdf("SELECT COUNT(*) AS cnt FROM mart_brute_force WHERE severity='CRITICAL'")
        dns=qdf("SELECT COUNT(*) AS cnt FROM mart_dns_summary WHERE possible_dns_tunnel")
        render_story_dss(kpi, atks, brt, dns, d_start, d_end)
    else:
        # Inline summary when helpers not available
        kpi=qdf(f"SELECT SUM(k.total_events) AS te,SUM(k.ids_alerts) AS ia,SUM(k.attack_events) AS ae,SUM(k.auth_failures) AS af,AVG(r.risk_score) AS rs FROM mart_kpi_daily k JOIN mart_risk_score_daily r USING(event_date) WHERE k.{DR}")
        if not kpi.empty:
            rs = float(kpi["rs"].iloc[0] or 0)
            rl = "CRITICAL" if rs>=75 else "HIGH" if rs>=50 else "MEDIUM" if rs>=25 else "LOW"
            clr = {"CRITICAL":"#f85149","HIGH":"#ffa657","MEDIUM":"#e3b341","LOW":"#3fb950"}[rl]
            st.markdown(f"""<div class="story-box">
            <strong>Period:</strong> {d_start} to {d_end}<br>
            <strong>Total Events:</strong> {fmt_number(kpi['te'].iloc[0])} &nbsp;|&nbsp;
            <strong>IDS Alerts:</strong> {fmt_number(kpi['ia'].iloc[0])} &nbsp;|&nbsp;
            <strong>Attack Events:</strong> {fmt_number(kpi['ae'].iloc[0])} &nbsp;|&nbsp;
            <strong>Auth Failures:</strong> {fmt_number(kpi['af'].iloc[0])}<br>
            <strong>Risk Level:</strong> <span style='color:{clr};font-weight:700'>{rl}</span> ({rs:.1f}/100)
            </div>""", unsafe_allow_html=True)
        atks=qdf("SELECT * FROM mart_attack_summary")
        if not atks.empty:
            st.markdown("#### Attack Scenarios Detected")
            st.dataframe(atks, use_container_width=True)
        st.markdown("#### Recommendations")
        for r in ["Enforce MFA on all privileged accounts","Review firewall DROP rules for persistent offenders",
                  "Investigate anomalous hosts with Z-score > 3","Tune IDS signatures to reduce false positives",
                  "Enable DNS monitoring for tunnelling detection"]:
            st.markdown(f"- {r}")
