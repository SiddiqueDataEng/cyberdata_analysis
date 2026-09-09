"""
CYBERSECURITY DATA ENGINEERING — ANALYTICS DASHBOARD
"""
import streamlit as st
import duckdb
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from config import DB_PATH, COLORS, ATTACK_COLORS
from analytics_helpers import fmt_number, color_risk, render_nlp_page, render_story_dss
from tooltips import inject_css, help_tip, add_chart_tooltip, get_tip

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberData Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""<style>
[data-testid="stAppViewContainer"]{background:#0d1117}
[data-testid="stSidebar"]{background:#161b22;border-right:1px solid #30363d}
[data-testid="stSidebar"] *{color:#e6edf3!important}
h1,h2,h3,h4{color:#58a6ff!important}
.kpi-card{background:linear-gradient(135deg,#161b22,#21262d);
  border:1px solid #30363d;border-radius:12px;padding:22px 16px;
  text-align:center;margin:6px 2px;box-shadow:0 4px 15px rgba(0,0,0,.4)}
.kpi-value{font-size:2rem;font-weight:800;color:#58a6ff}
.kpi-label{font-size:.82rem;color:#8b949e;margin-top:6px;text-transform:uppercase}
.story-box{background:#161b22;border:1px solid #30363d;
  border-left:4px solid #58a6ff;border-radius:10px;padding:20px 24px;margin:12px 0}
.dss-box{background:#161b22;border:1px solid #30363d;border-radius:10px;
  padding:16px 20px;margin:10px 0}
[data-testid="stMetric"]{background:#161b22;border:1px solid #30363d;
  border-radius:10px;padding:14px!important}
[data-testid="stMetricValue"]{color:#58a6ff!important}
</style>""", unsafe_allow_html=True)

inject_css()

# ── DB connection ─────────────────────────────────────────────────────────────
@st.cache_resource
def get_con():
    return duckdb.connect(DB_PATH, read_only=True)


@st.cache_data(ttl=300)
def qdf(sql: str) -> pd.DataFrame:
    try:
        return get_con().execute(sql).df()
    except Exception as e:
        return pd.DataFrame({"error": [str(e)]})


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ CyberData Analytics")
    st.caption("Data Engineering for Cybersecurity")
    st.divider()

    page = st.radio("Navigation", [
        "🏠 Executive Summary",
        "📊 KPI Dashboard",
        "🌐 Network & Firewall",
        "🚨 Threat Intelligence",
        "🔐 Auth & Identity",
        "💻 Endpoint & Process",
        "⚔️ Attack & Kill Chain",
        "🔍 Anomaly Detection",
        "🌍 Application Analytics",
        "🧠 NLP SQL Explorer",
        "📖 Story & DSS",
    ])

    st.divider()
    dr = qdf("SELECT MIN(event_date)::DATE AS mn, MAX(event_date)::DATE AS mx FROM mart_kpi_daily")
    if not dr.empty and "mn" in dr.columns and not pd.isna(dr["mn"].iloc[0]):
        mn = pd.to_datetime(dr["mn"].iloc[0]).date()
        mx = pd.to_datetime(dr["mx"].iloc[0]).date()
    else:
        mn = datetime(2024, 1, 1).date()
        mx = datetime(2024, 1, 30).date()

    d_start, d_end = st.date_input("Date Range", value=(mn, mx), min_value=mn, max_value=mx)
    st.caption(f"DB: `{Path(DB_PATH).name}`")

DRANGE  = f"event_date BETWEEN '{d_start}' AND '{d_end}'"
TRANGE  = f"event_time  BETWEEN '{d_start}' AND '{d_end} 23:59:59'"

PLOTLY_THEME = dict(template="plotly_dark", paper_bgcolor="#0d1117", plot_bgcolor="#0d1117")


def show(fig, key=None, h=350):
    fig.update_layout(height=h, **PLOTLY_THEME)
    if key:
        add_chart_tooltip(fig, key)
    st.plotly_chart(fig, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: EXECUTIVE SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
if page == "🏠 Executive Summary":
    st.title("🛡️ Executive Summary")
    st.caption(f"Period: **{d_start}** → **{d_end}**")

    # KPIs
    kpi = qdf(f"""SELECT
        SUM(total_events) AS te, SUM(ids_alerts) AS ia,
        SUM(attack_events) AS ae, SUM(auth_failures) AS af,
        SUM(fw_drops) AS fd, ROUND(AVG(active_hosts),0) AS ah,
        ROUND(SUM(total_bytes)/1e9,2) AS gb,
        SUM(external_connections) AS ec, SUM(ps_executions) AS ps
        FROM mart_kpi_daily WHERE {DRANGE}""")
    rdf = qdf(f"SELECT AVG(risk_score) AS rs FROM mart_risk_score_daily WHERE {DRANGE}")
    avg_risk = float(rdf["rs"].iloc[0]) if not rdf.empty and not pd.isna(rdf["rs"].iloc[0]) else 0

    c1,c2,c3,c4,c5 = st.columns(5)
    for col, icon, val, label in [
        (c1,"📋", fmt_number(kpi["te"].iloc[0]),  "Total Events"),
        (c2,"🚨", fmt_number(kpi["ia"].iloc[0]),  "IDS Alerts"),
        (c3,"⚔️", fmt_number(kpi["ae"].iloc[0]),  "Attack Events"),
        (c4,"🔒", fmt_number(kpi["af"].iloc[0]),  "Auth Failures"),
        (c5,"🧱", fmt_number(kpi["fd"].iloc[0]),  "FW Blocks"),
    ]:
        col.markdown(f'<div class="kpi-card"><div class="kpi-value">{icon} {val}</div>'
                     f'<div class="kpi-label">{label}</div></div>', unsafe_allow_html=True)

    st.divider()
    m1,m2,m3,m4 = st.columns(4)
    m1.metric("Avg Active Hosts/Day", f"{kpi['ah'].iloc[0]:.0f}")
    m2.metric("Data Volume", f"{kpi['gb'].iloc[0]:.1f} GB")
    m3.metric("External Connections", fmt_number(kpi["ec"].iloc[0]))
    m4.metric("PowerShell Executions", fmt_number(kpi["ps"].iloc[0]))

    st.divider()
    col_l, col_r = st.columns([3, 1])

    with col_l:
        trend = qdf(f"""SELECT event_date, total_events, ids_alerts, attack_events, auth_failures
            FROM mart_kpi_daily WHERE {DRANGE} ORDER BY event_date""")
        if not trend.empty:
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=trend["event_date"], y=trend["total_events"],
                name="Total Events", fill="tozeroy",
                fillcolor="rgba(88,166,255,0.08)", line=dict(color="#58a6ff", width=2)))
            fig.add_trace(go.Scatter(x=trend["event_date"], y=trend["ids_alerts"],
                name="IDS Alerts", line=dict(color="#f85149", width=2)))
            fig.add_trace(go.Scatter(x=trend["event_date"], y=trend["attack_events"],
                name="Attack Events", line=dict(color="#d2a8ff", width=2, dash="dot")))
            fig.add_trace(go.Scatter(x=trend["event_date"], y=trend["auth_failures"],
                name="Auth Failures", line=dict(color="#ffa657", width=1.5)))
            fig.update_layout(title="Daily Security Event Trends", legend=dict(orientation="h"))
            show(fig, "daily_event_volume", h=340)

    with col_r:
        fig_g = go.Figure(go.Indicator(
            mode="gauge+number",
            value=avg_risk,
            title={"text": "Risk Score", "font": {"color": "#e6edf3"}},
            number={"font": {"color": "#58a6ff"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#8b949e"},
                "bar":  {"color": color_risk(avg_risk)},
                "bgcolor": "#161b22",
                "steps": [
                    {"range": [0,  25], "color": "rgba(46,204,113,0.15)"},
                    {"range": [25, 50], "color": "rgba(241,196,15,0.15)"},
                    {"range": [50, 75], "color": "rgba(230,126,34,0.15)"},
                    {"range": [75,100], "color": "rgba(231,76,60,0.15)"},
                ],
            }
        ))
        fig_g.update_layout(height=300, **PLOTLY_THEME, margin=dict(t=40,b=0,l=20,r=20))
        st.plotly_chart(fig_g, use_container_width=True)
        risk_label = "CRITICAL" if avg_risk>=75 else "HIGH" if avg_risk>=50 else "MEDIUM" if avg_risk>=25 else "LOW"
        clr = {"CRITICAL":"#f85149","HIGH":"#ffa657","MEDIUM":"#e3b341","LOW":"#3fb950"}[risk_label]
        st.markdown(f"<p style='text-align:center;font-size:1.3rem;color:{clr};font-weight:700'>{risk_label}</p>",
                    unsafe_allow_html=True)

    col_a, col_b = st.columns(2)
    with col_a:
        atk = qdf("SELECT attack_type, SUM(event_count) AS cnt FROM mart_attack_summary GROUP BY 1")
        if not atk.empty and "attack_type" in atk.columns:
            fig = px.pie(atk, values="cnt", names="attack_type", title="Attack Type Distribution",
                         color_discrete_sequence=px.colors.qualitative.Bold, hole=0.45)
            show(fig, "attack_type_pie", h=300)

    with col_b:
        kc = qdf("SELECT kill_chain_phase, SUM(event_count) AS cnt FROM mart_mitre_coverage GROUP BY 1 ORDER BY 2 DESC")
        if not kc.empty:
            fig = px.bar(kc, x="cnt", y="kill_chain_phase", orientation="h",
                         title="MITRE Kill Chain Phases",
                         color="cnt", color_continuous_scale="Reds")
            show(fig, "kill_chain_bar", h=300)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: KPI DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📊 KPI Dashboard":
    st.title("📊 KPI Dashboard")

    kpi_df = qdf(f"SELECT * FROM mart_kpi_daily WHERE {DRANGE} ORDER BY event_date")
    if kpi_df.empty:
        st.warning("No data in selected date range.")
        st.stop()

    # Heatmap
    kpi_df["week"] = pd.to_datetime(kpi_df["event_date"]).dt.isocalendar().week.astype(int)
    kpi_df["dow"]  = pd.to_datetime(kpi_df["event_date"]).dt.day_name()
    fig = px.density_heatmap(kpi_df, x="week", y="dow", z="total_events",
        title="Activity Heatmap — Events by Week & Day of Week",
        color_continuous_scale="Blues",
        category_orders={"dow": ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]})
    show(fig, "activity_heatmap", h=280)

    c1, c2 = st.columns(2)
    with c1:
        fig = go.Figure()
        for col, clr in [("ids_alerts","#f85149"),("auth_failures","#ffa657"),
                          ("fw_drops","#58a6ff"),("attack_events","#d2a8ff")]:
            fig.add_trace(go.Scatter(x=kpi_df["event_date"], y=kpi_df[col],
                name=col.replace("_"," ").title(), line=dict(color=clr, width=1.8)))
        fig.update_layout(title="Security Signal Trends", legend=dict(orientation="h"))
        show(fig, "security_trends", h=320)

    with c2:
        fig = go.Figure()
        fig.add_trace(go.Bar(x=kpi_df["event_date"], y=kpi_df["successful_logins"],
            name="Successful", marker_color="#3fb950"))
        fig.add_trace(go.Bar(x=kpi_df["event_date"], y=kpi_df["auth_failures"],
            name="Failed", marker_color="#f85149"))
        fig.update_layout(title="Login Success vs Failure", barmode="stack",
            legend=dict(orientation="h"))
        show(fig, "login_stacked", h=320)

    # Risk score scatter
    rsk = qdf(f"SELECT * FROM mart_risk_score_daily WHERE {DRANGE} ORDER BY event_date")
    if not rsk.empty:
        clrs = {"CRITICAL":"#f85149","HIGH":"#ffa657","MEDIUM":"#e3b341","LOW":"#3fb950"}
        fig = go.Figure()
        for lvl, grp in rsk.groupby("risk_level"):
            fig.add_trace(go.Scatter(x=grp["event_date"], y=grp["risk_score"],
                mode="markers", name=lvl,
                marker=dict(color=clrs.get(lvl,"#aaa"), size=9)))
        fig.add_trace(go.Scatter(x=rsk["event_date"], y=rsk["risk_score"],
            mode="lines", name="Trend", line=dict(color="white", width=1, dash="dot"),
            showlegend=False))
        fig.update_layout(title="Daily Risk Score — Level Classification",
            legend=dict(orientation="h"))
        show(fig, "risk_scatter", h=300)

    st.markdown("#### Raw KPI Table")
    st.dataframe(kpi_df.drop(columns=["week","dow"], errors="ignore"),
                 use_container_width=True, height=320)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: NETWORK & FIREWALL
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🌐 Network & Firewall":
    st.title("🌐 Network & Firewall Analytics")

    tab1, tab2, tab3, tab4 = st.tabs(["Traffic Overview", "Top Talkers", "Port Scans", "Firewall"])

    with tab1:
        ext = qdf(f"""SELECT DATE_TRUNC('day', hour_window)::DATE AS dt,
            SUM(inbound_external) AS inbound, SUM(outbound_external) AS outbound
            FROM mart_external_traffic
            WHERE DATE_TRUNC('day', hour_window)::DATE BETWEEN '{d_start}' AND '{d_end}'
            GROUP BY 1 ORDER BY 1""")
        if not ext.empty:
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=ext["dt"], y=ext["inbound"],
                name="Inbound", fill="tozeroy", line=dict(color="#f85149")))
            fig.add_trace(go.Scatter(x=ext["dt"], y=ext["outbound"],
                name="Outbound", fill="tozeroy", line=dict(color="#58a6ff")))
            fig.update_layout(title="External Traffic Flow")
            show(fig, "external_traffic", h=300)

        proto = qdf(f"""SELECT protocol, SUM(event_count) AS cnt
            FROM mart_protocol_dist WHERE {DRANGE} GROUP BY 1 ORDER BY 2 DESC LIMIT 10""")
        if not proto.empty:
            p1, p2 = st.columns(2)
            with p1:
                fig = px.pie(proto, values="cnt", names="protocol",
                    title="Protocol Distribution", hole=0.4,
                    color_discrete_sequence=px.colors.qualitative.Set3)
                show(fig, "protocol_pie", h=280)
            with p2:
                fig = px.bar(proto, x="protocol", y="cnt", title="Events by Protocol",
                    color="cnt", color_continuous_scale="Blues")
                show(fig, "protocol_bar", h=280)

    with tab2:
        tk = qdf("""SELECT src_ip, connection_count, total_bytes,
            unique_destinations, unique_dest_ports
            FROM mart_top_talkers ORDER BY connection_count DESC LIMIT 30""")
        if not tk.empty:
            fig = px.scatter(tk, x="connection_count", y="unique_destinations",
                size="total_bytes", color="unique_dest_ports",
                hover_data=["src_ip"], title="Top Talkers — Connections vs Unique Destinations",
                color_continuous_scale="Reds", size_max=50)
            show(fig, "top_talkers_bubble", h=400)
            st.dataframe(tk, use_container_width=True)

    with tab3:
        sc = qdf("""SELECT src_ip, SUM(unique_ports_targeted) AS ports,
            SUM(total_attempts) AS attempts, scan_risk_level
            FROM mart_port_scan_suspects GROUP BY 1,4 ORDER BY 2 DESC LIMIT 25""")
        if not sc.empty:
            fig = px.bar(sc.head(15), x="src_ip", y="ports", color="scan_risk_level",
                color_discrete_map={"HIGH":"#f85149","MEDIUM":"#ffa657","LOW":"#3fb950"},
                title="Suspected Port Scanners — Unique Ports Targeted")
            fig.update_layout(xaxis_tickangle=-45)
            show(fig, "port_scan_bar", h=350)
            st.dataframe(sc, use_container_width=True)

    with tab4:
        fw = qdf(f"""SELECT event_date, event_action, SUM(event_count) AS events
            FROM mart_firewall_summary WHERE {DRANGE} GROUP BY 1,2 ORDER BY 1""")
        if not fw.empty:
            fig = px.area(fw, x="event_date", y="events", color="event_action",
                title="Firewall Actions Over Time",
                color_discrete_map={"drop":"#f85149","accept":"#3fb950","reject":"#ffa657"})
            show(fig, "fw_action_area", h=300)

        bl = qdf("""SELECT src_ip, block_count, targeted_ports, targeted_hosts
            FROM mart_fw_blocked_sources ORDER BY block_count DESC LIMIT 20""")
        if not bl.empty:
            fig = px.treemap(bl, path=["src_ip"], values="block_count",
                color="targeted_ports", title="Top Blocked IPs",
                color_continuous_scale="Reds")
            show(fig, "fw_blocked_treemap", h=350)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: THREAT INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🚨 Threat Intelligence":
    st.title("🚨 Threat Intelligence")

    ids = qdf(f"""SELECT event_date, SUM(alert_count) AS alerts,
        COUNT(DISTINCT signature) AS signatures, SUM(unique_sources) AS sources
        FROM mart_ids_alerts WHERE {DRANGE} GROUP BY 1 ORDER BY 1""")
    ti  = qdf(f"SELECT * FROM mart_threat_intel WHERE {DRANGE} ORDER BY event_date")

    c1, c2 = st.columns(2)
    with c1:
        if not ids.empty:
            fig = make_subplots(specs=[[{"secondary_y": True}]])
            fig.add_trace(go.Bar(x=ids["event_date"], y=ids["alerts"],
                name="IDS Alerts", marker_color="#f85149"), secondary_y=False)
            fig.add_trace(go.Scatter(x=ids["event_date"], y=ids["sources"],
                name="Unique Attacker IPs", line=dict(color="#ffa657")), secondary_y=True)
            fig.update_layout(title="IDS Alerts & Attacker IPs",
                legend=dict(orientation="h"), **PLOTLY_THEME, height=320)
            st.plotly_chart(fig, use_container_width=True)

    with c2:
        if not ti.empty:
            fig = px.area(ti, x="event_date", y="indicator_count",
                title="Threat Intel Indicators Over Time",
                color_discrete_sequence=["#d2a8ff"])
            show(fig, "ti_indicator_area", h=320)

    sigs = qdf(f"""SELECT signature, SUM(alert_count) AS cnt, SUM(unique_sources) AS src
        FROM mart_ids_alerts WHERE {DRANGE} GROUP BY 1 ORDER BY 2 DESC LIMIT 15""")
    if not sigs.empty:
        fig = px.bar(sigs, x="cnt", y="signature", orientation="h",
            title="Top IDS Signatures",
            color="cnt", color_continuous_scale="Reds")
        show(fig, "ids_signatures_bar", h=420)

    dns_t = qdf("SELECT * FROM mart_dns_summary WHERE possible_dns_tunnel OR possible_dga ORDER BY txt_queries DESC LIMIT 20")
    if not dns_t.empty:
        st.markdown("#### ⚠️ DNS Tunnelling / DGA Suspects")
        st.dataframe(dns_t, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: AUTH & IDENTITY
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🔐 Auth & Identity":
    st.title("🔐 Authentication & Identity Analytics")

    tab1, tab2, tab3 = st.tabs(["Login Trends", "Brute Force", "After-Hours"])

    with tab1:
        auth = qdf(f"""SELECT event_date, SUM(failures) AS failures,
            SUM(successes) AS successes, ROUND(AVG(failure_rate_pct),2) AS rate
            FROM mart_auth_trend WHERE {DRANGE} GROUP BY 1 ORDER BY 1""")
        if not auth.empty:
            fig = make_subplots(specs=[[{"secondary_y": True}]])
            fig.add_trace(go.Bar(x=auth["event_date"], y=auth["successes"],
                name="Successes", marker_color="#3fb950"), secondary_y=False)
            fig.add_trace(go.Bar(x=auth["event_date"], y=auth["failures"],
                name="Failures", marker_color="#f85149"), secondary_y=False)
            fig.add_trace(go.Scatter(x=auth["event_date"], y=auth["rate"],
                name="Failure Rate %", line=dict(color="#e3b341", width=2)),
                secondary_y=True)
            fig.update_layout(title="Login Trends with Failure Rate",
                barmode="group", legend=dict(orientation="h"),
                **PLOTLY_THEME, height=360)
            st.plotly_chart(fig, use_container_width=True)

        host_f = qdf(f"""SELECT hostname, SUM(failures) AS fails, SUM(successes) AS succ
            FROM mart_auth_trend WHERE {DRANGE} GROUP BY 1 ORDER BY 2 DESC LIMIT 15""")
        if not host_f.empty:
            fig = px.bar(host_f, x="hostname", y=["fails","succ"],
                title="Auth by Host (Top 15)", barmode="group",
                color_discrete_map={"fails":"#f85149","succ":"#3fb950"})
            fig.update_layout(xaxis_tickangle=-45)
            show(fig, "auth_host_bar", h=320)

    with tab2:
        bf = qdf("""SELECT src_ip, username, failure_count, severity, targets
            FROM mart_brute_force ORDER BY failure_count DESC LIMIT 30""")
        if not bf.empty:
            fig = px.scatter(bf, x="failure_count", y="username",
                size="failure_count", color="severity",
                color_discrete_map={"CRITICAL":"#f85149","HIGH":"#ffa657",
                                    "MEDIUM":"#e3b341","LOW":"#3fb950"},
                title="Brute Force — Failures by Username",
                hover_data=["src_ip","targets"])
            show(fig, "brute_force_scatter", h=400)

            sv = bf["severity"].value_counts().reset_index()
            sv.columns = ["severity","count"]
            fig = px.pie(sv, values="count", names="severity",
                title="Brute Force Severity Distribution", hole=0.5,
                color="severity",
                color_discrete_map={"CRITICAL":"#f85149","HIGH":"#ffa657",
                                    "MEDIUM":"#e3b341","LOW":"#3fb950"})
            show(fig, "brute_force_severity_pie", h=280)
        else:
            st.info("No brute-force data in selected range.")

    with tab3:
        ah = qdf("""SELECT username, hostname, login_hour, COUNT(*) AS cnt
            FROM mart_afterhours_logins GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT 100""")
        if not ah.empty:
            fig = px.density_heatmap(ah, x="login_hour", y="username", z="cnt",
                title="After-Hours Login Heatmap (Outside 7AM–7PM)",
                color_continuous_scale="Reds",
                labels={"login_hour":"Hour","cnt":"Logins"})
            show(fig, "afterhours_heatmap", h=420)
        else:
            st.info("No after-hours login data.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: ENDPOINT & PROCESS
# ══════════════════════════════════════════════════════════════════════════════
elif page == "💻 Endpoint & Process":
    st.title("💻 Endpoint & Process Analytics")

    tab1, tab2, tab3 = st.tabs(["Process Risk", "PowerShell", "Linux/SSH"])

    with tab1:
        risk = qdf("SELECT risk_classification, COUNT(*) AS cnt, SUM(execution_count) AS execs FROM mart_suspicious_processes GROUP BY 1")
        if not risk.empty:
            c1, c2 = st.columns(2)
            with c1:
                fig = px.pie(risk, values="cnt", names="risk_classification",
                    title="Process Risk Classification", hole=0.45,
                    color="risk_classification",
                    color_discrete_map={"MALICIOUS":"#f85149","SUSPICIOUS":"#ffa657","NORMAL":"#3fb950"})
                show(fig, "process_risk_pie", h=300)
            with c2:
                tp = qdf("""SELECT process_image, SUM(execution_count) AS cnt, risk_classification
                    FROM mart_suspicious_processes WHERE risk_classification!='NORMAL'
                    GROUP BY 1,3 ORDER BY 2 DESC LIMIT 15""")
                if not tp.empty:
                    fig = px.bar(tp, x="cnt", y="process_image", orientation="h",
                        color="risk_classification",
                        color_discrete_map={"MALICIOUS":"#f85149","SUSPICIOUS":"#ffa657"},
                        title="Top Risky Processes")
                    show(fig, "top_risky_processes_bar", h=300)

        sp = qdf("""SELECT event_date, hostname, username, process_image,
            LEFT(command_line,80) AS cmd, risk_classification
            FROM mart_suspicious_processes WHERE risk_classification IN ('MALICIOUS','SUSPICIOUS')
            ORDER BY risk_classification, event_date DESC LIMIT 50""")
        st.markdown("#### Suspicious Process Details")
        st.dataframe(sp, use_container_width=True, height=280)

    with tab2:
        ps = qdf("SELECT risk_level, COUNT(*) AS cnt FROM mart_risky_powershell GROUP BY 1 ORDER BY cnt DESC")
        if not ps.empty:
            fig = px.funnel(ps, x="cnt", y="risk_level", title="PowerShell Risk Funnel",
                color="risk_level",
                color_discrete_map={"CRITICAL":"#f85149","HIGH":"#ffa657","INFORMATIONAL":"#58a6ff"})
            show(fig, "ps_risk_funnel", h=300)

        ps_d = qdf("""SELECT event_date, hostname, username,
            LEFT(script_block,120) AS preview, risk_level
            FROM mart_risky_powershell WHERE risk_level IN ('CRITICAL','HIGH')
            ORDER BY risk_level, event_date DESC LIMIT 30""")
        st.markdown("#### Critical / High Risk PowerShell")
        st.dataframe(ps_d, use_container_width=True)

    with tab3:
        sl = qdf(f"""SELECT process_name, SUM(event_count) AS cnt, severity
            FROM mart_syslog_summary WHERE {DRANGE} GROUP BY 1,3 ORDER BY 2 DESC LIMIT 20""")
        if not sl.empty:
            fig = px.bar(sl, x="process_name", y="cnt", color="severity",
                color_discrete_map={"err":"#f85149","warning":"#ffa657",
                                    "info":"#58a6ff","debug":"#8b949e"},
                title="Linux Syslog by Process & Severity")
            fig.update_layout(xaxis_tickangle=-45)
            show(fig, "syslog_severity_bar", h=340)

        ssh = qdf(f"SELECT * FROM mart_ssh_attempts WHERE {DRANGE} ORDER BY event_date")
        if not ssh.empty:
            fig = go.Figure()
            fig.add_trace(go.Bar(x=ssh["event_date"], y=ssh["failed_ssh"],
                name="Failed SSH", marker_color="#f85149"))
            fig.add_trace(go.Bar(x=ssh["event_date"], y=ssh["successful_ssh"],
                name="Successful SSH", marker_color="#3fb950"))
            fig.add_trace(go.Scatter(x=ssh["event_date"], y=ssh["sudo_uses"],
                name="Sudo Uses", line=dict(color="#e3b341")))
            fig.update_layout(title="SSH Activity Over Time", barmode="stack",
                legend=dict(orientation="h"))
            show(fig, "ssh_activity", h=320)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: ATTACK & KILL CHAIN
# ══════════════════════════════════════════════════════════════════════════════
elif page == "⚔️ Attack & Kill Chain":
    st.title("⚔️ Attack Scenarios & MITRE ATT&CK Kill Chain")

    atk  = qdf("SELECT * FROM mart_attack_summary ORDER BY event_count DESC")
    mit  = qdf("SELECT * FROM mart_mitre_coverage ORDER BY event_count DESC")

    if not atk.empty:
        c1, c2 = st.columns(2)
        with c1:
            fig = px.bar(atk, x="attack_type", y="event_count",
                color="attack_type", title="Events by Attack Type",
                color_discrete_sequence=px.colors.qualitative.Bold)
            show(fig, "attack_events_bar", h=300)
        with c2:
            fig = px.scatter(atk, x="duration_minutes", y="hosts_affected",
                size="event_count", color="attack_type",
                title="Attack Duration vs Hosts Affected",
                color_discrete_sequence=px.colors.qualitative.Bold,
                hover_data=["attack_type","event_count"])
            show(fig, "attack_duration_scatter", h=300)

    if not mit.empty:
        phase_order = ["Initial Access","Execution","Command & Control",
                       "Lateral Movement","Credential Access","Privilege Escalation",
                       "Exfiltration","Impact","Unknown"]
        agg = mit.groupby(["kill_chain_phase","attack_type"])["event_count"].sum().reset_index()
        fig = px.density_heatmap(agg, x="attack_type", y="kill_chain_phase",
            z="event_count", title="Kill Chain Phase × Attack Type Matrix",
            color_continuous_scale="RdYlGn_r",
            category_orders={"kill_chain_phase": phase_order})
        show(fig, "kill_chain_matrix", h=400)

        fig = px.sunburst(mit, path=["kill_chain_phase","mitre_technique"],
            values="event_count",
            title="MITRE ATT&CK — Kill Chain → Technique (click to zoom)",
            color="event_count", color_continuous_scale="Reds")
        show(fig, "mitre_sunburst", h=520)

    tl = qdf("""SELECT event_time, attack_type, mitre_technique, hostname, username
        FROM fact_events WHERE attack_type IS NOT NULL AND attack_type!=''
        ORDER BY event_time LIMIT 300""")
    if not tl.empty:
        fig = px.scatter(tl, x="event_time", y="attack_type",
            color="mitre_technique", symbol="hostname",
            title="Attack Event Timeline",
            hover_data=["hostname","username","mitre_technique"])
        show(fig, "attack_timeline", h=360)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: ANOMALY DETECTION
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🔍 Anomaly Detection":
    st.title("🔍 Statistical Anomaly Detection")

    anom = qdf("SELECT * FROM mart_host_anomaly ORDER BY z_score DESC")
    if anom.empty:
        st.warning("No anomaly data found.")
        st.stop()

    c1,c2,c3,c4 = st.columns(4)
    for col, lbl in zip([c1,c2,c3,c4], ["Anomalous","Elevated","Normal","Low Activity"]):
        col.metric(lbl, anom[anom["anomaly_label"]==lbl].shape[0])

    ca, cb = st.columns(2)
    with ca:
        fig = px.histogram(anom, x="z_score", color="anomaly_label",
            title="Z-Score Distribution",
            color_discrete_map={"Anomalous":"#f85149","Elevated":"#ffa657",
                                "Normal":"#3fb950","Low Activity":"#8b949e"},
            nbins=60)
        show(fig, "anomaly_z_histogram", h=320)
    with cb:
        top = anom[anom["anomaly_label"]=="Anomalous"].nlargest(20,"z_score")
        if not top.empty:
            fig = px.bar(top, x="hostname", y="z_score", color="event_count",
                title="Top Anomalous Hosts by Z-Score",
                color_continuous_scale="Reds")
            fig.update_layout(xaxis_tickangle=-45)
            show(fig, "anomaly_top_hosts", h=320)

    fig = px.scatter(anom, x="mean", y="event_count",
        color="anomaly_label", size="z_score",
        hover_data=["hostname","hour_window"],
        title="Expected vs Actual Event Count per Host-Hour",
        color_discrete_map={"Anomalous":"#f85149","Elevated":"#ffa657",
                            "Normal":"#3fb950","Low Activity":"#8b949e"})
    show(fig, "anomaly_scatter", h=420)

    st.markdown("#### Anomalous Host-Hours")
    st.dataframe(anom[anom["anomaly_label"]=="Anomalous"].nlargest(50,"z_score"),
                 use_container_width=True, height=300)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: APPLICATION ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🌍 Application Analytics":
    st.title("🌍 Web Application Analytics")

    http = qdf(f"SELECT * FROM mart_http_status WHERE {DRANGE} ORDER BY event_date")
    err  = qdf(f"""SELECT * FROM mart_web_error_trend
        WHERE DATE_TRUNC('day', hour_window)::DATE BETWEEN '{d_start}' AND '{d_end}'
        ORDER BY hour_window""")

    if not http.empty:
        c1, c2 = st.columns(2)
        with c1:
            http["group"] = http["status_code"].astype(str).apply(
                lambda x: "2xx OK" if x.startswith("2") else
                          "3xx Redirect" if x.startswith("3") else
                          "4xx Client Error" if x.startswith("4") else
                          "5xx Server Error")
            agg = http.groupby("group")["request_count"].sum().reset_index()
            fig = px.pie(agg, values="request_count", names="group",
                title="HTTP Response Code Groups", hole=0.4,
                color="group",
                color_discrete_map={"2xx OK":"#3fb950","3xx Redirect":"#58a6ff",
                                    "4xx Client Error":"#ffa657","5xx Server Error":"#f85149"})
            show(fig, "http_status_pie", h=300)
        with c2:
            ma = http.groupby("method")["request_count"].sum().reset_index()
            fig = px.bar(ma, x="method", y="request_count", title="HTTP Methods",
                color="request_count", color_continuous_scale="Blues")
            show(fig, "http_methods_bar", h=300)

    if not err.empty:
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=err["hour_window"], y=err["total_requests"],
            name="Total Requests", fill="tozeroy", line=dict(color="#58a6ff")))
        fig.add_trace(go.Scatter(x=err["hour_window"], y=err["errors"],
            name="Errors", fill="tozeroy", line=dict(color="#f85149")))
        fig.update_layout(title="Request Volume & Error Count (Hourly)",
            legend=dict(orientation="h"))
        show(fig, "request_error_trend", h=340)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: NLP SQL EXPLORER
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🧠 NLP SQL Explorer":
    st.title("🧠 Natural Language SQL Explorer")
    st.caption("Ask cybersecurity questions in plain English — GPT-4o-mini translates to DuckDB SQL")
    render_nlp_page()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: STORY & DSS
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📖 Story & DSS":
    st.title("📖 Security Story & Decision Support")

    kpi  = qdf(f"""SELECT SUM(total_events) AS te, SUM(ids_alerts) AS ia,
        SUM(attack_events) AS ae, SUM(auth_failures) AS af,
        AVG(r.risk_score) AS rs
        FROM mart_kpi_daily k
        JOIN mart_risk_score_daily r USING(event_date)
        WHERE k.{DRANGE}""")
    atks = qdf("SELECT * FROM mart_attack_summary")
    brt  = qdf("SELECT COUNT(*) AS cnt FROM mart_brute_force WHERE severity='CRITICAL'")
    dns  = qdf("SELECT COUNT(*) AS cnt FROM mart_dns_summary WHERE possible_dns_tunnel")

    render_story_dss(kpi, atks, brt, dns, d_start, d_end)
