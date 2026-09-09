"""
Shared helper functions for the Streamlit dashboard.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import duckdb
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from config import DB_PATH, COLORS, OPENAI_API_KEY, ATTACK_COLORS


def fmt_number(val) -> str:
    """Format large numbers for KPI cards."""
    try:
        n = float(val)
        if n >= 1_000_000:
            return f"{n/1_000_000:.1f}M"
        if n >= 1_000:
            return f"{n/1_000:.1f}K"
        return f"{n:.0f}"
    except Exception:
        return str(val)


def color_risk(score: float) -> str:
    if score >= 75: return "#E74C3C"
    if score >= 50: return "#E67E22"
    if score >= 25: return "#F1C40F"
    return "#2ECC71"


def kpi_card(label: str, value: str, icon: str = "📋", delta: str = "") -> str:
    delta_html = f'<div class="kpi-delta">{delta}</div>' if delta else ""
    return f"""<div class="kpi-card">
    <div class="kpi-value">{icon} {value}</div>
    <div class="kpi-label">{label}</div>
    {delta_html}
    </div>"""


def risk_gauge(score: float) -> go.Figure:
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": "Risk Score"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar":  {"color": color_risk(score)},
            "steps": [
                {"range": [0,  25],  "color": "rgba(46,204,113,0.15)"},
                {"range": [25, 50],  "color": "rgba(241,196,15,0.15)"},
                {"range": [50, 75],  "color": "rgba(230,126,34,0.15)"},
                {"range": [75, 100], "color": "rgba(231,76,60,0.15)"},
            ],
        }
    ))
    fig.update_layout(template="plotly_dark", height=220, margin=dict(t=30,b=0))
    return fig


def threat_story(kpi_row, attacks_df, brute_cnt, dns_cnt, d_start, d_end) -> str:
    """Generate narrative from KPI data."""
    te  = fmt_number(kpi_row.get("te", 0))
    ia  = fmt_number(kpi_row.get("ia", 0))
    ae  = fmt_number(kpi_row.get("ae", 0))
    af  = fmt_number(kpi_row.get("af", 0))
    rs  = float(kpi_row.get("rs", 0) or 0)
    rsl = "CRITICAL" if rs>=75 else "HIGH" if rs>=50 else "MEDIUM" if rs>=25 else "LOW"

    attack_types = ", ".join(attacks_df["attack_type"].unique().tolist()) if not attacks_df.empty else "none detected"
    brute_c = int(brute_cnt.get("cnt", 0) or 0)
    dns_c   = int(dns_cnt.get("cnt", 0) or 0)

    return f"""
**📅 Reporting Period: {d_start} → {d_end}**

During this period, the security infrastructure processed **{te} total events** across all
data sources including network telemetry, endpoint logs, authentication systems, and
threat intelligence feeds.

**Key Findings:**

🔴 **Threat Activity** — {ae} confirmed attack events were observed spanning multiple
attack types: *{attack_types}*. The average daily risk score was **{rs:.1f}/100 ({rsl})**.

🚨 **Intrusion Detection** — {ia} IDS/Suricata alerts were raised, indicating active
adversarial probing and exploitation attempts against the network perimeter.

🔐 **Authentication** — {af} authentication failures were recorded. **{brute_c} critical-severity
brute-force campaigns** were identified targeting user accounts, suggesting credential
harvesting operations.

🌐 **DNS Anomalies** — **{dns_c} source IPs** exhibited DNS tunnelling behaviour
(high TXT query volume or NXDomain-heavy patterns), consistent with covert C2
communication or data exfiltration via DNS.

**Overall Posture:** The organisation's security posture rates as **{rsl}** for this period.
Immediate attention is required on {"credential security and lateral movement containment" if rs>=50 else "preventive hardening and monitoring expansion"}.
"""


def get_dss_recommendations(risk_score: float, brute_cnt: int,
                             dns_tunnel_cnt: int, attack_types: list) -> list:
    """Generate prioritised DSS recommendations."""
    recs = []

    if risk_score >= 75:
        recs.append({
            "priority": "🔴 CRITICAL",
            "action": "Activate Incident Response Plan",
            "detail": "Risk score exceeds critical threshold (≥75). Convene SOC war room, isolate affected segments, preserve forensic artifacts.",
            "effort": "Immediate"
        })

    if brute_cnt > 0:
        recs.append({
            "priority": "🔴 CRITICAL",
            "action": "Implement Account Lockout & MFA",
            "detail": f"{brute_cnt} critical brute-force campaigns detected. Enforce lockout after 5 failures, require MFA for all privileged accounts.",
            "effort": "< 2 hours"
        })

    if dns_tunnel_cnt > 0:
        recs.append({
            "priority": "🟠 HIGH",
            "action": "Block DNS Tunnelling C2 Channels",
            "detail": f"{dns_tunnel_cnt} IPs showing DNS tunnelling behaviour. Implement DNS sinkholes, restrict to approved resolvers, enable DNS-over-HTTPS.",
            "effort": "< 4 hours"
        })

    if "ransomware" in attack_types:
        recs.append({
            "priority": "🔴 CRITICAL",
            "action": "Verify Backup Integrity & Enable EDR",
            "detail": "Ransomware kill chain detected including shadow copy deletion. Verify offline backups are intact. Deploy EDR with behavioral blocking.",
            "effort": "< 1 hour"
        })

    if "apt" in attack_types:
        recs.append({
            "priority": "🟠 HIGH",
            "action": "Hunt for Persistent Footholds",
            "detail": "APT kill chain evidence (recon → exfil) detected. Perform threat hunt for scheduled tasks, autorun entries, and anomalous service accounts.",
            "effort": "1–3 days"
        })

    if "cred_theft" in attack_types:
        recs.append({
            "priority": "🟠 HIGH",
            "action": "Reset Privileged Credentials & Audit Kerberos",
            "detail": "Credential theft (LSASS dump + Kerberoasting) detected. Force password resets for service accounts. Audit SPN registrations.",
            "effort": "< 8 hours"
        })

    if "data_exfil" in attack_types:
        recs.append({
            "priority": "🟠 HIGH",
            "action": "Enable DLP & Inspect Encrypted Traffic",
            "detail": "Data exfiltration via DNS tunnelling detected. Enable Data Loss Prevention policies. Deploy SSL inspection at perimeter.",
            "effort": "< 12 hours"
        })

    # General recommendations
    recs += [
        {
            "priority": "🟡 MEDIUM",
            "action": "Implement Network Segmentation",
            "detail": "Reduce lateral movement blast radius by segmenting workstations, servers, and DMZ using firewall rules and VLAN policies.",
            "effort": "1–2 weeks"
        },
        {
            "priority": "🟡 MEDIUM",
            "action": "Centralise & Correlate Logs via Kafka",
            "detail": "Ensure all log sources feed into Kafka topics → Logstash → Elasticsearch for real-time correlation and alerting.",
            "effort": "1 week"
        },
        {
            "priority": "🟢 LOW",
            "action": "Tune IDS Signature Thresholds",
            "detail": "Review high-volume, low-fidelity Suricata signatures. Tune thresholds to reduce alert fatigue while maintaining detection coverage.",
            "effort": "2–3 days"
        },
    ]

    return recs


# ── NLP Page ──────────────────────────────────────────────────────────────────

def render_nlp_page():
    from nlp_sql_helper import run_query, EXAMPLE_QUERIES

    st.markdown("""
    Ask cybersecurity analytics questions in natural language.
    The system translates them to DuckDB SQL using **GPT-4o-mini** and runs them instantly.
    """)

    # Pre-built examples
    st.markdown("### 📚 Example Queries (click to run instantly)")
    examples = list(EXAMPLE_QUERIES.keys())
    selected = st.selectbox("Select a pre-built query", ["— choose —"] + examples)

    st.markdown("### ✍️ Or type your own question")
    user_q = st.text_area("Natural language question",
        placeholder="e.g. Which IPs had the most authentication failures last week?",
        height=80)

    col1, col2 = st.columns([1, 4])
    with col1:
        run_btn = st.button("🚀 Run", type="primary")
    with col2:
        show_sql = st.checkbox("Show generated SQL", value=True)

    if run_btn:
        question = user_q.strip() if user_q.strip() else (selected if selected != "— choose —" else "")
        if not question:
            st.warning("Please enter a question or select an example.")
            return

        with st.spinner("Translating to SQL and executing..."):
            from nlp_sql_helper import ask
            sql, df, err = ask(question)

        if show_sql and sql:
            st.code(sql, language="sql")

        if err:
            st.error(f"Query error: {err}")
        elif df is not None and not df.empty:
            st.success(f"✅ {len(df)} rows returned")
            st.dataframe(df, use_container_width=True, height=400)

            # Auto-visualise if numeric columns present
            num_cols = df.select_dtypes(include="number").columns.tolist()
            str_cols = df.select_dtypes(include="object").columns.tolist()
            date_cols = [c for c in df.columns if "date" in c.lower() or "time" in c.lower()]

            if num_cols and (str_cols or date_cols):
                st.markdown("#### 📊 Auto-Visualization")
                x_col = st.selectbox("X axis", date_cols + str_cols, key="nlp_x")
                y_col = st.selectbox("Y axis", num_cols, key="nlp_y")
                chart_type = st.radio("Chart type", ["Bar","Line","Scatter","Area"], horizontal=True, key="nlp_chart")

                chart_fn = {"Bar": px.bar, "Line": px.line, "Scatter": px.scatter, "Area": px.area}
                fig = chart_fn[chart_type](df, x=x_col, y=y_col, title=f"{y_col} by {x_col}")
                fig.update_layout(template="plotly_dark", height=400)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Query returned no results.")

    # SQL complexity showcase
    with st.expander("📖 SQL Complexity Examples"):
        st.markdown("""
**Basic** — Event counts by log source:
```sql
SELECT log_source, COUNT(*) AS cnt FROM fact_events GROUP BY 1 ORDER BY 2 DESC
```

**Intermediate** — 7-day rolling auth failure average:
```sql
SELECT event_date, auth_failures,
       AVG(auth_failures) OVER (ORDER BY event_date ROWS 6 PRECEDING) AS rolling_7d
FROM mart_kpi_daily ORDER BY event_date
```

**Advanced** — Rank hosts by anomaly score with percentile:
```sql
SELECT hostname, z_score, event_count,
       PERCENT_RANK() OVER (ORDER BY z_score) AS percentile,
       NTILE(4) OVER (ORDER BY z_score DESC) AS quartile
FROM mart_host_anomaly WHERE anomaly_label='Anomalous'
ORDER BY z_score DESC
```

**Complex** — Attack correlation: hosts with brute-force AND suspicious processes:
```sql
WITH bf_hosts AS (
    SELECT DISTINCT hostname FROM fact_events
    WHERE log_source='windows' AND event_action LIKE '%Failed%'
    GROUP BY hostname HAVING COUNT(*) > 20
),
sp_hosts AS (
    SELECT DISTINCT hostname FROM mart_suspicious_processes
    WHERE risk_classification='MALICIOUS'
)
SELECT f.hostname, COUNT(*) AS total_events,
       SUM(CASE WHEN log_source='attack' THEN 1 ELSE 0 END) AS attack_events
FROM fact_events f
WHERE f.hostname IN (SELECT hostname FROM bf_hosts)
  AND f.hostname IN (SELECT hostname FROM sp_hosts)
GROUP BY 1 ORDER BY 2 DESC
```

**NLP-style complex** — "Which users logged in after hours AND ran suspicious PowerShell?":
```sql
WITH ah_users AS (
    SELECT DISTINCT username FROM mart_afterhours_logins
),
ps_users AS (
    SELECT DISTINCT username FROM mart_risky_powershell WHERE risk_level IN ('CRITICAL','HIGH')
)
SELECT u.username,
       COUNT(DISTINCT a.hostname) AS hosts,
       MIN(a.event_time) AS first_activity
FROM fact_events a
JOIN ah_users u ON a.username = u.username
WHERE a.username IN (SELECT username FROM ps_users)
GROUP BY 1 ORDER BY 2 DESC
```
""")


# ── Story + DSS Page ──────────────────────────────────────────────────────────

def render_story_dss(kpi, attacks, brute, dns_tun, d_start, d_end):
    if kpi.empty or kpi.iloc[0].isnull().all():
        st.warning("Insufficient data for analysis. Ensure the pipeline ran and the date range is correct.")
        return

    row = kpi.iloc[0].to_dict()
    atk_types = attacks["attack_type"].unique().tolist() if not attacks.empty else []
    brute_c   = int(brute.iloc[0]["cnt"]) if not brute.empty else 0
    dns_c     = int(dns_tun.iloc[0]["cnt"]) if not dns_tun.empty else 0
    rs        = float(row.get("rs", 0) or 0)

    # Narrative
    st.markdown("## 📖 Security Narrative")
    story = threat_story(row, attacks, {"cnt": brute_c}, {"cnt": dns_c}, d_start, d_end)
    st.markdown(f'<div class="story-box">{story}</div>', unsafe_allow_html=True)

    # Risk Score Visual
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        st.plotly_chart(risk_gauge(rs), use_container_width=True)
    with col2:
        risk_label = "CRITICAL" if rs >= 75 else "HIGH" if rs >= 50 else "MEDIUM" if rs >= 25 else "LOW"
        color_cls = f"risk-{risk_label.lower()}"
        st.markdown(f"""
        <p style="color:#8b949e;font-size:0.85rem;margin-bottom:4px">OVERALL RISK LEVEL</p>
        <p class="{color_cls}" style="font-size:2.4rem;margin:0">{risk_label}</p>
        <p style="color:#c9d1d9;font-size:1rem;margin-top:4px">Score: <strong style="color:#58a6ff">{rs:.1f}</strong>/100</p>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("#### ⚔️ Attack Types Detected")
        if atk_types:
            for at in atk_types:
                color = ATTACK_COLORS.get(at, "#8b949e")
                st.markdown(
                    f'<span style="background:{color}22;border:1px solid {color};color:{color};'
                    f'padding:3px 10px;border-radius:12px;font-size:0.88rem;margin:2px;display:inline-block">'
                    f'⚔️ {at.replace("_"," ").title()}</span>',
                    unsafe_allow_html=True
                )
        else:
            st.info("No labeled attack events in selected range — try widening the date range.")

    # DSS Recommendations
    st.markdown("---")
    st.markdown("## 🎯 Decision Support — Prioritised Recommendations")
    recs = get_dss_recommendations(rs, brute_c, dns_c, atk_types)

    priority_colors = {
        "🔴 CRITICAL": "#ff6b6b",
        "🟠 HIGH":     "#ffa94d",
        "🟡 MEDIUM":   "#ffd43b",
        "🟢 LOW":      "#69db7c",
    }
    for rec in recs:
        border_color = priority_colors.get(rec["priority"], "#58a6ff")
        st.markdown(f"""
<div class="dss-box" style="border-left:4px solid {border_color}">
<strong>{rec['priority']} — {rec['action']}</strong><br>
<span style="color:#c9d1d9">{rec['detail']}</span><br>
<small>⏱ Estimated effort: <em style="color:#8b949e">{rec['effort']}</em></small>
</div>""", unsafe_allow_html=True)

    # OpenAI-powered insight
    st.markdown("---")
    st.markdown("## 🤖 AI-Powered Insight (GPT-4o-mini)")
    if st.button("✨ Generate AI Security Summary", type="primary"):
        with st.spinner("Querying OpenAI GPT-4o-mini..."):
            summary = _get_ai_summary(row, atk_types, brute_c, dns_c, rs)
        st.markdown(f'<div class="story-box">{summary}</div>', unsafe_allow_html=True)


def _get_ai_summary(row, attack_types, brute_cnt, dns_cnt, risk_score):
    try:
        import openai
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        prompt = f"""You are a cybersecurity analyst. Summarise this security report in 4 concise paragraphs covering:
1. Overall risk posture
2. Most critical threats observed
3. Key attack patterns and techniques (MITRE ATT&CK)
4. Top 3 recommended immediate actions

Data:
- Period events: {fmt_number(row.get('te',0))}
- IDS alerts: {fmt_number(row.get('ia',0))}
- Auth failures: {fmt_number(row.get('af',0))}
- Attack events: {fmt_number(row.get('ae',0))}
- Risk score: {risk_score:.1f}/100
- Attack types: {', '.join(attack_types) if attack_types else 'none'}
- Critical brute-force campaigns: {brute_cnt}
- DNS tunnelling suspects: {dns_cnt}

Be direct, specific and actionable. Write as if briefing a CISO."""

        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600, temperature=0.3
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"_AI summary unavailable: {e}_"
