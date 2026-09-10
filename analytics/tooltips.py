"""
Contextual tooltip system for the CyberData Analytics dashboard.

Two mechanisms:
1. help_tip(text)  — renders an ℹ️ icon next to any label; hover shows explanation
2. chart_explain() — returns a Plotly annotation dict to embed into figures
3. CHART_CONTEXT   — dict of all chart explanations keyed by chart id
"""

import streamlit as st

# ── CSS injected once ─────────────────────────────────────────────────────────
TOOLTIP_CSS = """
<style>
.tip-wrap {
    display: inline-flex; align-items: center; gap: 5px;
    position: relative; cursor: default;
}
.tip-icon {
    display: inline-block;
    width: 16px; height: 16px; line-height: 16px;
    font-size: 11px; text-align: center;
    background: #21262d; color: #58a6ff;
    border: 1px solid #30363d; border-radius: 50%;
    cursor: help; font-style: normal; font-weight: 700;
    flex-shrink: 0;
}
.tip-box {
    visibility: hidden; opacity: 0;
    position: absolute; left: 22px; top: -4px; z-index: 9999;
    width: 280px; padding: 10px 14px;
    background: #1c2128; border: 1px solid #388bfd;
    border-radius: 8px; border-left: 3px solid #388bfd;
    font-size: 12.5px; line-height: 1.55; color: #c9d1d9;
    box-shadow: 0 8px 24px rgba(0,0,0,.5);
    transition: opacity .18s ease, visibility .18s ease;
    pointer-events: none; white-space: normal;
}
.tip-wrap:hover .tip-box,
.tip-wrap:focus-within .tip-box {
    visibility: visible; opacity: 1;
}
/* keep box on-screen on right edge */
.tip-right .tip-box { left: auto; right: 22px; }
</style>
"""

_css_injected = False

def inject_css():
    global _css_injected
    if not _css_injected:
        st.markdown(TOOLTIP_CSS, unsafe_allow_html=True)
        _css_injected = True


def help_tip(label: str, tip: str, right: bool = False) -> str:
    """
    Return HTML: label text + hoverable ℹ️ icon.
    Usage:  st.markdown(help_tip("IDS Alerts", "Suricata..."), unsafe_allow_html=True)
    """
    side = " tip-right" if right else ""
    # Escape quotes in tip
    tip_safe = tip.replace('"', "&quot;").replace("'", "&#39;")
    return (
        f'<span class="tip-wrap{side}">'
        f'<span>{label}</span>'
        f'<span class="tip-icon" tabindex="0">i</span>'
        f'<span class="tip-box">{tip_safe}</span>'
        f'</span>'
    )


def section_header(title: str, tip: str) -> None:
    """Render a section header with tooltip."""
    inject_css()
    st.markdown(
        f'<div class="section-header">{help_tip(title, tip)}</div>',
        unsafe_allow_html=True
    )


# ── Per-chart explanations ────────────────────────────────────────────────────

CHART_CONTEXT = {

    # ── Executive Summary ─────────────────────────────────────────────────────
    "kpi_total_events":
        "Total log events ingested across all data sources (network, endpoint, "
        "authentication, threat intel) in the selected period. A sudden spike "
        "may indicate a scan, attack, or log misconfiguration.",

    "kpi_ids_alerts":
        "Suricata IDS/IPS rule matches. Each alert means a network packet matched "
        "a known malicious signature. High counts warrant investigation of the "
        "top triggering signatures.",

    "kpi_attack_events":
        "Events explicitly labeled as part of a simulated or detected attack "
        "scenario (APT, ransomware, credential theft, data exfiltration). "
        "Each event maps to a MITRE ATT&CK technique.",

    "kpi_auth_failures":
        "Failed login attempts across Windows (Event ID 4625) and SSH. "
        "Clusters of failures from a single IP/user are a brute-force indicator.",

    "kpi_fw_drops":
        "Packets blocked by the firewall (iptables DROP/REJECT actions). "
        "High counts from a single source IP suggest active scanning or DoS.",

    "daily_event_volume":
        "Shows the daily rhythm of the environment. Blue fill = total events; "
        "red line = IDS alerts; purple dashed = confirmed attack events. "
        "Look for spikes above the rolling baseline — these warrant investigation.",

    "risk_gauge":
        "Composite risk score (0–100) calculated from weighted daily totals: "
        "IDS alerts (30%), attack events (25%), auth failures (15%), "
        "firewall blocks (10%), PowerShell executions (10%), threat intel (10%). "
        "≥75 = Critical, ≥50 = High, ≥25 = Medium, <25 = Low.",

    "attack_type_pie":
        "Distribution of labeled attack scenarios by event count. "
        "APT = Advanced Persistent Threat multi-stage kill chain; "
        "Ransomware = encryption + shadow-copy deletion chain; "
        "Data Exfil = DNS tunnelling; Cred Theft = LSASS dump + Kerberoasting.",

    "kill_chain_bar":
        "MITRE ATT&CK kill chain phases observed. Longer bars indicate more "
        "activity in that phase. 'Initial Access' + 'Exfiltration' both active "
        "simultaneously signals a mature, ongoing breach.",

    # ── KPI Dashboard ─────────────────────────────────────────────────────────
    "activity_heatmap":
        "Event volume by ISO week number (X) and day of week (Y). "
        "Darker cells = more events. Weekend spikes are unusual and may indicate "
        "after-hours attacker activity. Weekday patterns show business hours.",

    "security_trends":
        "Multi-line trend of 4 key security signals over time. "
        "Correlated spikes (e.g., IDS alerts + auth failures on the same day) "
        "suggest a coordinated attack rather than noise.",

    "login_stacked":
        "Daily successful vs failed logins. A growing failure bar relative to "
        "successes indicates credential stuffing or brute-force campaigns. "
        "The ratio matters more than absolute numbers.",

    "risk_scatter":
        "Each dot = one day, coloured by risk level. Dots cluster into risk bands. "
        "An upward trend over time means the environment is degrading. "
        "Isolated red dots = incident days.",

    # ── Network & Firewall ────────────────────────────────────────────────────
    "external_traffic":
        "Inbound (red) vs outbound (blue) external connections per day. "
        "Normal environments have more outbound than inbound. "
        "A sharp inbound spike may be a scan or DDoS. "
        "Unusual outbound growth can indicate data exfiltration.",

    "protocol_pie":
        "Share of each network protocol. TCP/UDP dominate normal traffic. "
        "Unexpected ICMP spikes can indicate tunnel or ping-sweep activity. "
        "An unusual protocol appearing suddenly warrants investigation.",

    "protocol_bar":
        "Absolute event count by protocol. Compare against baseline — "
        "DNS spikes often precede exfiltration; SMB spikes suggest lateral movement.",

    "top_talkers_bubble":
        "Each bubble = one source IP. X = total connections, Y = unique destinations, "
        "bubble size = bytes transferred, colour = unique ports used. "
        "IPs in the top-right corner with large bubbles are high-risk talkers.",

    "port_scan_bar":
        "IPs that probed more than 5 unique destination ports in an hour window. "
        "High = >20 ports (likely automated scanner), Medium = 10–20. "
        "Cross-reference with IDS alerts for confirmation.",

    "fw_action_area":
        "Stacked area of firewall decisions over time. "
        "A growing DROP area relative to ACCEPT means more threats are being blocked — "
        "but also check if legitimate traffic is being caught.",

    "fw_blocked_treemap":
        "Treemap of top blocked source IPs. Tile size = block count; "
        "colour = number of unique ports targeted. "
        "Persistent large tiles indicate repeat offenders worth IP-blocking at perimeter.",

    # ── Threat Intelligence ───────────────────────────────────────────────────
    "ids_dual_axis":
        "Bar = IDS alert count (left axis). Line = unique attacker IPs (right axis). "
        "High alerts from few IPs = targeted attack. "
        "High alerts from many IPs = distributed scan or botnet activity.",

    "ti_indicator_area":
        "Volume of threat intelligence indicators ingested over time "
        "(from feeds like MISP, AlienVault, OpenCTI). "
        "A drop to zero means the feed pipeline may be broken.",

    "ids_signatures_bar":
        "Top Suricata rule names by total alert count. "
        "Recurring high-volume signatures should be tuned or escalated. "
        "ET (Emerging Threats) prefixed rules are community-sourced threat intel.",

    "dns_tunnel_table":
        "IPs exhibiting DNS tunnelling behaviour: high TXT query volume "
        "(data encoded in DNS requests) or many NXDOMAIN responses (DGA activity). "
        "These are strong indicators of C2 communication or covert data exfiltration.",

    # ── Authentication & Identity ─────────────────────────────────────────────
    "auth_dual_axis":
        "Bars = daily login volumes (green=success, red=failure). "
        "Yellow line = failure rate %. A failure rate >20% on a single host "
        "is a brute-force indicator. Spikes without corresponding successes "
        "suggest locked-out accounts.",

    "auth_host_bar":
        "Authentication breakdown by host. Hosts with disproportionate failures "
        "relative to successes should be investigated for credential attacks. "
        "Admin/domain controllers at top of the list are highest risk.",

    "brute_force_scatter":
        "Each dot = one (source IP, username) pair. Size = failure count; "
        "colour = severity. CRITICAL (>50 failures/hour) from a single IP "
        "is almost certainly automated credential stuffing.",

    "brute_force_severity_pie":
        "Distribution of brute-force campaigns by severity. "
        "Even a small number of CRITICAL campaigns demands immediate "
        "account lockout policy enforcement and IP blocking.",

    "afterhours_heatmap":
        "Login activity by hour (X) and username (Y) outside business hours (7PM–7AM). "
        "Bright cells at 2–4AM for privileged accounts are strong insider threat "
        "or compromised credential indicators.",

    # ── Endpoint & Process ────────────────────────────────────────────────────
    "process_risk_pie":
        "Process executions classified by risk: MALICIOUS (known attack tools like "
        "mimikatz, PsExec), SUSPICIOUS (PowerShell, cmd with encoded args), NORMAL. "
        "Even one MALICIOUS execution on a production host is a critical incident.",

    "top_risky_processes_bar":
        "Most frequently executed risky processes. Encoded PowerShell (-enc flag), "
        "wscript, and mshta are commonly used in living-off-the-land attacks. "
        "Frequency matters — rare but repeated = persistence mechanism.",

    "ps_risk_funnel":
        "PowerShell script blocks categorised by risk. CRITICAL = download-and-execute "
        "(IEX + DownloadString), HIGH = base64 encoded commands or backdoor creation. "
        "Funnel shape shows most PS is informational with a dangerous tail.",

    "syslog_severity_bar":
        "Linux syslog events by process and severity level. "
        "ERR and CRIT level events from authentication daemons (sshd, sudo) "
        "deserve immediate attention. High cron + daemon errors can indicate "
        "persistence mechanisms or service disruption.",

    "ssh_activity":
        "Daily SSH login attempts: failed (red), successful (green), sudo uses (yellow). "
        "Stacked bars show absolute volume. A high failed:success ratio on a server "
        "with no corresponding legitimate access window = brute-force attack.",

    # ── Attack Scenarios & Kill Chain ─────────────────────────────────────────
    "attack_events_bar":
        "Total labeled attack events by attack type over the entire dataset. "
        "Each event is a concrete log record (process creation, network connection, "
        "Windows event) that was part of a simulated kill chain.",

    "attack_duration_scatter":
        "Scatter of attack scenarios by duration (X) vs hosts affected (Y). "
        "Bubble size = event count. Long-duration + many hosts = APT-style campaign. "
        "Short + targeted = ransomware or credential theft.",

    "kill_chain_matrix":
        "Heatmap of MITRE ATT&CK kill chain phases (rows) × attack types (columns). "
        "Darker = more events in that phase for that attack type. "
        "All phases active for one attack type = complete kill chain execution.",

    "mitre_sunburst":
        "Hierarchical view: outer ring = MITRE techniques (T-numbers), "
        "inner ring = kill chain phase. Click segments to zoom. "
        "Larger sectors = more events. Used to prioritise detection rule coverage.",

    "attack_timeline":
        "Chronological scatter of attack events. Y = attack type, X = time, "
        "colour = MITRE technique, shape = hostname. "
        "Diagonal lines across multiple hosts = lateral movement in progress.",

    # ── Anomaly Detection ─────────────────────────────────────────────────────
    "anomaly_z_histogram":
        "Distribution of hourly Z-scores across all hosts. Z-score measures how many "
        "standard deviations a host's event count is from its own mean. "
        "Z > 3 = Anomalous (far-right tail). Most hosts should cluster near 0.",

    "anomaly_top_hosts":
        "Hosts with the highest Z-scores in the Anomalous category. "
        "Bar height = Z-score magnitude; colour = raw event count. "
        "High Z + high count = genuine spike. High Z + low count = unusually quiet host.",

    "anomaly_scatter":
        "Each point = one host-hour. X = expected (mean) events, Y = actual. "
        "Points above the diagonal = more than expected (elevated/anomalous). "
        "Points below = less than expected (could indicate service outage or log gap).",

    # ── Application Analytics ─────────────────────────────────────────────────
    "http_status_pie":
        "HTTP response code groups. 2xx = successful requests (good). "
        "4xx = client errors (could indicate scanning/fuzzing if volume is high). "
        "5xx = server errors (indicate backend issues or DoS impact). "
        "3xx = redirects (high volume could mean misconfiguration).",

    "http_methods_bar":
        "Request count by HTTP method. POST/PUT/DELETE spikes without corresponding "
        "GET traffic can indicate API abuse or injection attempts. "
        "Unusual methods like TRACE or OPTIONS may indicate reconnaissance.",

    "request_error_trend":
        "Hourly request volume (blue fill) vs errors (red fill) with error rate % "
        "(yellow dashed, right axis). Error rate >5% sustained = application issue. "
        "Sudden error spike with unchanged request volume = attack or config change.",
}


def get_tip(key: str) -> str:
    """Return tooltip text for a chart key, or a generic fallback."""
    return CHART_CONTEXT.get(key, "Click or hover chart elements for detailed data.")


def annotated_title(title: str, key: str) -> str:
    """
    Return a chart title string that includes a ℹ note embedded in the
    figure title — used via fig.update_layout(title=...).
    Keeps Plotly's native title clean; tooltip goes in the subtitle area.
    """
    tip = get_tip(key)
    # Truncate for figure title subtitle (Plotly subtitle is plain text)
    short = tip[:110] + "…" if len(tip) > 110 else tip
    return title


def add_chart_tooltip(fig, key: str, font_size: int = 11):
    """
    Add a subtitle annotation to a Plotly figure with the contextual explanation.
    Appears just below the chart title in small muted text.
    """
    tip = get_tip(key)
    short = (tip[:130] + "…") if len(tip) > 130 else tip
    fig.add_annotation(
        text=f"<i style='color:#8b949e'>ℹ {short}</i>",
        xref="paper", yref="paper",
        x=0, y=1.0,
        xanchor="left", yanchor="bottom",
        showarrow=False,
        font=dict(size=font_size, color="#8b949e"),
        align="left"
    )
    # Push title up so annotation doesn't overlap
    fig.update_layout(margin=dict(t=70))
    return fig
