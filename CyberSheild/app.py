import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from analyzer import (
    analyze_logs, attack_severity, get_ip_location,
    detect_high_requests, send_alert_email,
    get_ip_details, generate_report_data,
    CRITICAL_SUSPICIOUS_THRESHOLD,
)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecureShield · Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# ── Session state ─────────────────────────────────────────────────────────────
if "logged_in"    not in st.session_state: st.session_state.logged_in    = False
if "owner_email"  not in st.session_state: st.session_state.owner_email  = ""
if "active_tab"   not in st.session_state: st.session_state.active_tab   = "Dashboard"

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap');

*, *::before, *::after { box-sizing: border-box; }

html, body, [data-testid="stAppViewContainer"] {
    background: #020608 !important;
    color: #d0e4d8 !important;
    font-family: 'Rajdhani', sans-serif;
    font-size: 16px;
}
[data-testid="stHeader"]  { display: none !important; }
[data-testid="stToolbar"] { display: none !important; }
footer { display: none !important; }

/* animated grid */
[data-testid="stAppViewContainer"]::before {
    content: ''; position: fixed; inset: 0;
    background-image:
        linear-gradient(rgba(0,255,170,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,170,.03) 1px, transparent 1px);
    background-size: 48px 48px;
    animation: gridPan 25s linear infinite;
    pointer-events: none; z-index: 0;
}
@keyframes gridPan { 0%{background-position:0 0} 100%{background-position:48px 48px} }

[data-testid="stAppViewContainer"]::after {
    content: ''; position: fixed; inset: 0;
    background: repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.1) 2px,rgba(0,0,0,.1) 4px);
    pointer-events: none; z-index: 0;
}
[data-testid="stMainBlockContainer"] { position: relative; z-index: 1; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: rgba(2,12,18,.97) !important;
    border-right: 1px solid rgba(0,255,170,.14) !important;
}
[data-testid="stSidebar"] * { color: #a8c8b8 !important; }
[data-testid="stSidebar"] [data-testid="stButton"] > button {
    background: transparent !important;
    border: 1px solid rgba(255,60,100,.35) !important;
    color: #ff6688 !important; width: 100% !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: .82rem !important; letter-spacing: .14em !important;
}
[data-testid="stSidebar"] [data-testid="stButton"] > button:hover {
    border-color: #ff3355 !important; color: #ff3355 !important;
    box-shadow: 0 0 12px rgba(255,51,85,.2) !important;
}

/* ── Inputs ── */
[data-testid="stTextInput"] label {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: .82rem !important; color: #00b4ff !important;
    letter-spacing: .15em !important; text-transform: uppercase !important;
}
[data-testid="stTextInput"] input {
    background: rgba(0,20,30,.8) !important;
    border: 1px solid rgba(0,255,170,.3) !important; border-radius: 3px !important;
    color: #00ffaa !important; font-family: 'Share Tech Mono', monospace !important;
    font-size: 1rem !important; caret-color: #00ffaa;
    transition: border-color .2s, box-shadow .2s;
}
[data-testid="stTextInput"] input:focus {
    border-color: #00ffaa !important;
    box-shadow: 0 0 0 2px rgba(0,255,170,.15) !important; outline: none !important;
}
[data-testid="stTextInput"] input::placeholder { color: rgba(0,255,170,.3) !important; }

/* ── Buttons ── */
[data-testid="stButton"] > button {
    background: linear-gradient(135deg,rgba(0,255,170,.1),rgba(0,180,255,.07)) !important;
    border: 1px solid rgba(0,255,170,.45) !important; border-radius: 3px !important;
    color: #00ffaa !important; font-family: 'Share Tech Mono', monospace !important;
    font-size: .85rem !important; letter-spacing: .18em !important;
    text-transform: uppercase !important; transition: all .2s !important;
}
[data-testid="stButton"] > button:hover {
    background: linear-gradient(135deg,rgba(0,255,170,.2),rgba(0,180,255,.14)) !important;
    border-color: #00ffaa !important; box-shadow: 0 0 18px rgba(0,255,170,.22) !important;
    transform: translateY(-1px) !important;
}

/* ── File uploader ── */
[data-testid="stFileUploader"] {
    background: rgba(2,15,22,.7) !important;
    border: 1px dashed rgba(0,255,170,.22) !important; border-radius: 4px !important;
}
[data-testid="stFileUploader"] label {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: .82rem !important; color: #00b4ff !important;
    letter-spacing: .12em !important; text-transform: uppercase !important;
}

/* ── Dataframe ── */
[data-testid="stDataFrame"] { border: 1px solid rgba(0,255,170,.12) !important; border-radius: 4px !important; }

/* ── Select box ── */
[data-testid="stSelectbox"] label {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: .82rem !important; color: #00b4ff !important;
    letter-spacing: .12em !important; text-transform: uppercase !important;
}

/* ── Alerts ── */
[data-testid="stAlert"] {
    border-radius: 3px !important;
    font-family: 'Share Tech Mono', monospace !important; font-size: .82rem !important;
}

hr { border-color: rgba(0,255,170,.1) !important; }

/* ── Custom components ── */
.metric-card {
    background: rgba(2,15,22,.9); border: 1px solid rgba(0,255,170,.18);
    border-radius: 4px; padding: 1.5rem 1.7rem;
    position: relative; overflow: hidden;
    transition: border-color .2s, box-shadow .2s;
}
.metric-card:hover { border-color: rgba(0,255,170,.4); box-shadow: 0 0 22px rgba(0,255,170,.07); }
.metric-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, #00ffaa, #00b4ff); opacity: .7;
}
.metric-card.amber::before { background: linear-gradient(90deg,#ffaa00,#ffdd44); }
.metric-card.red::before   { background: linear-gradient(90deg,#ff3355,#ff8844); }
.metric-card.blue::before  { background: linear-gradient(90deg,#00b4ff,#44aaff); }
.metric-label {
    font-family: 'Share Tech Mono', monospace; font-size: .75rem;
    color: rgba(0,180,255,.75); letter-spacing: .2em; text-transform: uppercase; margin-bottom: .45rem;
}
.metric-value { font-size: 2.8rem; font-weight: 700; line-height: 1; color: #e8f4f0; }
.metric-value.amber { color: #ffcc44; }
.metric-value.red   { color: #ff6688; }
.metric-value.blue  { color: #44ccff; }
.metric-icon { position: absolute; right: 1.2rem; top: 50%; transform: translateY(-50%); font-size: 2.2rem; opacity: .13; }

.section-header {
    font-family: 'Share Tech Mono', monospace; font-size: .8rem; color: #00b4ff;
    letter-spacing: .25em; text-transform: uppercase;
    margin: 2rem 0 1rem; display: flex; align-items: center; gap: .6rem;
}
.section-header::after {
    content: ''; flex: 1; height: 1px;
    background: linear-gradient(90deg,rgba(0,180,255,.3),transparent);
}

.alert-row {
    display: flex; align-items: center; gap: 1rem;
    background: rgba(2,15,22,.7); border: 1px solid rgba(255,255,255,.07);
    border-left-width: 3px; border-radius: 3px;
    padding: .8rem 1.1rem; margin-bottom: .45rem;
    font-family: 'Share Tech Mono', monospace; font-size: .85rem;
    transition: background .15s;
}
.alert-row:hover { background: rgba(2,25,36,.85); }
.alert-row.low      { border-left-color: #00b4ff; color: #80ccee; }
.alert-row.medium   { border-left-color: #ffcc00; color: #ffdd77; }
.alert-row.high     { border-left-color: #ff8844; color: #ffaa66; }
.alert-row.critical {
    border-left-color: #ff3355; color: #ff8899;
    background: rgba(40,5,12,.7);
    animation: critPulse 1.6s ease-in-out infinite;
}
.alert-row.critical_suspicious {
    border-left-color: #ff0033; color: #ffcccc;
    background: rgba(60,0,10,.85);
    border-top: 1px solid rgba(255,0,51,.35);
    border-right: 1px solid rgba(255,0,51,.35);
    border-bottom: 1px solid rgba(255,0,51,.35);
    animation: csPulse 1s ease-in-out infinite;
}
@keyframes csPulse { 0%,100%{box-shadow:0 0 0 rgba(255,0,51,0)} 50%{box-shadow:0 0 22px rgba(255,0,51,.35)} }
@keyframes critPulse { 0%,100%{box-shadow:none} 50%{box-shadow:0 0 14px rgba(255,51,85,.18)} }
.alert-ip    { font-weight: 700; min-width: 140px; font-size: .9rem; }
.alert-badge {
    margin-left: auto; border-radius: 2px; padding: .12rem .5rem;
    font-size: .7rem; letter-spacing: .1em; border: 1px solid currentColor; opacity: .85;
}

/* ── IP detail card ── */
.ip-detail-card {
    background: rgba(2,15,22,.88); border: 1px solid rgba(0,255,170,.2);
    border-radius: 4px; padding: 1.2rem 1.5rem; margin-bottom: .6rem;
}
.ip-detail-row {
    display: flex; justify-content: space-between;
    font-family: 'Share Tech Mono', monospace; font-size: .82rem;
    padding: .3rem 0; border-bottom: 1px solid rgba(0,255,170,.06);
    color: #a0c8b0;
}
.ip-detail-row:last-child { border-bottom: none; }
.ip-detail-key   { color: rgba(0,180,255,.7); letter-spacing: .1em; text-transform: uppercase; }
.ip-detail-value { color: #d0e8d8; font-weight: 600; }

/* ── Report table ── */
.report-table {
    width: 100%; border-collapse: collapse;
    font-family: 'Share Tech Mono', monospace; font-size: .82rem;
}
.report-table th {
    background: rgba(0,180,255,.1); color: #00b4ff;
    padding: .6rem .9rem; text-align: left; letter-spacing: .12em;
    text-transform: uppercase; border-bottom: 1px solid rgba(0,180,255,.2);
}
.report-table td {
    padding: .55rem .9rem; color: #b0d0c0;
    border-bottom: 1px solid rgba(0,255,170,.06);
}
.report-table tr:hover td { background: rgba(0,255,170,.04); }

/* ── Login card ── */
.login-card {
    background: rgba(2,15,22,.92); border: 1px solid rgba(0,255,170,.22);
    border-radius: 4px; padding: 2.8rem 2.5rem; max-width: 460px; margin: 0 auto;
    box-shadow: 0 0 40px rgba(0,255,170,.06), inset 0 1px 0 rgba(0,255,170,.1);
    position: relative; overflow: hidden;
}
.login-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg,transparent,#00ffaa,#00b4ff,transparent);
    animation: scanBar 3s ease-in-out infinite;
}
@keyframes scanBar { 0%,100%{opacity:0;transform:translateX(-100%)} 50%{opacity:1;transform:translateX(0)} }
.shield-icon {
    font-size: 3.2rem; display: block; text-align: center;
    filter: drop-shadow(0 0 14px rgba(0,255,170,.55));
    animation: iconPulse 3s ease-in-out infinite;
}
@keyframes iconPulse {
    0%,100%{filter:drop-shadow(0 0 10px rgba(0,255,170,.45))}
    50%{filter:drop-shadow(0 0 24px rgba(0,255,170,.85))}
}
.brand-name {
    font-family: 'Rajdhani', sans-serif; font-size: 1.9rem; font-weight: 700;
    letter-spacing: .25em; color: #e8f4f0; text-transform: uppercase; text-align: center;
}
.brand-sub {
    font-family: 'Share Tech Mono', monospace; font-size: .75rem; color: #00ffaa;
    letter-spacing: .3em; text-transform: uppercase; text-align: center; margin-top: .15rem;
}
.status-strip {
    display: flex; justify-content: space-between; align-items: center;
    margin-top: 1.8rem; padding-top: 1rem; border-top: 1px solid rgba(0,255,170,.1);
}
.status-dot {
    width: 8px; height: 8px; border-radius: 50%; background: #00ffaa;
    display: inline-block; margin-right: .4rem; box-shadow: 0 0 6px #00ffaa;
    animation: blink 1.4s step-end infinite;
}
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.15} }
.status-text  { font-family:'Share Tech Mono',monospace; font-size:.72rem; color:rgba(0,255,170,.55); letter-spacing:.1em; }
.version-text { font-family:'Share Tech Mono',monospace; font-size:.68rem; color:rgba(0,180,255,.38); letter-spacing:.08em; }

@keyframes badgePulse {
    0%,100%{box-shadow:0 0 4px rgba(0,255,170,.25)}
    50%{box-shadow:0 0 12px rgba(0,255,170,.65)}
}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# LOGIN
# ══════════════════════════════════════════════════════════════════════════════
if not st.session_state.logged_in:
    st.markdown("<div style='padding-top:5rem;'>", unsafe_allow_html=True)
    st.markdown("""
    <div class="login-card">
        <span class="shield-icon">🛡️</span>
        <div style="margin-top:.8rem;">
            <div class="brand-name">SecureShield</div>
            <div class="brand-sub">Threat Intelligence Platform</div>
        </div>
        <div style="margin-top:1.8rem;font-family:'Share Tech Mono',monospace;
                    font-size:.75rem;color:#00b4ff;letter-spacing:.2em;
                    text-transform:uppercase;margin-bottom:.4rem;">
            [ Operator Authentication ]
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_l, col_c, col_r = st.columns([1, 2, 1])
    with col_c:
        st.markdown("<div style='height:.5rem;'></div>", unsafe_allow_html=True)
        email = st.text_input("Owner Email ID", placeholder="operator@domain.com")
        if st.button("⟶  AUTHENTICATE", use_container_width=True):
            if email.strip():
                st.session_state.logged_in   = True
                st.session_state.owner_email = email.strip()
                st.success("✓  Identity verified — loading dashboard…")
                st.rerun()
            else:
                st.error("✗  No credentials supplied. Access denied.")

    st.markdown("""
    <div style="max-width:460px;margin:0 auto;">
        <div class="status-strip">
            <span class="status-text"><span class="status-dot"></span>SYSTEM ONLINE</span>
            <span class="version-text">v2.4.1 · SECURE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:1.4rem 0 .8rem;">
        <div style="font-size:2.4rem;filter:drop-shadow(0 0 12px rgba(0,255,170,.55));">🛡️</div>
        <div style="font-family:'Rajdhani',sans-serif;font-size:1.2rem;font-weight:700;
                    letter-spacing:.2em;color:#e0f0e8;text-transform:uppercase;margin-top:.35rem;">
            SecureShield
        </div>
        <div style="font-family:'Share Tech Mono',monospace;font-size:.68rem;
                    color:rgba(0,255,170,.45);letter-spacing:.15em;text-transform:uppercase;">
            Threat Intel Platform
        </div>
    </div>
    <hr style="border-color:rgba(0,255,170,.13);margin:.4rem 0 1rem;">
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div style="font-family:'Share Tech Mono',monospace;font-size:.68rem;
                color:rgba(0,180,255,.55);letter-spacing:.15em;text-transform:uppercase;
                margin-bottom:.25rem;">Operator</div>
    <div style="font-family:'Rajdhani',sans-serif;font-size:1rem;font-weight:600;
                color:#90d0b0;word-break:break-all;">
        {st.session_state.owner_email}
    </div>
    <hr style="border-color:rgba(0,255,170,.1);margin:.9rem 0 1rem;">
    """, unsafe_allow_html=True)

    tabs_config = [
        ("Dashboard",    "◈"),
        ("Log Analysis", "◉"),
        ("Reports",      "◇"),
    ]
    for label, icon in tabs_config:
        active = st.session_state.active_tab == label
        style = "background:rgba(0,255,170,.08);border-color:rgba(0,255,170,.3);color:#00ffaa !important;" if active else ""
        st.markdown(f"""
        <div onclick="" style="font-family:'Share Tech Mono',monospace;font-size:.8rem;
                    color:#78b898;letter-spacing:.1em;padding:.55rem .8rem;
                    border:1px solid rgba(0,255,170,.1);border-radius:3px;
                    margin-bottom:.3rem;{style}">
            {icon} &nbsp; {label.upper()}
        </div>
        """, unsafe_allow_html=True)
        if st.button(label, key=f"nav_{label}", use_container_width=True):
            st.session_state.active_tab = label
            st.rerun()

    st.markdown("<hr style='border-color:rgba(0,255,170,.1);margin:1rem 0;'>", unsafe_allow_html=True)
    if st.button("⏻  LOGOUT"):
        st.session_state.logged_in   = False
        st.session_state.owner_email = ""
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# DATA LOADING (shared across all tabs)
# ══════════════════════════════════════════════════════════════════════════════

# ── Page header ───────────────────────────────────────────────────────────────
tab_icons = {"Dashboard": "🛡️", "Log Analysis": "🔍", "Reports": "📊"}
st.markdown(f"""
<div style="display:flex;align-items:center;gap:1rem;
            border-bottom:1px solid rgba(0,255,170,.13);
            padding-bottom:1.1rem;margin-bottom:1.5rem;">
    <div>
        <div style="font-family:'Rajdhani',sans-serif;font-size:1.9rem;font-weight:700;
                    letter-spacing:.15em;text-transform:uppercase;color:#e0f0e8;">
            {tab_icons.get(st.session_state.active_tab,'🛡️')} {st.session_state.active_tab.upper()}
        </div>
        <div style="font-family:'Share Tech Mono',monospace;font-size:.75rem;
                    color:#00b4ff;letter-spacing:.2em;text-transform:uppercase;margin-top:.12rem;">
            Real-time Log Monitoring &amp; Threat Detection
        </div>
    </div>
    <div style="margin-left:auto;font-family:'Share Tech Mono',monospace;font-size:.7rem;
                color:#00ffaa;border:1px solid rgba(0,255,170,.38);border-radius:2px;
                padding:.15rem .55rem;letter-spacing:.12em;
                animation:badgePulse 2s ease-in-out infinite;">
        ● LIVE
    </div>
</div>
""", unsafe_allow_html=True)

# ── File upload (shown on all tabs) ──────────────────────────────────────────
st.markdown('<div class="section-header">◈ Log Source</div>', unsafe_allow_html=True)
uploaded_file = st.file_uploader("Upload Log File (.log)", type=["log"])

if uploaded_file is not None:
    with open("uploaded.log", "wb") as f:
        f.write(uploaded_file.getbuffer())
    df, failed, suspicious = analyze_logs("uploaded.log")
else:
    df, failed, suspicious = analyze_logs("sample.log")

# High-request alerts
high_requests = detect_high_requests(df)
if len(high_requests) > 0:
    for ip, count in high_requests.items():
        try:
            send_alert_email(st.session_state.owner_email, ip, count)
            email_status = "Email sent to admin."
        except Exception:
            email_status = "Email delivery failed."
        st.markdown(f"""
        <div class="alert-row critical">
            <span>🚨</span>
            <span class="alert-ip">{ip}</span>
            <span>{count} requests detected — {email_status}</span>
            <span class="alert-badge">AUTO-ALERT</span>
        </div>
        """, unsafe_allow_html=True)

DARK_BG    = "rgba(2,15,22,0)"
GRID_COLOR = "rgba(0,255,170,0.06)"
FONT_MONO  = "Share Tech Mono"
FONT_COLOR = "#6a9080"


# ══════════════════════════════════════════════════════════════════════════════
# TAB: DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
if st.session_state.active_tab == "Dashboard":

    # Metrics
    st.markdown('<div class="section-header">◈ System Overview</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Log Entries</div>
            <div class="metric-value">{len(df):,}</div>
            <div class="metric-icon">📋</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="metric-card amber">
            <div class="metric-label">Failed Logins</div>
            <div class="metric-value amber">{len(failed):,}</div>
            <div class="metric-icon">⚠️</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="metric-card red">
            <div class="metric-label">Suspicious IPs</div>
            <div class="metric-value red">{len(suspicious):,}</div>
            <div class="metric-icon">🎯</div>
        </div>""", unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
        <div class="metric-card blue">
            <div class="metric-label">Unique IPs</div>
            <div class="metric-value blue">{df['IP'].nunique() if not df.empty else 0}</div>
            <div class="metric-icon">🌐</div>
        </div>""", unsafe_allow_html=True)

    # Security alerts
    st.markdown('<div class="section-header">◈ Security Alerts</div>', unsafe_allow_html=True)
    if len(suspicious) == 0:
        st.markdown("""
        <div style="font-family:'Share Tech Mono',monospace;font-size:.85rem;
                    color:rgba(0,255,170,.45);padding:1rem;text-align:center;
                    border:1px dashed rgba(0,255,170,.13);border-radius:3px;">
            ✓ No suspicious activity detected
        </div>""", unsafe_allow_html=True)
    else:
        icons  = {"low":"ℹ️","medium":"⚡","high":"🔥","critical":"🚨","critical_suspicious":"☠️"}
        labels = {"low":"LOW RISK","medium":"MEDIUM","high":"HIGH","critical":"CRITICAL","critical_suspicious":"CRITICAL SUSPICIOUS"}
        for ip, count in suspicious.items():
            level = attack_severity(int(count)).lower()
            st.markdown(f"""
            <div class="alert-row {level}">
                <span>{icons.get(level,'⚠️')}</span>
                <span class="alert-ip">{ip}</span>
                <span>{count} failed login attempts</span>
                <span class="alert-badge">{labels.get(level, level.upper())}</span>
            </div>""", unsafe_allow_html=True)

    # Charts
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown('<div class="section-header">◈ Top Suspicious IPs</div>', unsafe_allow_html=True)
        if len(suspicious) > 0:
            colors_bar = ["#00b4ff" if attack_severity(int(v)) == "LOW"
                          else "#ffaa00" if attack_severity(int(v)) == "MEDIUM"
                          else "#ff8844" if attack_severity(int(v)) == "HIGH"
                          else "#ff3355"
                          for v in suspicious.values]
            fig_bar = go.Figure(go.Bar(
                x=list(suspicious.index), y=list(suspicious.values),
                marker=dict(color=colors_bar, line=dict(width=0)),
                hovertemplate="<b>%{x}</b><br>Failed: %{y}<extra></extra>",
            ))
            fig_bar.update_layout(
                paper_bgcolor=DARK_BG, plot_bgcolor=DARK_BG,
                font=dict(family=FONT_MONO, color=FONT_COLOR, size=12),
                xaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)", title="IP Address",
                           tickfont=dict(size=11)),
                yaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)", title="Failed Attempts"),
                margin=dict(l=10,r=10,t=10,b=10), height=300,
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.markdown("<p style='font-family:Share Tech Mono,monospace;font-size:.85rem;color:rgba(0,255,170,.35);'>No suspicious IPs detected.</p>", unsafe_allow_html=True)

    with chart_col2:
        st.markdown('<div class="section-header">◈ Login Event Distribution</div>', unsafe_allow_html=True)
        if not df.empty:
            event_counts = df["Event"].value_counts()
            fig_pie = go.Figure(go.Pie(
                labels=list(event_counts.index), values=list(event_counts.values),
                hole=.55,
                marker=dict(
                    colors=["#00ffaa","#ff3355","#00b4ff","#ffaa00","#aa44ff"][:len(event_counts)],
                    line=dict(color="#020608", width=3),
                ),
                hovertemplate="<b>%{label}</b><br>%{value} events (%{percent})<extra></extra>",
                textfont=dict(family=FONT_MONO, size=12, color="#c8d8e8"),
            ))
            fig_pie.update_layout(
                paper_bgcolor=DARK_BG,
                font=dict(family=FONT_MONO, color=FONT_COLOR, size=12),
                legend=dict(font=dict(size=12, color=FONT_COLOR), bgcolor="rgba(0,0,0,0)"),
                margin=dict(l=10,r=10,t=10,b=10), height=300,
                annotations=[dict(text="EVENTS",x=.5,y=.5,font_size=13,
                                  font_color="#00ffaa",font_family=FONT_MONO,showarrow=False)],
            )
            st.plotly_chart(fig_pie, use_container_width=True)

    # Attacker map
    st.markdown('<div class="section-header">◈ Attacker IP Locations</div>', unsafe_allow_html=True)
    locations = []
    for ip in suspicious.index:
        loc = get_ip_location(ip)
        if loc and loc.get("lat") and loc.get("lon"):
            locations.append(loc)
    if locations:
        map_df = pd.DataFrame(locations).rename(columns={"lat":"latitude","lon":"longitude"})
        st.map(map_df, use_container_width=True)
    else:
        st.markdown("""
        <div style="font-family:'Share Tech Mono',monospace;font-size:.82rem;
                    color:rgba(0,255,170,.35);padding:.8rem;text-align:center;
                    border:1px dashed rgba(0,255,170,.1);border-radius:3px;">
            No geolocation data available
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: LOG ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.active_tab == "Log Analysis":

    if df.empty:
        st.warning("No log data loaded. Please upload a log file above.")
    else:
        # ── Summary stats ──────────────────────────────────────────────────
        st.markdown('<div class="section-header">◈ Log Summary</div>', unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f"""<div class="metric-card"><div class="metric-label">Total Events</div>
            <div class="metric-value">{len(df):,}</div></div>""", unsafe_allow_html=True)
        with c2:
            st.markdown(f"""<div class="metric-card amber"><div class="metric-label">Failed Logins</div>
            <div class="metric-value amber">{len(failed):,}</div></div>""", unsafe_allow_html=True)
        with c3:
            success_count = len(df[df["Event"].str.contains("SUCCESS", na=False)])
            st.markdown(f"""<div class="metric-card"><div class="metric-label">Successful Logins</div>
            <div class="metric-value">{success_count:,}</div></div>""", unsafe_allow_html=True)
        with c4:
            st.markdown(f"""<div class="metric-card blue"><div class="metric-label">Unique Users</div>
            <div class="metric-value blue">{df['User'].nunique()}</div></div>""", unsafe_allow_html=True)

        # ── Per-IP breakdown ───────────────────────────────────────────────
        st.markdown('<div class="section-header">◈ Suspicious IP Deep Dive</div>', unsafe_allow_html=True)

        if len(suspicious) == 0:
            st.markdown("""
            <div style="font-family:'Share Tech Mono',monospace;font-size:.85rem;
                        color:rgba(0,255,170,.45);padding:1rem;text-align:center;
                        border:1px dashed rgba(0,255,170,.13);border-radius:3px;">
                ✓ No suspicious IPs found (threshold: ≥ 3 failed attempts)
            </div>""", unsafe_allow_html=True)
        else:
            # ── CRITICAL SUSPICIOUS banner ─────────────────────────────────
            cs_ips = [(ip, int(cnt)) for ip, cnt in suspicious.items()
                      if attack_severity(int(cnt)) == "CRITICAL_SUSPICIOUS"]
            if cs_ips:
                cs_list = "".join(
                    f'<span style="font-weight:700;color:#ff0033;">{ip}</span>'
                    f'<span style="color:rgba(255,180,180,.6);font-size:.78rem;"> ({cnt} attempts)</span>'
                    f'{"  ·  " if i < len(cs_ips)-1 else ""}'
                    for i, (ip, cnt) in enumerate(cs_ips)
                )
                st.markdown(f"""
                <div style="background:rgba(60,0,10,.9);border:1px solid #ff0033;border-radius:4px;
                            padding:1rem 1.3rem;margin-bottom:1rem;
                            box-shadow:0 0 24px rgba(255,0,51,.2);
                            animation:csPulse 1s ease-in-out infinite;">
                    <div style="font-family:'Share Tech Mono',monospace;font-size:.8rem;
                                color:#ff0033;letter-spacing:.2em;margin-bottom:.45rem;">
                        ☠️ &nbsp; CRITICAL SUSPICIOUS DETECTED — BRUTE FORCE ATTACK LIKELY
                    </div>
                    <div style="font-family:'Share Tech Mono',monospace;font-size:.82rem;color:#ffaaaa;">
                        {len(cs_ips)} IP{'s' if len(cs_ips)>1 else ''} exceeded {CRITICAL_SUSPICIOUS_THRESHOLD} failed attempts:
                        &nbsp; {cs_list}
                    </div>
                    <div style="font-family:'Share Tech Mono',monospace;font-size:.7rem;
                                color:rgba(255,100,100,.55);margin-top:.4rem;letter-spacing:.1em;">
                        Threshold: &gt;{CRITICAL_SUSPICIOUS_THRESHOLD} failed logins · Immediate action recommended
                    </div>
                </div>
                """, unsafe_allow_html=True)

            selected_ip = st.selectbox(
                "Select IP to inspect",
                options=list(suspicious.index),
                format_func=lambda ip: (
                    f"☠️ {ip}  ({suspicious[ip]} attempts — CRITICAL SUSPICIOUS)"
                    if attack_severity(int(suspicious[ip])) == "CRITICAL_SUSPICIOUS"
                    else f"{ip}  ({suspicious[ip]} failed attempts — {attack_severity(int(suspicious[ip]))})"
                )
            )
            if selected_ip:
                details = get_ip_details(df, selected_ip)
                level   = details["severity"].lower()
                level_color = {"low":"#00b4ff","medium":"#ffcc00","high":"#ff8844","critical":"#ff3355","critical_suspicious":"#ff0033"}.get(level,"#fff")
                st.markdown(f"""
                <div class="ip-detail-card">
                    <div style="font-family:'Share Tech Mono',monospace;font-size:.9rem;
                                color:{level_color};letter-spacing:.15em;margin-bottom:.8rem;">
                        ◈ {selected_ip} &nbsp;·&nbsp; SEVERITY: {details['severity']}
                    </div>
                    <div class="ip-detail-row">
                        <span class="ip-detail-key">Total Requests</span>
                        <span class="ip-detail-value">{details['total_requests']}</span>
                    </div>
                    <div class="ip-detail-row">
                        <span class="ip-detail-key">Failed Attempts</span>
                        <span class="ip-detail-value" style="color:{level_color};">{details['failed_attempts']}</span>
                    </div>
                    <div class="ip-detail-row">
                        <span class="ip-detail-key">Successful Logins</span>
                        <span class="ip-detail-value">{details['successful_logins']}</span>
                    </div>
                    <div class="ip-detail-row">
                        <span class="ip-detail-key">Users Targeted</span>
                        <span class="ip-detail-value">{', '.join(details['users_targeted'])}</span>
                    </div>
                    <div class="ip-detail-row">
                        <span class="ip-detail-key">First Seen</span>
                        <span class="ip-detail-value">{details['first_seen']}</span>
                    </div>
                    <div class="ip-detail-row">
                        <span class="ip-detail-key">Last Seen</span>
                        <span class="ip-detail-value">{details['last_seen']}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Activity timeline for this IP
                ip_df = df[df["IP"] == selected_ip].copy()
                st.markdown(f'<div class="section-header">◈ Activity Timeline · {selected_ip}</div>', unsafe_allow_html=True)
                fig_timeline = go.Figure()
                for event_type, color in [("LOGIN_FAILED","#ff3355"),("LOGIN_SUCCESS","#00ffaa"),("LOGOUT","#00b4ff")]:
                    subset = ip_df[ip_df["Event"] == event_type]
                    if not subset.empty:
                        fig_timeline.add_trace(go.Scatter(
                            x=list(range(len(subset))),
                            y=[event_type] * len(subset),
                            mode="markers",
                            name=event_type,
                            marker=dict(color=color, size=10, symbol="circle"),
                            hovertemplate=f"<b>{event_type}</b><br>User: %{{customdata}}<extra></extra>",
                            customdata=subset["User"].tolist(),
                        ))
                fig_timeline.update_layout(
                    paper_bgcolor=DARK_BG, plot_bgcolor=DARK_BG,
                    font=dict(family=FONT_MONO, color=FONT_COLOR, size=12),
                    xaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)", title="Event #"),
                    yaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)"),
                    legend=dict(font=dict(size=12, color=FONT_COLOR), bgcolor="rgba(0,0,0,0)"),
                    margin=dict(l=10,r=10,t=10,b=10), height=260,
                )
                st.plotly_chart(fig_timeline, use_container_width=True)

        # ── Failed login trend ─────────────────────────────────────────────
        st.markdown('<div class="section-header">◈ Failed Login Trend by IP</div>', unsafe_allow_html=True)
        top_failed = failed["IP"].value_counts().head(15)
        if not top_failed.empty:
            fig_trend = go.Figure(go.Bar(
                x=list(top_failed.index), y=list(top_failed.values),
                marker=dict(
                    color=list(top_failed.values),
                    colorscale=[[0,"#00b4ff"],[0.4,"#ffaa00"],[1,"#ff3355"]],
                    line=dict(width=0),
                ),
                hovertemplate="<b>%{x}</b><br>Failed: %{y}<extra></extra>",
            ))
            fig_trend.update_layout(
                paper_bgcolor=DARK_BG, plot_bgcolor=DARK_BG,
                font=dict(family=FONT_MONO, color=FONT_COLOR, size=12),
                xaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)", title="IP Address"),
                yaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)", title="Failed Attempts"),
                margin=dict(l=10,r=10,t=10,b=10), height=300,
            )
            st.plotly_chart(fig_trend, use_container_width=True)

        # ── Most targeted users ────────────────────────────────────────────
        st.markdown('<div class="section-header">◈ Most Targeted User Accounts</div>', unsafe_allow_html=True)
        top_users_failed = failed["User"].value_counts().head(10)
        if not top_users_failed.empty:
            fig_users = go.Figure(go.Bar(
                x=list(top_users_failed.values),
                y=list(top_users_failed.index),
                orientation="h",
                marker=dict(color="#00b4ff", line=dict(width=0)),
                hovertemplate="<b>%{y}</b><br>Attacks: %{x}<extra></extra>",
            ))
            fig_users.update_layout(
                paper_bgcolor=DARK_BG, plot_bgcolor=DARK_BG,
                font=dict(family=FONT_MONO, color=FONT_COLOR, size=12),
                xaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)", title="Attack Count"),
                yaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)"),
                margin=dict(l=10,r=10,t=10,b=60), height=300,
            )
            st.plotly_chart(fig_users, use_container_width=True)

        # ── Filtered log table ─────────────────────────────────────────────
        st.markdown('<div class="section-header">◈ Log Explorer</div>', unsafe_allow_html=True)
        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            event_filter = st.selectbox(
                "Filter by Event",
                ["ALL"] + sorted(df["Event"].unique().tolist())
            )
        with filter_col2:
            ip_filter = st.selectbox(
                "Filter by IP",
                ["ALL"] + sorted(df["IP"].unique().tolist())
            )

        filtered_df = df.copy()
        if event_filter != "ALL":
            filtered_df = filtered_df[filtered_df["Event"] == event_filter]
        if ip_filter != "ALL":
            filtered_df = filtered_df[filtered_df["IP"] == ip_filter]

        # Build ip->severity map for flag column
        ip_severity_map = {ip: attack_severity(int(cnt)) for ip, cnt in suspicious.items()}
        cs_ips_set = {ip for ip, sev in ip_severity_map.items() if sev == "CRITICAL_SUSPICIOUS"}

        # Add Flag column
        def flag_row(row):
            sev = ip_severity_map.get(row["IP"], "")
            if sev == "CRITICAL_SUSPICIOUS":
                return "☠️ CRITICAL SUSPICIOUS"
            elif sev == "CRITICAL":
                return "🚨 CRITICAL"
            elif sev == "HIGH":
                return "🔥 HIGH"
            elif sev == "MEDIUM":
                return "⚡ MEDIUM"
            elif sev == "LOW":
                return "ℹ️ LOW"
            return ""

        display_df = filtered_df.copy()
        display_df.insert(0, "⚑ Flag", display_df.apply(flag_row, axis=1))

        # Count critical suspicious rows for callout
        cs_row_count = (display_df["⚑ Flag"] == "☠️ CRITICAL SUSPICIOUS").sum()

        st.markdown(f"""
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem;">
            <span style="font-family:'Share Tech Mono',monospace;font-size:.75rem;
                         color:rgba(0,180,255,.6);letter-spacing:.1em;">
                Showing {len(filtered_df):,} of {len(df):,} records
            </span>
            {f'<span style="font-family:Share Tech Mono,monospace;font-size:.75rem;color:#ff0033;letter-spacing:.1em;">☠️ {cs_row_count} CRITICAL SUSPICIOUS rows</span>' if cs_row_count > 0 else ""}
        </div>""", unsafe_allow_html=True)
        st.dataframe(display_df, use_container_width=True, height=380)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: REPORTS
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.active_tab == "Reports":

    if df.empty:
        st.warning("No log data loaded. Please upload a log file above.")
    else:
        report = generate_report_data(df, failed, suspicious)

        st.markdown(f"""
        <div style="font-family:'Share Tech Mono',monospace;font-size:.75rem;
                    color:rgba(0,180,255,.5);letter-spacing:.1em;margin-bottom:1.5rem;">
            Report generated: {report.get('generated_at','—')}
        </div>""", unsafe_allow_html=True)

        # ── Executive summary cards ────────────────────────────────────────
        st.markdown('<div class="section-header">◈ Executive Summary</div>', unsafe_allow_html=True)
        r1, r2, r3, r4, r5 = st.columns(5)
        cards = [
            (r1, "Total Events",     report['total_logs'],       "", ""),
            (r2, "Failed Logins",    report['total_failed'],     "amber", "amber"),
            (r3, "Suspicious IPs",   report['total_suspicious'], "red",   "red"),
            (r4, "Unique IPs",       report['unique_ips'],       "blue",  "blue"),
            (r5, "Unique Users",     report['unique_users'],     "", ""),
        ]
        for col, label, val, card_cls, val_cls in cards:
            with col:
                st.markdown(f"""
                <div class="metric-card {card_cls}">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value {val_cls}">{val:,}</div>
                </div>""", unsafe_allow_html=True)

        # ── Severity breakdown ─────────────────────────────────────────────
        st.markdown('<div class="section-header">◈ Threat Severity Breakdown</div>', unsafe_allow_html=True)
        sev = report["severity_breakdown"]
        sev_col1, sev_col2 = st.columns(2)

        with sev_col1:
            sev_labels = list(sev.keys())
            sev_values = list(sev.values())
            sev_colors = ["#00b4ff","#ffcc00","#ff8844","#ff3355","#ff0033"]
            fig_sev = go.Figure(go.Bar(
                x=sev_labels, y=sev_values,
                marker=dict(color=sev_colors[:len(sev_labels)], line=dict(width=0)),
                hovertemplate="<b>%{x}</b><br>IPs: %{y}<extra></extra>",
            ))
            fig_sev.update_layout(
                paper_bgcolor=DARK_BG, plot_bgcolor=DARK_BG,
                font=dict(family=FONT_MONO, color=FONT_COLOR, size=12),
                xaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)", title="Severity Level"),
                yaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)", title="Number of IPs"),
                margin=dict(l=10,r=10,t=10,b=10), height=280,
            )
            st.plotly_chart(fig_sev, use_container_width=True)

        with sev_col2:
            fig_sev_pie = go.Figure(go.Pie(
                labels=sev_labels, values=sev_values, hole=.5,
                marker=dict(colors=sev_colors, line=dict(color="#020608", width=3)),
                textfont=dict(family=FONT_MONO, size=12, color="#c8d8e8"),
                hovertemplate="<b>%{label}</b><br>%{value} IPs (%{percent})<extra></extra>",
            ))
            fig_sev_pie.update_layout(
                paper_bgcolor=DARK_BG,
                font=dict(family=FONT_MONO, color=FONT_COLOR, size=12),
                legend=dict(font=dict(size=12, color=FONT_COLOR), bgcolor="rgba(0,0,0,0)"),
                margin=dict(l=10,r=10,t=10,b=10), height=280,
                annotations=[dict(text="SEVERITY",x=.5,y=.5,font_size=11,
                                  font_color="#00ffaa",font_family=FONT_MONO,showarrow=False)],
            )
            st.plotly_chart(fig_sev_pie, use_container_width=True)

        # ── Hourly activity chart ──────────────────────────────────────────
        if report.get("hourly_events") is not None and not report["hourly_events"].empty:
            st.markdown('<div class="section-header">◈ Hourly Activity Timeline</div>', unsafe_allow_html=True)
            hourly = report["hourly_events"]
            fig_hourly = go.Figure(go.Scatter(
                x=hourly["Hour"].astype(str).tolist(),
                y=hourly["Count"].tolist(),
                mode="lines+markers",
                line=dict(color="#00ffaa", width=2),
                marker=dict(color="#00ffaa", size=6),
                fill="tozeroy",
                fillcolor="rgba(0,255,170,0.05)",
                hovertemplate="<b>%{x}</b><br>Events: %{y}<extra></extra>",
            ))
            fig_hourly.update_layout(
                paper_bgcolor=DARK_BG, plot_bgcolor=DARK_BG,
                font=dict(family=FONT_MONO, color=FONT_COLOR, size=12),
                xaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)", title="Hour"),
                yaxis=dict(gridcolor=GRID_COLOR, linecolor="rgba(0,0,0,0)", title="Event Count"),
                margin=dict(l=10,r=10,t=10,b=10), height=280,
            )
            st.plotly_chart(fig_hourly, use_container_width=True)

        # ── Top IPs table ──────────────────────────────────────────────────
        st.markdown('<div class="section-header">◈ Top 10 IPs by Activity</div>', unsafe_allow_html=True)
        top_ips_items = list(report["top_ips"].items())
        rows = ""
        for rank, (ip, count) in enumerate(top_ips_items, 1):
            is_susp   = ip in suspicious.index
            susp_tag  = f'<span style="color:#ff6688;font-size:.7rem;border:1px solid #ff3355;border-radius:2px;padding:.05rem .3rem;margin-left:.5rem;">SUSPICIOUS</span>' if is_susp else ""
            fail_cnt  = int(suspicious[ip]) if is_susp else 0
            sev_label = attack_severity(fail_cnt) if is_susp else "—"
            sev_color = {"LOW":"#00b4ff","MEDIUM":"#ffcc00","HIGH":"#ff8844","CRITICAL":"#ff3355","CRITICAL_SUSPICIOUS":"#ff0033"}.get(sev_label,"#6a9080")
            rows += f"""
            <tr>
                <td style="color:rgba(0,180,255,.5);">#{rank}</td>
                <td>{ip}{susp_tag}</td>
                <td>{count:,}</td>
                <td>{fail_cnt if fail_cnt else '—'}</td>
                <td style="color:{sev_color};">{sev_label}</td>
            </tr>"""

        st.markdown(f"""
        <table class="report-table">
            <thead><tr>
                <th>#</th><th>IP Address</th><th>Total Requests</th>
                <th>Failed Logins</th><th>Severity</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>""", unsafe_allow_html=True)

        # ── Top users table ────────────────────────────────────────────────
        st.markdown('<div class="section-header">◈ Top 10 Targeted Users</div>', unsafe_allow_html=True)
        user_rows = ""
        for rank, (user, total) in enumerate(report["top_users"].items(), 1):
            fail_cnt = len(failed[failed["User"] == user])
            pct = round(fail_cnt / total * 100) if total > 0 else 0
            bar_w = max(4, pct)
            user_rows += f"""
            <tr>
                <td style="color:rgba(0,180,255,.5);">#{rank}</td>
                <td>{user}</td>
                <td>{total:,}</td>
                <td>{fail_cnt:,}</td>
                <td>
                    <div style="display:flex;align-items:center;gap:.5rem;">
                        <div style="width:{bar_w}%;max-width:120px;height:6px;
                                    background:#ff3355;border-radius:2px;min-width:4px;"></div>
                        <span style="font-size:.72rem;color:rgba(255,51,85,.8);">{pct}%</span>
                    </div>
                </td>
            </tr>"""

        st.markdown(f"""
        <table class="report-table">
            <thead><tr>
                <th>#</th><th>Username</th><th>Total Events</th>
                <th>Failed Logins</th><th>Failure Rate</th>
            </tr></thead>
            <tbody>{user_rows}</tbody>
        </table>""", unsafe_allow_html=True)

        # ── Event type breakdown ───────────────────────────────────────────
        st.markdown('<div class="section-header">◈ Event Type Breakdown</div>', unsafe_allow_html=True)
        evt_rows = ""
        total_events = sum(report["event_counts"].values())
        for evt, cnt in sorted(report["event_counts"].items(), key=lambda x: -x[1]):
            pct  = round(cnt / total_events * 100, 1) if total_events else 0
            color = "#ff3355" if "FAIL" in evt else "#00ffaa" if "SUCCESS" in evt else "#00b4ff"
            bar_w = max(4, int(pct))
            evt_rows += f"""
            <tr>
                <td style="color:{color};">{evt}</td>
                <td>{cnt:,}</td>
                <td>
                    <div style="display:flex;align-items:center;gap:.5rem;">
                        <div style="width:{bar_w}%;max-width:180px;height:6px;
                                    background:{color};border-radius:2px;min-width:4px;opacity:.75;"></div>
                        <span style="font-size:.72rem;color:rgba(200,216,200,.6);">{pct}%</span>
                    </div>
                </td>
            </tr>"""

        st.markdown(f"""
        <table class="report-table">
            <thead><tr><th>Event Type</th><th>Count</th><th>Distribution</th></tr></thead>
            <tbody>{evt_rows}</tbody>
        </table>""", unsafe_allow_html=True)

        # ── Download button ────────────────────────────────────────────────
        st.markdown('<div class="section-header">◈ Export Report</div>', unsafe_allow_html=True)

        report_text = f"""SECURESHIELD SECURITY REPORT
Generated: {report['generated_at']}
Operator:  {st.session_state.owner_email}
{'='*60}

EXECUTIVE SUMMARY
  Total Log Events   : {report['total_logs']:,}
  Failed Logins      : {report['total_failed']:,}
  Suspicious IPs     : {report['total_suspicious']:,}
  Unique IPs         : {report['unique_ips']:,}
  Unique Users       : {report['unique_users']:,}

SEVERITY BREAKDOWN
  LOW      : {sev['LOW']} IPs
  MEDIUM   : {sev['MEDIUM']} IPs
  HIGH     : {sev['HIGH']} IPs
  CRITICAL : {sev['CRITICAL']} IPs

TOP SUSPICIOUS IPs
{'IP Address':<20} {'Failed Attempts':<18} Severity
{'-'*50}
""" + "\n".join(
    f"{ip:<20} {int(cnt):<18} {attack_severity(int(cnt))}"
    for ip, cnt in suspicious.items()
) + f"""

TOP TARGETED USERS
{'Username':<20} {'Total':<10} Failed
{'-'*40}
""" + "\n".join(
    f"{u:<20} {t:<10} {len(failed[failed['User']==u])}"
    for u, t in report['top_users'].items()
)

        st.download_button(
            label="⬇  DOWNLOAD REPORT (.txt)",
            data=report_text,
            file_name=f"secureshield_report_{report['generated_at'].replace(' ','_').replace(':','-')}.txt",
            mime="text/plain",
            use_container_width=True,
        )


# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="margin-top:3rem;padding-top:1rem;
            border-top:1px solid rgba(0,255,170,.08);
            display:flex;justify-content:space-between;">
    <span style="font-family:'Share Tech Mono',monospace;font-size:.68rem;
                 color:rgba(0,255,170,.28);letter-spacing:.1em;">
        SECURESHIELD · THREAT INTELLIGENCE PLATFORM
    </span>
    <span style="font-family:'Share Tech Mono',monospace;font-size:.68rem;
                 color:rgba(0,180,255,.28);letter-spacing:.1em;">
        v2.4.1 · ALL SYSTEMS NOMINAL
    </span>
</div>
""", unsafe_allow_html=True)
