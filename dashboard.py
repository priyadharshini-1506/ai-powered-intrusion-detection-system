import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
import numpy as np
import time
 
from predictor import predict
from risk_engine import get_risk
from alert_engine import get_alert
from shap_engine import get_top_features
from prevention_engine import get_prevention
 
# ══════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════
 
st.set_page_config(
    page_title="CyberSentinel IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)
 
# ══════════════════════════════════════════════
# GLOBAL CSS
# ══════════════════════════════════════════════
 
st.markdown("""
<style>
 
@import url('https://fonts.googleapis.com/css2?family=Caveat:wght@700&display=swap');
 
*, *::before, *::after {
    box-sizing: border-box;
}
 
.stApp {
    background: #0F172A !important;
    font-family: 'Helvetica', sans-serif !important;
}
 
#MainMenu, footer, header {
    visibility: hidden;
}
 
section[data-testid="stSidebar"] {
    display: none;
}
 
.block-container {
    max-width: 1600px;
    padding: 2.5rem 3rem !important;
}
 
[data-testid="metric-container"] {
    background: #1E293B !important;
    border: 1px solid #334155 !important;
    border-radius: 8px !important;
    padding: 22px 18px !important;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2) !important;
}
 
[data-testid="stMetricLabel"] {
    color: #94A3B8 !important;
    font-size: 10px !important;
    font-weight: 700 !important;
    font-family: 'Helvetica', sans-serif !important;
    text-transform: uppercase !important;
    letter-spacing: 1.5px !important;
}
 
[data-testid="stMetricValue"] {
    color: #F8FAFC !important;
    font-size: 28px !important;
    font-weight: 800 !important;
    font-family: 'Helvetica', sans-serif !important;
    letter-spacing: -0.02em !important;
}
 
[data-testid="stMetricDelta"] {
    color: #22C55E !important;
    font-size: 11px !important;
    font-family: 'Helvetica', sans-serif !important;
    font-weight: 600 !important;
}
 
.stButton > button {
    background: #22C55E !important;
    color: #0F172A !important;
    border: none !important;
    border-radius: 6px !important;
    font-size: 11px !important;
    font-weight: 700 !important;
    padding: 6px 14px !important;
    letter-spacing: 0.5px !important;
    text-transform: uppercase !important;
    font-family: 'Helvetica', sans-serif !important;
    transition: background 0.15s, transform 0.1s !important;
    width: auto !important;
    min-width: 130px !important;
}
 
.stButton > button * {
    color: #0F172A !important;
}
 
.stButton > button:hover {
    background: #16a34a !important;
    color: #0F172A !important;
    transform: translateY(-1px) !important;
}
 
.stAlert {
    border-radius: 6px !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    letter-spacing: 0.5px !important;
    border-left-width: 4px !important;
    background-color: #1E293B !important;
    border-color: #334155 !important;
    color: #F8FAFC !important;
}
 
details {
    background: #1E293B !important;
    border: 1px solid #334155 !important;
    border-radius: 8px !important;
    padding: 12px !important;
}
 
.eyebrow {
    color: #22C55E !important;
    font-size: 16px !important;
    font-weight: 800 !important;
    text-transform: uppercase !important;
    letter-spacing: 3px !important;
    font-family: 'Helvetica', sans-serif !important;
    margin-top: 15px !important;
    margin-bottom: 20px !important;
    text-align: center !important;
}
 
.live-dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #22C55E;
    margin-right: 6px;
    animation: blink 1.4s infinite;
}
 
@keyframes blink {
    0%   { opacity: 1; }
    50%  { opacity: 0; }
    100% { opacity: 1; }
}
 
.stCodeBlock {
    border-radius: 6px !important;
    background: #1E293B !important;
    border: 1px solid #334155 !important;
}
 
.stCodeBlock code,
.stCodeBlock pre,
.stCodeBlock span,
.stCodeBlock div {
    color: #F8FAFC !important;
    background: #1E293B !important;
}
 
hr {
    border-color: #334155 !important;
    border-width: 1.5px !important;
}
 
p, span, label, div {
    color: #94A3B8;
    font-family: 'Helvetica', sans-serif;
    line-height: 1.6;
}
 
h1, h2, h3, h4, h5, h6 {
    color: #F8FAFC !important;
    font-weight: 700 !important;
    letter-spacing: -0.02em !important;
    font-family: 'Helvetica', sans-serif !important;
}
 
.stDownloadButton > button {
    background: transparent !important;
    color: #22C55E !important;
    border: 1.5px solid #22C55E !important;
    border-radius: 6px !important;
    font-size: 12px !important;
    font-weight: 700 !important;
    letter-spacing: 1.5px !important;
    text-transform: uppercase !important;
}
 
.stDownloadButton > button:hover {
    background: #22C55E !important;
    color: #0F172A !important;
}
 
</style>
""", unsafe_allow_html=True)
 
# ══════════════════════════════════════════════
# TOP CENTERED TITLE
# ══════════════════════════════════════════════
 
st.markdown("""
<div style="font-size:38px; font-weight:700; color:#F8FAFC;
            font-family:'Times New Roman', Times, serif; line-height:1.2;
            margin-bottom:35px; text-align:center;">
    An Explainable Extra Trees Framework for Efficient IoT Intrusion Detection
    Using SHAP-Based Feature Interpretation
</div>
""", unsafe_allow_html=True)
 
# ══════════════════════════════════════════════
# COLOR PALETTES
# ══════════════════════════════════════════════
 
BAR_COLORS   = ["#1e293b", "#334155", "#475569", "#16a34a", "#22C55E"]
DONUT_COLORS = ["#22C55E", "#16a34a", "#475569", "#334155", "#1e293b"]
LINE_COLOR   = "#22C55E"
FILL_COLOR   = "rgba(34, 197, 94, 0.05)"
 
# ══════════════════════════════════════════════
# CHART HELPER
# ══════════════════════════════════════════════
 
def make_layout(title_text, height, xaxis=None, yaxis=None,
                showlegend=False, extra=None):
    layout = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Helvetica, sans-serif", color="#94A3B8", size=11),
        margin=dict(l=10, r=10, t=40, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=10, color="#94A3B8")),
        title=dict(text=title_text, font=dict(size=14, color="#22C55E", family="Helvetica", weight="bold")),
        height=height,
        showlegend=showlegend,
    )
    if xaxis is not None:
        layout["xaxis"] = xaxis
    if yaxis is not None:
        layout["yaxis"] = yaxis
    if extra:
        layout.update(extra)
    return layout
 
GRID  = dict(gridcolor="rgba(148, 163, 184, 0.1)", zeroline=False, linecolor="rgba(148, 163, 184, 0.2)", color="#94A3B8")
CLEAN = dict(gridcolor="rgba(0,0,0,0)", zeroline=False, tickfont=dict(size=10, color="#94A3B8"))
 
# ══════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════
 
def get_threat_score(risk, alert, attack):
    level = {"SAFE": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    k     = next((k for k in level if k in alert.upper()), "SAFE")
    score = round(risk * 0.7 + level[k] * 10, 2)
    if attack.lower() == "normal":
        score = min(score * 0.2, 15)
    return min(score, 100)
 
 
def render_log_table(display_df):
    """Render the live security log via components.html (bypasses Streamlit HTML sanitizer)."""
 
    def badge(alert):
        a = alert.upper()
        if "CRITICAL" in a:
            bg, color, label = "rgba(239,68,68,0.15)", "#ef4444", "CRITICAL"
        elif "HIGH" in a:
            bg, color, label = "rgba(249,115,22,0.15)", "#f97316", "HIGH"
        elif "MEDIUM" in a:
            bg, color, label = "rgba(234,179,8,0.15)", "#eab308", "MEDIUM"
        else:
            bg, color, label = "rgba(34,197,94,0.15)", "#22C55E", "SAFE"
        return (
            f'<span style="background:{bg};color:{color};'
            f'padding:2px 8px;border-radius:4px;font-size:10px;'
            f'font-weight:700;letter-spacing:1px;text-transform:uppercase;">'
            f'{label}</span>'
        )
 
    def threat_color(score_str):
        try:
            v = float(score_str)
        except Exception:
            return score_str
        if v > 80:
            color = "#ef4444"
        elif v > 60:
            color = "#f97316"
        elif v > 30:
            color = "#eab308"
        else:
            color = "#22C55E"
        return f'<span style="color:{color};font-weight:700;">{score_str}</span>'
 
    rows_html = ""
    for idx, row in display_df.iterrows():
        bg = "#263348" if idx % 2 == 0 else "#1E293B"
        rows_html += f"""
        <tr style="background:{bg};border-bottom:1px solid #334155;">
            <td style="padding:9px 14px;color:#94A3B8;font-size:12px;">{row['Time']}</td>
            <td style="padding:9px 14px;color:#94A3B8;font-size:12px;">{int(row['Packet'])}</td>
            <td style="padding:9px 14px;color:#F8FAFC;font-size:12px;font-weight:600;">{row['Attack']}</td>
            <td style="padding:9px 14px;color:#94A3B8;font-size:12px;">{row['Risk']}</td>
            <td style="padding:9px 14px;font-size:12px;">{badge(row['Alert'])}</td>
            <td style="padding:9px 14px;font-size:12px;">{threat_color(row['ThreatScore'])}</td>
        </tr>"""
 
    full_html = f"""<!DOCTYPE html>
<html>
<head>
<style>
    body {{
        margin: 0;
        padding: 0;
        background: transparent;
        font-family: Helvetica, sans-serif;
    }}
    .wrap {{
        overflow-x: auto;
        border-radius: 8px;
        border: 1px solid #334155;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        background: #1E293B;
    }}
    thead tr {{
        background: #0F172A;
        border-bottom: 2px solid #334155;
    }}
    thead th {{
        padding: 10px 14px;
        text-align: left;
        color: #94A3B8;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        white-space: nowrap;
    }}
    tbody tr:hover {{
        background: #2d3f55 !important;
    }}
</style>
</head>
<body>
<div class="wrap">
    <table>
        <thead>
            <tr>
                <th>Time</th>
                <th>Packet</th>
                <th>Attack Type</th>
                <th>Risk</th>
                <th>Alert</th>
                <th>Threat Score</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
</div>
</body>
</html>"""
 
    row_count = len(display_df)
    height = max(200, row_count * 38 + 60)
    components.html(full_html, height=height, scrolling=False)
 
 
# ══════════════════════════════════════════════
# MODEL PERFORMANCE
# ══════════════════════════════════════════════
 
st.markdown('<div class="eyebrow" style="margin-top: 0px !important;">Model Performance</div>', unsafe_allow_html=True)
 
p1, p2, p3, p4 = st.columns(4)
p1.metric("Accuracy",  "99.54%", "Extra Trees classifier")
p2.metric("Precision", "99%",    "Low false positive")
p3.metric("Recall",    "99%",    "Low false negative")
p4.metric("F1 Score",  "99%",    "Weighted macro avg")
 
st.divider()
 
col_btn, _ = st.columns([1, 8])
with col_btn:
    start = st.button("▶ Start")
 
placeholder = st.empty()
 
# ══════════════════════════════════════════════
# LOAD DATA
# ══════════════════════════════════════════════
 
df = pd.read_csv(r"D:\files\test_data.csv")
X  = df.drop(columns=["label"]) if "label" in df.columns else df.copy()
 
# ══════════════════════════════════════════════
# SESSION STATE
# ══════════════════════════════════════════════
 
if "log" not in st.session_state:
    st.session_state.log = []
if "threat_trend" not in st.session_state:
    st.session_state.threat_trend = []
 
# ══════════════════════════════════════════════
# MAIN LOOP
# ══════════════════════════════════════════════
 
if start:
    for i in range(len(X)):
 
        row          = X.iloc[[i]]
        current_time = datetime.now().strftime("%H:%M:%S")
        attack, prob = predict(row)
        risk         = get_risk(prob, attack)
        alert        = get_alert(risk)
        threat_score = get_threat_score(risk, alert, attack)
 
        shap_data = None
        if risk > 70:
            try:
                shap_data = get_top_features(row)
            except Exception:
                pass
 
        prevention = get_prevention(attack)
 
        st.session_state.log.append({
            "Time":        current_time,
            "Packet":      i + 1,
            "Attack":      attack,
            "Risk":        round(risk, 2),
            "Alert":       alert,
            "ThreatScore": threat_score,
        })
        st.session_state.threat_trend.append(threat_score)
 
        log_df = pd.DataFrame(st.session_state.log)
 
        with placeholder.container():
 
            # ── SOC Metrics ────────────────────────
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Packets Analyzed", f"{i+1:,}")
            c2.metric("Risk Score",       f"{risk:.1f}%",
                      delta="elevated" if risk > 70 else "normal",
                      delta_color="inverse")
            c3.metric("Alert Level",      alert.split()[-1])
            c4.metric("Threat Score",     f"{threat_score:.1f}/100",
                      delta="critical" if threat_score > 80 else "stable",
                      delta_color="inverse" if threat_score > 80 else "off")
 
            st.markdown(
                f'<p style="font-size:14px;color:#94A3B8;'
                f'font-family:Helvetica,sans-serif;margin:4px 0 10px;'
                f'letter-spacing:1px;text-transform:uppercase;font-weight:600">'
                f'🕒 {current_time}</p>',
                unsafe_allow_html=True
            )
 
            # ── Threat Banner ──────────────────────
            if   threat_score > 80: st.error(  f"🔴 CRITICAL THREAT — {attack}")
            elif threat_score > 60: st.warning(f"🟠 HIGH THREAT — {attack}")
            elif threat_score > 30: st.info(   f"🟡 MEDIUM THREAT — {attack}")
            else:                   st.success( f"🟢 LOW THREAT — {attack}")
 
            st.divider()
 
            # ── Two column layout ──────────────────
            col_left, col_right = st.columns([3, 2])
 
            with col_left:
 
                # ── Attack Distribution Bar (Top 5) ────
                attack_count_full = (
                    log_df.groupby("Attack").size()
                    .reset_index(name="Count")
                )
 
                attack_count = (
                    attack_count_full
                    .sort_values("Count", ascending=False)
                    .head(5)
                    .sort_values("Count", ascending=True)
                    .reset_index(drop=True)
                )
 
                n_bars = len(attack_count)
                bar_color_seq = BAR_COLORS[-n_bars:] if n_bars <= 5 else BAR_COLORS
 
                fig_bar = go.Figure(go.Bar(
                    x=attack_count["Count"],
                    y=attack_count["Attack"],
                    orientation="h",
                    marker=dict(color=bar_color_seq, line=dict(width=0)),
                    text=attack_count["Count"],
                    textfont=dict(family="Helvetica", size=10, color="#F8FAFC"),
                    textposition="outside",
                ))
                fig_bar.update_layout(
                    **make_layout("TOP 5 ATTACK DISTRIBUTION", 260, xaxis=GRID, yaxis=CLEAN)
                )
                st.plotly_chart(fig_bar, use_container_width=True, key=f"bar_{i}")
 
                # ── Threat Score Line Chart ────────
                if len(st.session_state.threat_trend) > 1:
                    trend_df = pd.DataFrame({
                        "Packet": range(1, len(st.session_state.threat_trend) + 1),
                        "Score":  st.session_state.threat_trend,
                    })
 
                    marker_colors = [
                        "#22C55E" if s > 80 else "#16a34a" if s > 60 else "#475569"
                        for s in trend_df["Score"]
                    ]
 
                    fig_line = go.Figure()
                    fig_line.add_hrect(y0=80, y1=100, fillcolor="rgba(34, 197, 94, 0.04)", line_width=0)
                    fig_line.add_hrect(y0=60, y1=80,  fillcolor="rgba(34, 197, 94, 0.01)", line_width=0)
 
                    fig_line.add_trace(go.Scatter(
                        x=trend_df["Packet"],
                        y=trend_df["Score"],
                        mode="lines+markers",
                        line=dict(color=LINE_COLOR, width=2),
                        marker=dict(size=4, color=marker_colors),
                        fill="tozeroy",
                        fillcolor=FILL_COLOR,
                        name="Threat Score",
                    ))
                    fig_line.add_hline(
                        y=80,
                        line=dict(color="#22C55E", width=1, dash="dot"),
                        annotation_text="CRITICAL",
                        annotation_font=dict(size=9, color="#22C55E", family="Helvetica"),
                        annotation_position="top right",
                    )
                    fig_line.add_hline(
                        y=60,
                        line=dict(color="#16a34a", width=1, dash="dot"),
                        annotation_text="HIGH",
                        annotation_font=dict(size=9, color="#16a34a", family="Helvetica"),
                        annotation_position="top right",
                    )
                    fig_line.update_layout(
                        **make_layout(
                            "THREAT SCORE OVER TIME", 300,
                            xaxis={
                                **GRID,
                                "title": "Packet #",
                                "side": "bottom",
                                "mirror": False,
                                "showline": True,
                                "linecolor": "rgba(148,163,184,0.2)",
                                "ticks": "outside",
                                "tickcolor": "rgba(148,163,184,0.3)",
                                "rangemode": "tozero",
                            },
                            yaxis={
                                **GRID,
                                "range": [0, 105],
                                "title": "Score",
                                "side": "left",
                                "mirror": False,
                            },
                            showlegend=False,
                        )
                    )
                    fig_line.update_xaxes(showgrid=False, zeroline=False)
                    fig_line.update_yaxes(showgrid=True)
                    st.plotly_chart(fig_line, use_container_width=True, key=f"line_{i}")
 
            with col_right:
 
                # ── SHAP Explainability ────────────
                st.markdown(
                    '<p style="font-size:14px;font-weight:700;color:#22C55E;'
                    'text-transform:uppercase;letter-spacing:2px;'
                    'margin-bottom:8px;font-family:Helvetica,sans-serif">'
                    'SHAP Explainability</p>',
                    unsafe_allow_html=True,
                )
 
                if shap_data is not None:
                    n_shap = len(shap_data)
                    shap_color_seq = BAR_COLORS[-n_shap:] if n_shap <= 5 else BAR_COLORS
 
                    fig_shap = go.Figure(go.Bar(
                        x=shap_data["Importance"],
                        y=shap_data["Feature"],
                        orientation="h",
                        marker=dict(color=shap_color_seq, line=dict(width=0)),
                        text=[f"{v:.3f}" for v in shap_data["Importance"]],
                        textfont=dict(family="Helvetica", size=10, color="#F8FAFC"),
                        textposition="outside",
                    ))
                    fig_shap.update_layout(
                        **make_layout("TOP 5 FEATURES", 260, xaxis=GRID, yaxis=CLEAN)
                    )
                    st.plotly_chart(fig_shap, use_container_width=True, key=f"shap_{i}")
                else:
                    st.markdown(
                        '<div style="background:#1E293B;'
                        'border-left:3px solid #22C55E;'
                        'padding:14px 16px;border-radius:4px;'
                        'font-size:11px;color:#94A3B8;'
                        'font-family:Helvetica,sans-serif;'
                        'border-top:1px solid #334155;'
                        'border-bottom:1px solid #334155;'
                        'border-right:1px solid #334155;'
                        'letter-spacing:0.5px">'
                        'SHAP available only for risk &gt; 70%'
                        '</div>',
                        unsafe_allow_html=True,
                    )
 
                # ── Attack Share Donut ──
                total_packets = attack_count["Count"].sum()
                top_pct = (
                    int(round(attack_count.iloc[-1]["Count"] / total_packets * 100))
                    if total_packets > 0 else 0
                )
                top_label = attack_count.iloc[-1]["Attack"] if len(attack_count) > 0 else ""
 
                n_donut = len(attack_count)
                donut_colors = DONUT_COLORS[:n_donut]
 
                fig_pie = go.Figure(go.Pie(
                    labels=attack_count["Attack"],
                    values=attack_count["Count"],
                    hole=0.62,
                    textinfo="none",
                    marker=dict(colors=donut_colors, line=dict(color="#0F172A", width=2)),
                    hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>",
                ))
                fig_pie.update_layout(
                    **make_layout("ATTACK SHARE", 280, showlegend=True,
                        extra=dict(
                            annotations=[dict(
                                text=f"<b>{top_pct}%</b><br>"
                                     f"<span style='font-size:9px'>{top_label}</span>",
                                x=0.5, y=0.5,
                                font=dict(family="Helvetica", size=15, color="#F8FAFC"),
                                showarrow=False, align="center",
                            )],
                            legend=dict(font=dict(size=9, color="#94A3B8"), bgcolor="rgba(0,0,0,0)", orientation="v"),
                        )
                    )
                )
                st.plotly_chart(fig_pie, use_container_width=True, key=f"pie_{i}")
 
            st.divider()
 
            # ── Prevention Engine ──────────────────
            st.markdown(
                '<p style="font-size:14px;font-weight:700;color:#22C55E;'
                'text-transform:uppercase;letter-spacing:2px;'
                'margin-bottom:6px;font-family:Helvetica,sans-serif">'
                '🛡️ Prevention Engine</p>',
                unsafe_allow_html=True,
            )
            st.markdown(prevention, unsafe_allow_html=True)
 
            st.divider()
 
            # ── Live Security Log ──────────────────
            st.markdown(
                '<p style="font-size:14px;font-weight:700;color:#22C55E;'
                'text-transform:uppercase;letter-spacing:2px;'
                'margin-bottom:10px;font-family:Helvetica,sans-serif">'
                '📜 Live Security Log</p>',
                unsafe_allow_html=True,
            )
 
            display_df = log_df.tail(15).copy()
            display_df["Risk"] = display_df["Risk"].apply(lambda v: f"{v:.2f}%")
            display_df["ThreatScore"] = display_df["ThreatScore"].apply(lambda v: f"{v:.1f}")
            display_df = display_df[::-1].reset_index(drop=True)
 
            render_log_table(display_df)
 
            st.divider()
 
            # ── Download Report ────────────────────
            st.download_button(
                label="📄 Download Security Report",
                data=log_df.to_csv(index=False),
                file_name=f"IDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                key=f"dl_{i}",
            )
 
        time.sleep(0.2)
 