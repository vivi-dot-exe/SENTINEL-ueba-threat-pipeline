"""
app.py
SENTINEL // Autonomous AI DLP & Insider Threat Intelligence Platform.
Interactive Streamlit Dashboard providing User & Entity Behavior Analytics (UEBA),
anomaly visualization, and Gemini-powered forensic compliance briefings.
"""

import os
import json
import pandas as pd
import numpy as np
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv

from ueba_engine import analyze_ueba_stream
from ueba_generator import generate_synthetic_ueba_logs
from dlp_auditor import generate_forensic_audit_report

# Page Configuration & Dark Cyber Theme
load_dotenv()
st.set_page_config(
    page_title="SENTINEL // AI DLP & Insider Threat Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Aesthetic Cybersecurity CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap');
    
    .stApp {
        background-color: #0B0E14;
        font-family: 'Plus Jakarta Sans', sans-serif;
        color: #E2E8F0;
    }
    
    h1, h2, h3, h4 {
        font-family: 'Plus Jakarta Sans', sans-serif;
        font-weight: 600;
        letter-spacing: -0.02em;
    }
    
    .cyber-title {
        font-size: 2.2rem;
        font-weight: 700;
        background: linear-gradient(90deg, #38BDF8 0%, #818CF8 50%, #C084FC 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2px;
    }
    
    .cyber-subtitle {
        color: #94A3B8;
        font-size: 0.95rem;
        margin-bottom: 20px;
    }
    
    .metric-card {
        background: #111827;
        border: 1px solid #1E293B;
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        border-color: #38BDF8;
        transform: translateY(-2px);
    }
    .metric-num {
        font-family: 'JetBrains Mono', monospace;
        font-size: 2rem;
        font-weight: 700;
        color: #F8FAFC;
    }
    .metric-label {
        font-size: 0.75rem;
        font-weight: 600;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }
    
    .threat-card {
        background: #131B2E;
        border: 1px solid #1E293B;
        border-radius: 12px;
        padding: 18px;
        margin-bottom: 12px;
    }
    .badge-critical {
        background-color: #450A0A;
        color: #F87171;
        border: 1px solid #991B1B;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-high {
        background-color: #431407;
        color: #FB923C;
        border: 1px solid #C2410C;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }
    
    .briefing-box {
        background: #0F172A;
        border: 1px solid #334155;
        border-left: 4px solid #818CF8;
        border-radius: 8px;
        padding: 24px 28px;
        line-height: 1.7;
        color: #E2E8F0;
        margin-top: 15px;
    }
    
    code {
        font-family: 'JetBrains Mono', monospace !important;
        background: #1E293B !important;
        color: #38BDF8 !important;
        padding: 2px 6px !important;
        border-radius: 4px !important;
    }
</style>
""", unsafe_allow_html=True)


# Data Ingestion / Validation
@st.cache_data(show_spinner=False)
def load_security_data():
    logs_file = "ueba_analyzed_logs.csv"
    dossiers_file = "employee_risk_dossiers.json"
    
    if not os.path.exists(logs_file) or not os.path.exists(dossiers_file):
        generate_synthetic_ueba_logs()
        analyze_ueba_stream()
        
    df = pd.read_csv(logs_file)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    
    with open(dossiers_file, "r", encoding="utf-8") as f:
        dossiers = json.load(f)
        
    return df, dossiers


df_logs, dossiers = load_security_data()

# Header Section
st.markdown('<div class="cyber-title">🛡️ SENTINEL // Autonomous DLP & Insider Threat Hub</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="cyber-subtitle">User & Entity Behavior Analytics (UEBA) • High-Volume Data Exfiltration Interceptor • Autonomous AI Forensic Auditor</div>',
    unsafe_allow_html=True
)

# Top Telemetry Metrics
total_events = len(df_logs)
total_users = df_logs["employee_id"].nunique()
critical_dossiers = [d for d in dossiers if d["max_risk_score"] >= 80]
total_exfil_gb = sum(d["total_exfiltrated_gb"] for d in dossiers)

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Identities Monitored</div>
        <div class="metric-num">{total_users}</div>
    </div>
    """, unsafe_allow_html=True)
with c2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Events Processed</div>
        <div class="metric-num">{total_events:,}</div>
    </div>
    """, unsafe_allow_html=True)
with c3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Critical Threat Dossiers</div>
        <div class="metric-num" style="color:#F87171;">{len(critical_dossiers)}</div>
    </div>
    """, unsafe_allow_html=True)
with c4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Data Exfiltration Flagged</div>
        <div class="metric-num" style="color:#38BDF8;">{total_exfil_gb:.1f} GB</div>
    </div>
    """, unsafe_allow_html=True)

st.write("")

# Sidebar Navigation & Controls
with st.sidebar:
    st.markdown("### ⚙️ Pipeline Control")
    if st.button("🔄 Reseed & Rerun Telemetry", use_container_width=True):
        with st.spinner("Regenerating activity stream and recalculating UEBA models..."):
            generate_synthetic_ueba_logs()
            analyze_ueba_stream()
            st.cache_data.clear()
            st.rerun()
            
    st.write("---")
    st.markdown("### 🎯 Investigation Filters")
    dept_filter = st.selectbox("Department", ["ALL"] + sorted(list(df_logs["department"].unique())))
    risk_filter = st.selectbox("Minimum Risk Level", ["ALL", "CRITICAL (>=80)", "HIGH (>=65)", "ELEVATED (>=40)"])
    
    st.write("---")
    st.markdown("### 🧠 AI Engine Status")
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if api_key.startswith("AIzaSy"):
        st.success("Cloud Gemini API: Online (gemini-2.5-flash)")
    else:
        st.info("Local Expert CISO Rules Engine: Active")

# Main Investigation Layout
tab_threats, tab_deep_dive, tab_stream = st.tabs([
    "🚨 Active Threat Dossiers",
    "🔬 Forensic Case Deep-Dive",
    "📊 Global Telemetry Explorer"
])

with tab_threats:
    st.subheader("Isolated High-Risk Identity Dossiers")
    st.markdown("Prioritized based on multi-factor behavioral anomalies (Volume, Off-Hours, Geo/Device, and Sensitive Actions).")
    
    for d in dossiers:
        badge_cls = "badge-critical" if d["max_risk_score"] >= 80 else "badge-high"
        risk_tag = "CRITICAL RISK" if d["max_risk_score"] >= 80 else "HIGH RISK"
        
        col_main, col_stats, col_btn = st.columns([3, 2, 1.5])
        with col_main:
            st.markdown(f"""
            <div style="font-size:1.15rem; font-weight:600; color:#F8FAFC;">
                {d['name']} <span style="font-size:0.85rem; color:#94A3B8;">({d['employee_id']})</span>
                <span class="{badge_cls}">{risk_tag} • {d['max_risk_score']}/100</span>
            </div>
            <div style="color:#94A3B8; font-size:0.85rem; margin-top:4px;">
                <strong>Role:</strong> {d['role']} | <strong>Dept:</strong> {d['department']}
            </div>
            <div style="color:#CBD5E1; font-size:0.9rem; margin-top:6px;">
                ⚡ <strong>Threat Vector:</strong> {d['threat_category']}
            </div>
            """, unsafe_allow_html=True)
            
        with col_stats:
            st.markdown(f"""
            <div style="font-size:0.85rem; color:#94A3B8; line-height:1.6;">
                📁 <strong>Exfiltrated:</strong> <span style="color:#F87171; font-weight:600;">{d['total_exfiltrated_gb']} GB</span><br>
                📈 <strong>Volume Surge:</strong> <span style="color:#38BDF8;">{d['anomaly_volume_multiplier']}x</span> normal baseline<br>
                🌐 <strong>Location:</strong> {d['primary_country']} ({d['primary_endpoint']})
            </div>
            """, unsafe_allow_html=True)
            
        with col_btn:
            if st.button(f"Inspect Case #{d['employee_id']}", key=f"btn_{d['employee_id']}", use_container_width=True):
                st.session_state["selected_employee"] = d["employee_id"]
                st.rerun()
                
        st.divider()

with tab_deep_dive:
    selected_id = st.session_state.get("selected_employee", dossiers[0]["employee_id"] if dossiers else None)
    
    if selected_id:
        target_dossier = next((d for d in dossiers if d["employee_id"] == selected_id), dossiers[0])
        
        st.subheader(f"Forensic Case File: {target_dossier['name']} ({target_dossier['employee_id']})")
        
        # Identity Summary Header
        info_c1, info_c2, info_c3 = st.columns(3)
        with info_c1:
            st.metric("Composite Risk Score", f"{target_dossier['max_risk_score']} / 100")
        with info_c2:
            st.metric("Total Exfiltrated Volume", f"{target_dossier['total_exfiltrated_gb']} GB")
        with info_c3:
            st.metric("Behavioral Surge Multiplier", f"{target_dossier['anomaly_volume_multiplier']}x Baseline")
            
        st.write("")
        
        # Interactive Visualizations
        emp_records = df_logs[df_logs["employee_id"] == selected_id].sort_values("timestamp")
        
        v_col1, v_col2 = st.columns([3, 2])
        
        with v_col1:
            # Transfer Volume Over Time
            fig_timeline = px.scatter(
                emp_records,
                x="timestamp",
                y="bytes_transferred",
                color="risk_level",
                size="bytes_transferred",
                hover_data=["action", "source_ip", "device"],
                color_discrete_map={"LOW": "#38BDF8", "ELEVATED": "#FACC15", "HIGH": "#FB923C", "CRITICAL": "#F87171"},
                title="Activity Timeline: Baseline vs. Anomalous Spikes",
                template="plotly_dark"
            )
            fig_timeline.update_layout(
                paper_bgcolor="#0F172A",
                plot_bgcolor="#0F172A",
                margin=dict(l=20, r=20, t=40, b=20),
                height=320
            )
            st.plotly_chart(fig_timeline, use_container_width=True)
            
        with v_col2:
            # Hour-of-day distribution
            fig_hours = px.histogram(
                emp_records,
                x="hour",
                color="risk_level",
                nbins=24,
                title="Access Hour Distribution (Off-Hours Deviation)",
                color_discrete_map={"LOW": "#38BDF8", "ELEVATED": "#FACC15", "HIGH": "#FB923C", "CRITICAL": "#F87171"},
                template="plotly_dark"
            )
            fig_hours.update_layout(
                paper_bgcolor="#0F172A",
                plot_bgcolor="#0F172A",
                margin=dict(l=20, r=20, t=40, b=20),
                height=320,
                xaxis=dict(tickmode="linear", tick0=0, dtick=4)
            )
            st.plotly_chart(fig_hours, use_container_width=True)
            
        # Forensic Evidence Trail Table
        st.markdown("#### 🔍 Chronological Forensic Evidence Trail")
        timeline_df = pd.DataFrame(target_dossier["evidence_timeline"])
        st.dataframe(timeline_df[["timestamp", "action", "data_size", "ip", "country", "device", "session", "risk_score"]], use_container_width=True)
        
        st.write("---")
        
        # AI Autonomous Briefing Action
        act_col1, act_col2 = st.columns([1, 1])
        with act_col1:
            if st.button("🤖 Generate Autonomous CISO & Compliance Briefing", type="primary", use_container_width=True):
                with st.spinner("AI Agent analyzing breach parameters, evaluating GDPR/SOC2 exposure, and creating runbook..."):
                    briefing = generate_forensic_audit_report(target_dossier)
                    st.session_state["current_briefing"] = briefing
                    
        with act_col2:
            if st.button("⚡ Execute Automated SOAR Containment Playbook", use_container_width=True):
                st.toast(f"Terminated active Okta sessions for {target_dossier['employee_id']}.", icon="🔒")
                st.toast(f"Deactivated AWS programmatic IAM access keys.", icon="☁️")
                st.toast(f"Sent endpoint isolation packet to CrowdStrike Falcon.", icon="🛡️")
                st.success(f"Quarantine executed successfully for {target_dossier['name']}. Legal hold initiated.")
                
        # Display Generated AI Briefing
        if "current_briefing" in st.session_state:
            st.markdown('<div class="briefing-box">', unsafe_allow_html=True)
            st.markdown(st.session_state["current_briefing"])
            st.markdown('</div>', unsafe_allow_html=True)
            
            st.download_button(
                label="📥 Download Formal Incident Audit File (.md)",
                data=st.session_state["current_briefing"],
                file_name=f"INCIDENT_AUDIT_{target_dossier['employee_id']}.md",
                mime="text/markdown"
            )
    else:
        st.info("No employee dossier selected. Return to the Dossiers tab and choose a case.")

with tab_stream:
    st.subheader("Global Security Telemetry Explorer")
    st.markdown("Search and filter across all enterprise authentication and data transfer records.")
    
    # Filter DataFrame
    view_df = df_logs.copy()
    if dept_filter != "ALL":
        view_df = view_df[view_df["department"] == dept_filter]
        
    if risk_filter.startswith("CRITICAL"):
        view_df = view_df[view_df["event_risk_score"] >= 80]
    elif risk_filter.startswith("HIGH"):
        view_df = view_df[view_df["event_risk_score"] >= 65]
    elif risk_filter.startswith("ELEVATED"):
        view_df = view_df[view_df["event_risk_score"] >= 40]
        
    st.dataframe(
        view_df[["timestamp", "employee_id", "name", "department", "action", "bytes_transferred", "source_ip", "country", "device", "event_risk_score", "risk_level"]].head(250),
        use_container_width=True
    )