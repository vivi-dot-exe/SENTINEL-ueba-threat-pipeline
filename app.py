import os
import pandas as pd
import streamlit as st
from google import genai
from dotenv import load_dotenv

# 1. Setup secure configuration & page styling
load_dotenv()
st.set_page_config(page_title="AI Cloud Security Hub", layout="wide")

st.title("🛡️ Enterprise AI Cloud Log Dashboard")
st.markdown("Real-time data clearing, mathematical anomaly verification, and autonomous AI threat reporting.")
st.write("---")

# 2. Extract Data from your existing Data Engineering pipeline
try:
    df_clean = pd.read_csv('cleaned_logs.csv')
    df_alerts = pd.read_csv('security_alerts.csv')
except FileNotFoundError:
    st.error("❌ Missing project data files! Run generator.py and pipeline.py first to create the data.")
    st.stop()

# 3. UI Layer: Metric Highlighters
total_logs = len(df_clean)
total_anomalies = len(df_alerts)
avg_bytes = int(df_clean['Bytes'].mean())

col1, col2, col3 = st.columns(3)
with col1:
    st.metric(label="Total Logs Streamed", value=f"{total_logs:,}")
with col2:
    st.metric(label="Flagged System Alerts", value=total_anomalies, delta="Action Required", delta_color="inverse")
with col3:
    st.metric(label="Average Traffic Volume", value=f"{avg_bytes} Bytes")

st.write("---")

# 4. UI Layer: Data Grid Preview
st.subheader("🚨 High-Priority Security Logs (Isolated via Vector Math)")
st.dataframe(df_alerts, use_container_width=True)

st.write("---")

# 5. UI Layer: AI Orchestration Integration
st.subheader("🤖 Autonomous Incident Assessment")
st.write("Click below to pass the critical network breach parameters to the live Cloud LLM framework.")

if st.button("Generate Executive AI Security Briefing", type="primary"):
    # Target critical data exfiltration vectors
    critical_hacks = df_alerts[df_alerts['Bytes'] > 1000000]

    if critical_hacks.empty:
        st.success("No high-volume data exfiltrations detected inside today's stream matrix.")
    else:
        # Format the context bundle
        incident_report_data = ""
        for index, row in critical_hacks.head(3).iterrows():
            incident_report_data += f"- Time: {row['Timestamp']} | User: {row['User_ID']} | IP: {row['IP']} | Action: {row['Action']} | Data Leaked: {row['Bytes']} bytes\n"

        ai_system_instruction = """
        ROLE: You are an elite enterprise Cybersecurity AI Agent.
        TASK: Analyze the raw server alerts provided below and write a 3-sentence summary for the engineering team.
        FORMAT:
        - Sentence 1: Identify the primary malicious activity and who did it.
        - Sentence 2: Explain the potential business damage (e.g., data exfiltration).
        - Sentence 3: Provide an immediate mitigation step (e.g., block the IP, revoke user tokens).
        """

        full_llm_prompt = f"{ai_system_instruction}\n\nRAW INCIDENT DATA:\n{incident_report_data}"

        # Connect to key structure safely
        API_KEY = os.environ.get("GEMINI_API_KEY")
        if not API_KEY:
            st.error("API Key missing! Ensure GEMINI_API_KEY is configured inside your local .env file.")
        else:
            with st.spinner("Streaming live security analysis directly from cloud engine..."):
                try:
                    client = genai.Client(api_key=API_KEY)
                    response = client.models.generate_content(
                        model="gemini-2.5-flash",
                        contents=full_llm_prompt
                    )
                    # Display the AI's output in a clean UI callout card
                    st.info(response.text)
                except Exception as e:
                    st.error(f"Cloud Architecture Connection Timeout: {e}")