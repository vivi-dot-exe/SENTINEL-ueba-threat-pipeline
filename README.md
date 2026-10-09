# 🛡️ SENTINEL // Autonomous DLP & Insider Threat Intelligence Platform

> **An Enterprise User & Entity Behavior Analytics (UEBA) and Autonomous AI Forensic Auditor built with Pandas, NumPy, Plotly, Streamlit, and Google Gemini.**

---

## 📌 Executive Summary

Modern cybersecurity threats originate as frequently from **compromised contractor credentials, malicious insiders, and pre-resignation data exfiltration** as from external perimeter attacks. Traditional Data Loss Prevention (DLP) tools trigger thousands of un-contextualized alerts, resulting in severe analyst alert fatigue.

**SENTINEL** solves this challenge by implementing an end-to-end autonomous pipeline:
1. **Behavioral Profiling (UEBA)**: Automatically baselines normal daily download volumes, working hours, and network endpoints across enterprise identities.
2. **Multi-Factor Risk Scoring Engine**: Calculates composite threat scores (0–100) based on mathematical volume surges, dead-of-night access, proxy/Tor geolocations, and sensitive DLP actions (e.g., bulk database exports, proprietary repository clones).
3. **Autonomous AI Forensic Auditor (Google Gemini)**: Analyzes isolated incident dossiers and generates audit-ready compliance briefings evaluating **GDPR Article 33**, **SOC 2 Type II**, and **HIPAA** breach exposure alongside one-click automated containment runbooks.

---

## 🏗️ Architecture & Pipeline Flow

```
   [Enterprise User Activity Stream] (12,000+ Multi-Day Telemetry Logs)
                   │
                   ▼
       [ueba_generator.py] (Simulates Normal Baselines + Real Insider Threat Scenarios)
                   │
                   ▼
         [ueba_engine.py]  (User & Entity Behavior Analytics Engine)
         ├── 1. Volume Anomaly Scoring (Z-score & Deviation Multipliers)
         ├── 2. Temporal Anomaly Scoring (Dead-of-Night / Weekend Access)
         ├── 3. Geolocation & Device Scoring (Tor / Proxies / Personal Hardware)
         └── 4. Sensitive DLP Action Matrix (DB Dumps, Repo Clones, S3 Syncs)
                   │
                   ▼
     [Flagged Incident Dossiers] (Composite Risk Score >= 60)
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
  [dlp_auditor.py]       [app.py]
  (Gemini CISO Agent)    (Interactive Web Dashboard)
  - Intent Analysis      - Top Telemetry KPIs
  - GDPR/SOC2 Impact     - Plotly Anomaly Scatter & Hour Distribution
  - Automated Runbooks   - One-Click SOAR Quarantine & Containment
```

---

## ⚡ Core Features

- **Multi-Factor Composite Risk Scoring (0–100)**: Evaluates behavioral variance instead of static signatures.
- **Interactive Deep Forensic Dossiers**: Inspect any flagged employee's normal baseline vs. current anomalous spike.
- **Plotly Dynamic Visualizations**: Temporal scatter plots and 24-hour access distributions showing off-hours deviations.
- **Audit-Ready Compliance Briefings**: Evaluates GDPR 72-hour notification triggers and SOC 2 Trust Services Criteria violations.
- **Simulated SOAR Containment Playbooks**: One-click actions to terminate Okta SSO sessions, invalidate AWS programmatic IAM keys, and quarantine endpoints via CrowdStrike/EDR.

---

## 🚀 Quickstart Guide

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/vivi-dot-exe/i-security-log-pipeline_project1.git
cd i-security-log-pipeline_project1
pip install -r requirements.txt
```

### 2. Configure Environment (Optional for Cloud Gemini)
Create a `.env` file in the project root:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```
*(Note: If no API key is provided, the platform automatically utilizes its built-in local expert forensic rules engine.)*

### 3. Generate Telemetry & Launch the Sentinel Dashboard
```bash
# Generate synthetic enterprise logs & run UEBA analysis
python ueba_generator.py
python ueba_engine.py

# Launch the interactive web dashboard
streamlit run app.py
```
Open **[http://localhost:8501](http://localhost:8501)** in your web browser.

---

## 📜 Regulatory Standards Addressed
- **GDPR Article 33**: Automatic evaluation of 72-hour supervisory authority breach notifications.
- **SOC 2 Type II**: CC6.1 (Logical Access Controls) & CC6.8 (Unauthorized Exfiltration Prevention).
- **HIPAA Privacy & Security Rules**: Detection of unauthorized electronic Protected Health Information (ePHI) queries.
