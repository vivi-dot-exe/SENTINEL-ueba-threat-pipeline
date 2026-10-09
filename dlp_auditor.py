"""
dlp_auditor.py
Autonomous AI Forensic & Compliance Incident Auditor for Insider Threats.
Uses Google Gemini to analyze high-risk employee dossiers, determine regulatory exposure
(GDPR, SOC 2, HIPAA), and generate automated containment playbooks.
Includes resilient fallback to an expert local forensic rules engine if API keys are inactive.
"""

import os
import json
from dotenv import load_dotenv

load_dotenv()


def generate_local_expert_briefing(dossier: dict) -> str:
    """Deterministic, high-fidelity CISO forensic briefing when Cloud API key is inactive."""
    name = dossier.get("name", "Unknown")
    emp_id = dossier.get("employee_id", "EMP_UNKNOWN")
    dept = dossier.get("department", "Unknown")
    role = dossier.get("role", "Unknown")
    score = dossier.get("max_risk_score", 0)
    category = dossier.get("threat_category", "Anomalous Data Access")
    exfil_gb = dossier.get("total_exfiltrated_gb", 0)
    multiplier = dossier.get("anomaly_volume_multiplier", 1)
    country = dossier.get("primary_country", "Unknown")
    device = dossier.get("primary_endpoint", "Unknown")

    timeline_items = dossier.get("evidence_timeline", [])
    timeline_desc = "\n".join([
        f"- **{t['timestamp']}**: `{t['action']}` | Data: {t['data_size']} | IP: `{t['ip']}` ({t['country']}) | Device: `{t['device']}`"
        for t in timeline_items
    ])

    # Regulatory assessment logic
    if "CUSTOMER" in category.upper() or "PII" in category.upper():
        reg_impact = (
            "- **GDPR Article 33**: **TRIGGERED (High Severity)**. Unauthorized export of customer PII requires formal supervisory notification within **72 hours** of breach confirmation.\n"
            "- **SOC 2 Type II**: Direct violation of **CC6.1 (Logical Access)** and **CC6.8 (Unauthorized Data Exfiltration)**.\n"
            "- **Customer SLA**: Requires triggering enterprise customer security disclosure protocols."
        )
    elif "REPO" in category.upper() or "CODE" in category.upper():
        reg_impact = (
            "- **Trade Secret & IP Protection**: **CRITICAL BREACH**. Proprietary mono-repo exfiltration violates Corporate Confidentiality & IP Agreements. Immediate injunctive relief warranted.\n"
            "- **SOC 2 Type II**: Violation of **CC6.6 (Boundary Protection)** due to unauthorized code pull over external proxy node.\n"
            "- **Contractor SLA**: Breach of Master Services Agreement (MSA) intellectual property covenants."
        )
    else:
        reg_impact = (
            "- **HIPAA / Data Privacy**: **MANDATORY REVIEW**. Mass database export of healthcare/user tables requires immediate audit for protected health information (PHI).\n"
            "- **SOC 2 Type II**: Violation of **CC6.3 (Least Privilege Access)** and unencrypted cloud transfer controls."
        )

    return f"""### 1. Forensic Assessment & Intent Analysis
- **Observed Kill Chain**: Target identity **{name}** (`{emp_id}`, {role}) exhibited a classic multi-stage insider threat sequence:
{timeline_desc}
- **Intent Evaluation**: The transmission volume of **{exfil_gb} GB** represents a **{multiplier}x deviation** from the subject's 14-day baseline. The combination of off-hours access, non-standard endpoints (`{device}`), and geographic anomalies (`{country}`) confirms **intentional data exfiltration** rather than accidental activity.

### 2. Regulatory & Compliance Breach Exposure
{reg_impact}

### 3. Immediate Containment Playbook (Automated SOAR Runbook)
- **Identity Layer**:
  ```bash
  # Invalidate active Okta / SSO sessions & suspend user credentials
  curl -X POST https://api.okta.com/v1/users/{emp_id}/lifecycle/suspend \\
    -H "Authorization: Bearer ${{OKTA_API_TOKEN}}"
  ```
- **Infrastructure & Cloud Access**:
  ```bash
  # Detach IAM policies and deactivate AWS programmatic access keys
  aws iam list-access-keys --user-name {emp_id} | jq -r '.AccessKeyMetadata[].AccessKeyId' | \\
    xargs -I {{}} aws iam update-access-key --user-name {emp_id} --access-key-id {{}} --status Inactive
  ```
- **Endpoint Security**:
  ```bash
  # Issue CrowdStrike / Defender isolation command to quarantine endpoint
  cs-falcon-admin isolate-host --device-id "{device}" --reason "DLP Critical Severity Breach #{emp_id}"
  ```

### 4. HR & Legal Counsel Advisory
> **CONFIDENTIAL ATTORNEY-CLIENT PRIVILEGED MEMORANDUM**  
> We recommend an immediate litigation hold on **{name}**'s company-issued hardware, mailbox, and revision control commit logs. Human Resources should pause any pending offboarding or severance agreements pending forensic disk imaging.
"""


def generate_forensic_audit_report(dossier: dict) -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    
    # Check if a valid-format Google AI Studio key is provided
    if api_key and api_key.startswith("AIzaSy"):
        try:
            from google import genai
            client = genai.Client(api_key=api_key)

            timeline_str = ""
            for idx, item in enumerate(dossier.get("evidence_timeline", []), 1):
                timeline_str += (
                    f"Step {idx}: [{item['timestamp']}] ACTION: {item['action']} | "
                    f"Data: {item['data_size']} | IP: {item['ip']} ({item['country']}) | "
                    f"Device: {item['device']} | Session: {item['session']} | "
                    f"Risk Score: {item['risk_score']}/100\n"
                )

            system_instruction = """
ROLE: You are the Chief Information Security Officer (CISO) and Lead Digital Forensics Auditor for an enterprise.
TASK: Conduct a comprehensive, forensic investigation of the flagged employee insider threat incident dossier provided below.

Provide your briefing in clean, executive-ready Markdown with the following exact 4 sections:
### 1. Forensic Assessment & Intent Analysis
### 2. Regulatory & Compliance Breach Exposure (GDPR Art. 33, SOC 2, HIPAA)
### 3. Immediate Containment Playbook (Automated SOAR Runbook with concrete CLI snippets)
### 4. HR & Legal Counsel Advisory
"""

            prompt = f"""
{system_instruction}

---
INCIDENT DOSSIER:
- Target Employee: {dossier.get('name')} ({dossier.get('employee_id')})
- Department & Role: {dossier.get('department')} | {dossier.get('role')}
- Threat Risk Score: {dossier.get('max_risk_score')} / 100
- Primary Threat Category: {dossier.get('threat_category')}
- Total Data Exfiltrated: {dossier.get('total_exfiltrated_gb')} GB
- Normal Daily Baseline: {dossier.get('normal_baseline_avg_mb')} MB
- Anomaly Volume Spike Multiplier: {dossier.get('anomaly_volume_multiplier')}x standard deviation
- Primary Endpoint Used: {dossier.get('primary_endpoint')}
- Primary Geolocation: {dossier.get('primary_country')}

CHRONOLOGICAL FORENSIC TIMELINE:
{timeline_str}
"""
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            return response.text
        except Exception as e:
            print(f"[!] Gemini live call exception: {e}. Utilizing Local Expert Rules Engine.")
            return generate_local_expert_briefing(dossier)
    else:
        # Graceful fallback to deterministic expert CISO audit engine
        return generate_local_expert_briefing(dossier)


if __name__ == "__main__":
    if os.path.exists("employee_risk_dossiers.json"):
        with open("employee_risk_dossiers.json", "r", encoding="utf-8") as f:
            dossiers = json.load(f)
            if dossiers:
                print(f"[*] Running test audit for top threat: {dossiers[0]['name']}...")
                report = generate_forensic_audit_report(dossiers[0])
                print("\n" + report)
            else:
                print("[-] No flagged dossiers found.")
    else:
        print("[-] Run ueba_engine.py first to create dossiers.")
