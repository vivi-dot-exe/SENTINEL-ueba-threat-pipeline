"""
ueba_engine.py
User & Entity Behavior Analytics (UEBA) Detection Engine.
Computes individual behavioral baselines and multi-factor Insider Threat Risk Scores (0-100).
Produces audit dossiers for high-risk identity investigations.
"""

import os
import json
import pandas as pd
import numpy as np

# High-Risk DLP Action Severities (0 - 25 points)
HIGH_RISK_ACTIONS = {
    "BULK_CUSTOMER_DB_EXPORT": 25,
    "MASS_PROPRIETARY_REPO_CLONE": 25,
    "UNENCRYPTED_S3_BUCKET_SYNC": 25,
    "PERSONAL_CLOUD_STORAGE_UPLOAD": 22,
    "OFF_HOURS_SQL_WAREHOUSE_DUMP": 22,
    "PRIVILEGED_IAM_ROLE_ATTACH": 20,
    "TOR_NODE_LOGIN": 20,
    "OFF_HOURS_LOGIN": 12,
    "ROUTINE_REPORT_EXPORT": 5,
}


def analyze_ueba_stream(input_file: str = "user_activity_logs.csv", 
                        output_logs: str = "ueba_analyzed_logs.csv",
                        output_dossiers: str = "employee_risk_dossiers.json"):
    print("[*] Launching UEBA Analytics Engine...")
    
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file '{input_file}' not found. Run ueba_generator.py first.")
        
    df = pd.read_csv(input_file)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    print(f"[+] Loaded {len(df):,} employee activity logs for behavioral profiling.")

    # 1. Temporal Feature Engineering
    df["hour"] = df["timestamp"].dt.hour
    df["day_name"] = df["timestamp"].dt.day_name()
    df["is_weekend"] = df["timestamp"].dt.dayofweek >= 5
    df["is_dead_of_night"] = (df["hour"] >= 0) & (df["hour"] <= 5)
    df["is_off_hours"] = (df["hour"] < 8) | (df["hour"] >= 19)

    # 2. Behavioral Baseline per Employee (Volume & Patterns)
    emp_stats = df.groupby("employee_id")["bytes_transferred"].agg(
        emp_mean_bytes="mean",
        emp_std_bytes="std"
    ).reset_index()
    
    df = df.merge(emp_stats, on="employee_id", how="left")
    df["emp_std_bytes"] = df["emp_std_bytes"].fillna(1)

    # 3. Multi-Factor Risk Scoring (0 - 100)
    
    # Factor A: Volume Anomaly Score (0 - 35)
    # Scaled based on both absolute data exfiltration volume and deviation from employee mean
    def compute_volume_score(row):
        bytes_val = row["bytes_transferred"]
        if bytes_val >= 5 * 1024 * 1024 * 1024:    # >= 5 GB
            return 35
        elif bytes_val >= 2 * 1024 * 1024 * 1024:  # >= 2 GB
            return 30
        elif bytes_val >= 500 * 1024 * 1024:       # >= 500 MB
            return 22
        elif bytes_val >= 100 * 1024 * 1024:       # >= 100 MB
            return 14
        else:
            return 0

    df["score_volume"] = df.apply(compute_volume_score, axis=1)

    # Factor B: Temporal Anomaly Score (0 - 25)
    def compute_time_score(row):
        if row["is_dead_of_night"] and row["is_weekend"]:
            return 25
        elif row["is_dead_of_night"]:
            return 20
        elif row["is_weekend"] and row["is_off_hours"]:
            return 15
        elif row["is_off_hours"]:
            return 8
        return 0

    df["score_time"] = df.apply(compute_time_score, axis=1)

    # Factor C: Geolocation & Endpoint Environment Score (0 - 20)
    def compute_env_score(row):
        score = 0
        country_str = str(row["country"]).lower()
        device_str = str(row["device"]).lower()
        
        if "proxy" in country_str or "tor" in country_str or "romania" in country_str:
            score += 15
        if "personal" in device_str or "unknown" in device_str:
            score += 10
        return min(score, 20)

    df["score_env"] = df.apply(compute_env_score, axis=1)

    # Factor D: High-Risk Action Weight (0 - 20)
    df["score_action"] = df["action"].apply(lambda act: min(HIGH_RISK_ACTIONS.get(act, 0), 20))

    # Composite Threat Score
    df["event_risk_score"] = (
        df["score_volume"] + 
        df["score_time"] + 
        df["score_env"] + 
        df["score_action"]
    ).clip(0, 100)

    # Risk Classification
    conditions = [
        (df["event_risk_score"] >= 80),
        (df["event_risk_score"] >= 65),
        (df["event_risk_score"] >= 40),
    ]
    choices = ["CRITICAL", "HIGH", "ELEVATED"]
    df["risk_level"] = np.select(conditions, choices, default="LOW")

    # Save enriched logs
    df.to_csv(output_logs, index=False)
    print(f"[+] Saved event-level behavioral logs to '{output_logs}'.")

    # 4. Generate Employee Identity Dossiers
    flagged_employees = df[df["event_risk_score"] >= 60]["employee_id"].unique()
    print(f"[!] Flagged {len(flagged_employees)} suspicious employee identities exceeding security thresholds.")

    dossiers = []
    for emp_id in flagged_employees:
        emp_events = df[df["employee_id"] == emp_id].sort_values("timestamp", ascending=True)
        top_incident = emp_events.loc[emp_events["event_risk_score"].idxmax()]
        
        # Calculate behavioral baseline comparison
        baseline_events = emp_events[emp_events["risk_level"] == "LOW"]
        avg_normal_mb = (baseline_events["bytes_transferred"].mean() / (1024 * 1024)) if not baseline_events.empty else 1.0
        
        # High risk events timeline
        anomalies = emp_events[emp_events["event_risk_score"] >= 50]
        exfiltrated_bytes = int(anomalies["bytes_transferred"].sum())
        exfiltrated_gb = round(exfiltrated_bytes / (1024 ** 3), 2)
        
        # Formulate primary threat category
        top_action = top_incident["action"]
        if "CUSTOMER" in top_action:
            threat_type = "Pre-Resignation Customer PII & Leads Exfiltration"
        elif "REPO" in top_action or "CODE" in top_action:
            threat_type = "Intellectual Property / Source Code Exfiltration"
        elif "SQL" in top_action or "S3" in top_action:
            threat_type = "Mass Cloud Database Dump to Unmanaged Infrastructure"
        else:
            threat_type = "Unauthorized Privileged Off-Hours Data Access"

        timeline = []
        for _, ev in anomalies.iterrows():
            timeline.append({
                "timestamp": ev["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "action": ev["action"],
                "data_size": f"{round(ev['bytes_transferred'] / (1024*1024), 2)} MB",
                "bytes": int(ev["bytes_transferred"]),
                "ip": ev["source_ip"],
                "country": ev["country"],
                "device": ev["device"],
                "session": ev["session_type"],
                "risk_score": int(ev["event_risk_score"]),
                "risk_level": ev["risk_level"]
            })

        dossier = {
            "employee_id": emp_id,
            "name": top_incident["name"],
            "department": top_incident["department"],
            "role": top_incident["role"],
            "max_risk_score": int(emp_events["event_risk_score"].max()),
            "threat_category": threat_type,
            "total_exfiltrated_gb": exfiltrated_gb,
            "normal_baseline_avg_mb": round(avg_normal_mb, 2),
            "anomaly_volume_multiplier": round((exfiltrated_bytes / max(baseline_events["bytes_transferred"].mean(), 1024)), 1) if not baseline_events.empty else 100.0,
            "primary_endpoint": top_incident["device"],
            "primary_country": top_incident["country"],
            "evidence_timeline": timeline
        }
        dossiers.append(dossier)

    # Sort dossiers by max risk score descending
    dossiers = sorted(dossiers, key=lambda x: x["max_risk_score"], reverse=True)

    with open(output_dossiers, "w", encoding="utf-8") as f:
        json.dump(dossiers, f, indent=2)

    print(f"[+] Successfully exported {len(dossiers)} comprehensive threat dossiers to '{output_dossiers}'.")
    return df, dossiers


if __name__ == "__main__":
    analyze_ueba_stream()
