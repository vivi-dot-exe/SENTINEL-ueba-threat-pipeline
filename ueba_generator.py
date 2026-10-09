"""
ueba_generator.py
Enterprise User & Entity Behavior Analytics (UEBA) Synthetic Log Generator.
Generates multi-day enterprise activity logs simulating normal workplace baselines
and realistic, high-impact Insider Threat / Data Loss Prevention (DLP) incidents.
"""

import random
import datetime
import pandas as pd

# 1. Enterprise User Profiles
EMPLOYEES = [
    {"id": "EMP_1042", "name": "Marcus Vance", "dept": "Sales", "role": "Senior Sales Director", "country": "United States", "device": "Corporate-MacBook-Pro"},
    {"id": "EMP_3081", "name": "Alexei Romanov", "dept": "External Contractor", "role": "Cloud DevOps Contractor", "country": "United States", "device": "Corporate-ThinkPad"},
    {"id": "EMP_2019", "name": "Priya Sharma", "dept": "Finance", "role": "Staff Financial Analyst", "country": "United States", "device": "Corporate-Dell-Latitude"},
    {"id": "EMP_1094", "name": "Jordan Reed", "dept": "Data Platform", "role": "Senior Data Engineer", "country": "United States", "device": "Corporate-MacBook-Pro"},
    {"id": "EMP_1011", "name": "Sarah Connor", "dept": "Engineering", "role": "Backend Lead", "country": "United States", "device": "Corporate-MacBook-Pro"},
    {"id": "EMP_1012", "name": "David Kim", "dept": "Engineering", "role": "Fullstack Engineer", "country": "United States", "device": "Corporate-MacBook-Pro"},
    {"id": "EMP_1013", "name": "Elena Rostova", "dept": "Product", "role": "VP Product Management", "country": "United States", "device": "Corporate-MacBook-Pro"},
    {"id": "EMP_1014", "name": "Michael Scott", "dept": "Sales", "role": "Regional Sales Manager", "country": "United States", "device": "Corporate-ThinkPad"},
    {"id": "EMP_1015", "name": "Angela Martin", "dept": "Finance", "role": "Senior Accountant", "country": "United States", "device": "Corporate-Dell-Latitude"},
    {"id": "EMP_1016", "name": "Toby Flenderson", "dept": "Human Resources", "role": "HR Director", "country": "United States", "device": "Corporate-ThinkPad"},
    {"id": "EMP_1017", "name": "Kevin Malone", "dept": "Finance", "role": "Financial Clerk", "country": "United States", "device": "Corporate-Dell-Latitude"},
    {"id": "EMP_1018", "name": "Oscar Martinez", "dept": "Finance", "role": "Comptroller", "country": "United States", "device": "Corporate-Dell-Latitude"},
    {"id": "EMP_1019", "name": "Jim Halpert", "dept": "Sales", "role": "Account Executive", "country": "United States", "device": "Corporate-MacBook-Pro"},
    {"id": "EMP_1020", "name": "Pam Beesly", "dept": "Operations", "role": "Office Administrator", "country": "United States", "device": "Corporate-ThinkPad"},
    {"id": "EMP_1021", "name": "Dwight Schrute", "dept": "Sales", "role": "Assistant Regional Manager", "country": "United States", "device": "Corporate-ThinkPad"},
]

NORMAL_ACTIONS = [
    "NORMAL_LOGIN", "FILE_READ", "CODE_COMMIT", "PULL_REQUEST_REVIEW", 
    "EMAIL_EXCHANGE", "SLACK_MESSAGE", "JIRA_TICKET_UPDATE", "INTERNAL_WIKI_READ",
    "CUSTOMER_PORTAL_VIEW", "ROUTINE_REPORT_EXPORT"
]

NORMAL_IPS = [
    "10.0.1.45", "10.0.2.110", "192.168.10.15", "172.16.4.88",
    "64.233.160.1", "72.14.207.99", "198.51.100.22"
]


def generate_synthetic_ueba_logs(num_normal_records: int = 12000, output_path: str = "user_activity_logs.csv"):
    print(f"[*] Generating {num_normal_records:,} baseline enterprise user activity logs...")
    records = []
    
    # 1. Generate 14-day normal baseline activities
    now = datetime.datetime.now()
    start_date = now - datetime.timedelta(days=14)
    
    for _ in range(num_normal_records):
        emp = random.choice(EMPLOYEES)
        
        # 85% of normal activity occurs during working hours (08:30 to 18:30)
        if random.random() < 0.85:
            hour = random.randint(8, 18)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
        else:
            # 15% casual off-hours (e.g. evening Slack or quick ticket check)
            hour = random.choice([7, 19, 20, 21, 22])
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
        random_day = random.randint(0, 13)
        event_time = (start_date + datetime.timedelta(days=random_day)).replace(
            hour=hour, minute=minute, second=second
        )
        
        action = random.choice(NORMAL_ACTIONS)
        # Normal files transferred: 1 KB to 25 MB (in bytes)
        bytes_transferred = random.randint(1024, 25 * 1024 * 1024)
        ip = random.choice(NORMAL_IPS)
        
        records.append({
            "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": emp["id"],
            "name": emp["name"],
            "department": emp["dept"],
            "role": emp["role"],
            "action": action,
            "bytes_transferred": bytes_transferred,
            "source_ip": ip,
            "country": emp["country"],
            "device": emp["device"],
            "session_type": "Corporate_SSO",
            "is_known_threat_sim": 0
        })

    # 2. Inject Curated High-Impact Insider Threat Scenarios (Recent: last 48-72 hours)
    print("[!] Injecting realistic Insider Threat / DLP exfiltration scenarios...")

    # --- Scenario A: Marcus Vance (Sales Director - Pre-Resignation Customer List Exfiltration) ---
    exfil_time_a = now - datetime.timedelta(hours=14)
    records.extend([
        {
            "timestamp": (exfil_time_a - datetime.timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": "EMP_1042",
            "name": "Marcus Vance",
            "department": "Sales",
            "role": "Senior Sales Director",
            "action": "OFF_HOURS_LOGIN",
            "bytes_transferred": 1048576,
            "source_ip": "136.25.104.99",
            "country": "United States",
            "device": "Personal-MacBook-Air",
            "session_type": "Direct_Browser",
            "is_known_threat_sim": 1
        },
        {
            "timestamp": (exfil_time_a - datetime.timedelta(minutes=25)).strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": "EMP_1042",
            "name": "Marcus Vance",
            "department": "Sales",
            "role": "Senior Sales Director",
            "action": "BULK_CUSTOMER_DB_EXPORT",
            "bytes_transferred": 3840000000,  # 3.84 GB
            "source_ip": "136.25.104.99",
            "country": "United States",
            "device": "Personal-MacBook-Air",
            "session_type": "Direct_Browser",
            "is_known_threat_sim": 1
        },
        {
            "timestamp": exfil_time_a.strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": "EMP_1042",
            "name": "Marcus Vance",
            "department": "Sales",
            "role": "Senior Sales Director",
            "action": "PERSONAL_CLOUD_STORAGE_UPLOAD",
            "bytes_transferred": 4120000000,  # 4.12 GB (Dropbox / GDrive upload)
            "source_ip": "136.25.104.99",
            "country": "United States",
            "device": "Personal-MacBook-Air",
            "session_type": "Direct_Browser",
            "is_known_threat_sim": 1
        }
    ])

    # --- Scenario B: Alexei Romanov (Compromised / Rogue External Contractor) ---
    exfil_time_b = now - datetime.timedelta(hours=28)
    records.extend([
        {
            "timestamp": (exfil_time_b - datetime.timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": "EMP_3081",
            "name": "Alexei Romanov",
            "department": "External Contractor",
            "role": "Cloud DevOps Contractor",
            "action": "TOR_NODE_LOGIN",
            "bytes_transferred": 2500000,
            "source_ip": "185.220.101.4",  # Known Tor exit node / Foreign IP
            "country": "Romania / Proxy",
            "device": "Unknown-Linux-Daemon",
            "session_type": "SSH_Direct",
            "is_known_threat_sim": 1
        },
        {
            "timestamp": (exfil_time_b - datetime.timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": "EMP_3081",
            "name": "Alexei Romanov",
            "department": "External Contractor",
            "role": "Cloud DevOps Contractor",
            "action": "PRIVILEGED_IAM_ROLE_ATTACH",
            "bytes_transferred": 500000,
            "source_ip": "185.220.101.4",
            "country": "Romania / Proxy",
            "device": "Unknown-Linux-Daemon",
            "session_type": "AWS_CLI",
            "is_known_threat_sim": 1
        },
        {
            "timestamp": exfil_time_b.strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": "EMP_3081",
            "name": "Alexei Romanov",
            "department": "External Contractor",
            "role": "Cloud DevOps Contractor",
            "action": "MASS_PROPRIETARY_REPO_CLONE",
            "bytes_transferred": 9850000000,  # 9.85 GB (Entire core codebase)
            "source_ip": "185.220.101.4",
            "country": "Romania / Proxy",
            "device": "Unknown-Linux-Daemon",
            "session_type": "Git_Direct",
            "is_known_threat_sim": 1
        }
    ])

    # --- Scenario C: Jordan Reed (Data Engineer - Massive Healthcare PII Exfiltration) ---
    exfil_time_c = now - datetime.timedelta(hours=6)
    records.extend([
        {
            "timestamp": (exfil_time_c - datetime.timedelta(minutes=20)).strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": "EMP_1094",
            "name": "Jordan Reed",
            "department": "Data Platform",
            "role": "Senior Data Engineer",
            "action": "OFF_HOURS_SQL_WAREHOUSE_DUMP",
            "bytes_transferred": 6200000000,  # 6.2 GB
            "source_ip": "198.51.100.89",
            "country": "United States",
            "device": "Corporate-MacBook-Pro",
            "session_type": "Snowflake_Direct",
            "is_known_threat_sim": 1
        },
        {
            "timestamp": exfil_time_c.strftime("%Y-%m-%d %H:%M:%S"),
            "employee_id": "EMP_1094",
            "name": "Jordan Reed",
            "department": "Data Platform",
            "role": "Senior Data Engineer",
            "action": "UNENCRYPTED_S3_BUCKET_SYNC",
            "bytes_transferred": 6350000000,  # 6.35 GB
            "source_ip": "198.51.100.89",
            "country": "United States",
            "device": "Corporate-MacBook-Pro",
            "session_type": "AWS_CLI",
            "is_known_threat_sim": 1
        }
    ])

    # Convert to DataFrame, sort chronologically, and save
    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values(by="timestamp", ascending=True).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    
    print(f"[+] Successfully generated and wrote {len(df):,} enterprise activity logs to '{output_path}'.")
    return df


if __name__ == "__main__":
    generate_synthetic_ueba_logs()
