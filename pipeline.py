import pandas as pd
import numpy as np

print("Starting the Cloud Data Pipeline...")

# Step 1: Load the raw messy text file using ' | ' as the separator
try:
    df = pd.read_csv('raw_logs.txt', sep=r' \| ', engine='python', header=None)
    df.columns = ['Timestamp', 'User_ID', 'IP_Raw', 'Action_Raw', 'Bytes_Raw']
    print("✅ Successfully loaded 10,000 raw log lines.")
except FileNotFoundError:
    print("❌ Error: 'raw_logs.txt' not found! Run generator.py first.")
    exit()

# Step 2: Clean the text prefixes using Pandas string operations
print("Cleaning data fields...")
df['IP'] = df['IP_Raw'].str.replace('IP: ', '', regex=False)
df['Action'] = df['Action_Raw'].str.replace('ACTION: ', '', regex=False)
df['Bytes'] = df['Bytes_Raw'].str.replace('BYTES_TRANSFERRED: ', '', regex=False).astype(int)

# Drop the messy old raw columns since we have clean versions now
df = df.drop(columns=['IP_Raw', 'Action_Raw', 'Bytes_Raw'])

# Step 3: Fix Data Anomalies (Handling the intentional corruptions)
# If bytes transferred are negative (corrupt data), clip them to 0
corrupt_bytes_count = (df['Bytes'] < 0).sum()
df.loc[df['Bytes'] < 0, 'Bytes'] = 0

# Step 4: NumPy Statistical Anomaly Detection (Finding the Data Exfiltration)
print("Running statistical anomaly detection...")
mean_bytes = np.mean(df['Bytes'])
std_bytes = np.std(df['Bytes'])

# Define a high threshold: 3 standard deviations above the average volume
anomaly_threshold = mean_bytes + (3 * std_bytes)

# Use NumPy's rapid conditional matching to flag anomalies
# Flag as 1 if bytes exceed the threshold OR if the IP address is masked as "UNKNOWN"
df['IS_ANOMALY'] = np.where((df['Bytes'] > anomaly_threshold) | (df['IP'] == 'UNKNOWN'), 1, 0)

# Step 5: Generate the Analytics Reports
total_anomalies = df['IS_ANOMALY'].sum()
print(f"\n📊 --- PIPELINE INSIGHTS REPORT ---")
print(f"🔹 Total Logs Processed: {len(df)}")
print(f"🔹 Negative Data Corruptions Repaired: {corrupt_bytes_count}")
print(f"🔹 Normal Data Transmission Avg: {int(mean_bytes)} Bytes")
print(f"🔹 Flagged Security/System Anomalies: {total_anomalies}")

# Export the results to your directory
df.to_csv('cleaned_logs.csv', index=False)
df[df['IS_ANOMALY'] == 1].to_csv('security_alerts.csv', index=False)

print("\n💾 Reports saved successfully: 'cleaned_logs.csv' and 'security_alerts.csv'.")
print("🏁 Pipeline execution complete.")