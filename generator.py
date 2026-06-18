import random
import datetime

# Setup some basic ingredients for data simulation
actions = ["LOGIN_SUCCESS", "LOGIN_FAILED", "DATA_UPLOAD", "DATA_DOWNLOAD", "LOGOUT"]
ips = ["192.168.1.10", "10.0.0.5", "172.16.0.42", "192.168.1.50"]

print("Generating 10,000 lines of messy log data")

# This opens a text file and automatically writes 10,000 lines inside a loop
with open("raw_logs.txt", "w") as file:
    for i in range(10000):
        user_id = f"USER_{random.randint(100, 999)}"
        action = random.choice(actions)

        # 3% of the time, create a corrupt log with an "UNKNOWN" IP
        ip = "UNKNOWN" if random.random() < 0.03 else random.choice(ips)

        # 2% of the time, inject a massive or negative anomaly for NumPy to catch later
        if random.random() < 0.02:
            bytes_transferred = random.choice([-999, 8500000])
        else:
            bytes_transferred = random.randint(100, 5000)

        # Generate random recent timestamps
        random_minutes = random.randint(1, 20000)
        timestamp = datetime.datetime.now() - datetime.timedelta(minutes=random_minutes)
        timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")

        # Assemble the line and write it to the file
        log_line = f"{timestamp_str} | {user_id} | IP: {ip} | ACTION: {action} | BYTES_TRANSFERRED: {bytes_transferred}\n"
        file.write(log_line)
