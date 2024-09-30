import os
import time
import pandas as pd
import matplotlib.pyplot as plt

# Path to Snort alert log (adjust to your Snort installation path)
SNORT_ALERT_LOG = "C:\\Snort\\log\\alert"

# Function to parse Snort alert log
def parse_snort_log(file_path):
    alerts = []
    with open(file_path, "r") as f:
        for line in f:
            if "Priority" in line:  # Capture lines with priority (alerts)
                timestamp = line.split("[**]")[0].strip()  # Extract timestamp
                alert_msg = line.split("]")[2].split("{")[0].strip()  # Extract alert message
                alerts.append([timestamp, alert_msg])
    return pd.DataFrame(alerts, columns=["Timestamp", "Alert"])

# Function to visualize the alerts
def visualize_alerts(alert_df):
    alert_counts = alert_df["Alert"].value_counts()

    # Plot bar chart of alerts
    plt.figure(figsize=(10, 6))
    alert_counts.plot(kind="bar")
    plt.title("Snort Alerts")
    plt.xlabel("Alert Type")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# Continuously monitor the Snort alert log
def monitor_snort_log():
    initial_size = os.path.getsize(SNORT_ALERT_LOG)
    print("Monitoring Snort alerts...")

    while True:
        current_size = os.path.getsize(SNORT_ALERT_LOG)
        if current_size > initial_size:
            print("New alert detected! Parsing and visualizing...")
            alert_df = parse_snort_log(SNORT_ALERT_LOG)
            visualize_alerts(alert_df)
            initial_size = current_size  # Update log size to new size

        time.sleep(5)  # Check for new alerts every 5 seconds

if __name__ == "__main__":
    monitor_snort_log()


