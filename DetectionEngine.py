import subprocess
import re
import json
from collections import Counter
from datetime import datetime

# Get SSH logs from the last 10 minutes
command = [
    "sudo",
    "journalctl",
    "-u",
    "sshd",
    "--since",
    "10 minutes ago",
    "--no-pager"
]

result = subprocess.run(command, capture_output=True, text=True)

logs = result.stdout.splitlines()

events = []

for line in logs:

    # Invalid username
    match = re.search(r"Invalid user (\S+) from ([0-9.]+)", line)

    if match:
        username = match.group(1)
        source_ip = match.group(2)

        events.append({
            "type": "Invalid SSH User",
            "username": username,
            "source_ip": source_ip,
            "log": line
        })

    # Failed authentication
    match = re.search(
        r"Failed password for (?:invalid user )?(\S+) from ([0-9.]+)",
        line
    )

    if match:
        username = match.group(1)
        source_ip = match.group(2)

        events.append({
            "type": "Failed SSH Authentication",
            "username": username,
            "source_ip": source_ip,
            "log": line
        })


print("====================================")
print("       SSH DETECTION ENGINE v3")
print("====================================")

print(f"\nTotal suspicious SSH events: {len(events)}")

if not events:
    print("\n[OK] No suspicious SSH activity detected.")
    exit()


# Group events by source IP
ip_counts = Counter(event["source_ip"] for event in events)

alerts = []

for ip, count in ip_counts.items():

    usernames = list(set(
        event["username"]
        for event in events
        if event["source_ip"] == ip
    ))

    if count >= 5:

        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "detection": "SSH Brute Force",
            "source_ip": ip,
            "attempts": count,
            "usernames": usernames,
            "mitre_attack": "T1110",
            "severity": "medium"
        }

        alerts.append(alert)

        print("\n[ALERT] SSH BRUTE-FORCE ACTIVITY DETECTED")
        print(f"Source IP: {ip}")
        print(f"Attempts: {count}")
        print(f"Usernames: {', '.join(usernames)}")
        print("MITRE ATT&CK: T1110")
        print("Severity: MEDIUM")


# Save alerts as JSON
if alerts:

    alert_file = "../alerts/alerts.json"

    with open(alert_file, "w") as file:
        json.dump(alerts, file, indent=4)

    print(f"\n[+] Structured alerts saved to: {alert_file}")