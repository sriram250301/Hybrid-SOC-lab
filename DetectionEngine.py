import subprocess
import re
from collections import Counter

# Get recent SSH logs
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

suspicious_events = []

for line in logs:

    if "Failed password" in line:
        suspicious_events.append(line)

    elif "Invalid user" in line:
        suspicious_events.append(line)


print("=== SSH DETECTION ENGINE ===")
print(f"Suspicious SSH events found: {len(suspicious_events)}")

if suspicious_events:
    print("\nSuspicious events:")

    for event in suspicious_events:
        print(event)

    if len(suspicious_events) >= 5:
        print("\n[ALERT] Possible SSH brute-force attack detected!")
    else:
        print("\n[INFO] Suspicious SSH activity detected.")

else:
    print("\n[OK] No suspicious SSH activity detected.")
    