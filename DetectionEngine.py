import subprocess
import re
from collections import Counter

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

    # Detect invalid username attempts
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

    # Detect failed password attempts
    match = re.search(r"Failed password for (?:invalid user )?(\S+) from ([0-9.]+)", line)

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
print("       SSH DETECTION ENGINE v2")
print("====================================")

print(f"\nTotal suspicious SSH events: {len(events)}")

if not events:
    print("\n[OK] No suspicious SSH activity detected.")
    exit()


# Count events by source IP
ip_counts = Counter(event["source_ip"] for event in events)


print("\nDetected activity:")

for ip, count in ip_counts.items():

    print(f"\nSource IP: {ip}")
    print(f"Attempts: {count}")

    # Show usernames used by this source
    usernames = set(
        event["username"]
        for event in events
        if event["source_ip"] == ip
    )

    print(f"Usernames attempted: {', '.join(usernames)}")

    if count >= 5:

        print("\n[ALERT] SSH BRUTE-FORCE ACTIVITY DETECTED")
        print("MITRE ATT&CK: T1110 - Brute Force")
        print("Detection severity: MEDIUM")

    else:

        print("\n[INFO] Suspicious SSH activity detected.")