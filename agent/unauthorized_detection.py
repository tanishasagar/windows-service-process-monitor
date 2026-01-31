import psutil
import subprocess
import json

SUSPICIOUS_PATH_KEYWORDS = [
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\"
]

print("=== Unauthorized / Suspicious Activity Detection ===\n")

# PART 1: Suspicious Processes
print("[*] Checking running processes...\n")

for proc in psutil.process_iter(['pid', 'name', 'exe']):
    try:
        path = proc.info['exe']
        name = proc.info['name']

        if path:
            lower_path = path.lower()
            for keyword in SUSPICIOUS_PATH_KEYWORDS:
                if keyword in lower_path:
                    print("[ALERT] Suspicious Process Location")
                    print(f"Process Name : {name}")
                    print(f"PID          : {proc.info['pid']}")
                    print(f"Path         : {path}")
                    print("-" * 50)
                    break

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

# PART 2: Suspicious Services
print("\n[*] Checking Windows services...\n")

ps_command = """
Get-WmiObject Win32_Service |
Select-Object Name, State, PathName |
ConvertTo-Json
"""

try:
    result = subprocess.run(
        ["powershell", "-Command", ps_command],
        capture_output=True,
        text=True
    )

    services = json.loads(result.stdout)

    for service in services:
        path = service.get("PathName")

        if not path:
            print("[ALERT] Service with Missing Executable Path")
            print(f"Service Name : {service.get('Name')}")
            print(f"Status       : {service.get('State')}")
            print("-" * 50)
            continue

        lower_path = path.lower()
        for keyword in SUSPICIOUS_PATH_KEYWORDS:
            if keyword in lower_path:
                print("[ALERT] Suspicious Service Location")
                print(f"Service Name : {service.get('Name')}")
                print(f"Status       : {service.get('State')}")
                print(f"Path         : {path}")
                print("-" * 50)
                break

except Exception as e:
    print("Error checking services:", e)
