import subprocess
import json

print("=== Windows Startup Service Audit ===\n")

# PowerShell command to get services with executable paths
ps_command = """
Get-WmiObject Win32_Service |
Select-Object Name, DisplayName, State, PathName |
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
        print(f"Service Name  : {service.get('Name')}")
        print(f"Display Name : {service.get('DisplayName')}")
        print(f"Status       : {service.get('State')}")
        print(f"Path         : {service.get('PathName')}")
        print("-" * 50)

except Exception as e:
    print("Error collecting service data:", e)
