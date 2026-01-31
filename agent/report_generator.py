import datetime
import subprocess
import json
import psutil
import socket

# Load whitelist
with open("rules/whitelist_processes.txt", "r") as f:
    WHITELIST = [line.strip().lower() for line in f.readlines()]

def is_whitelisted(name):
    return name and name.lower() in WHITELIST

# Setup
timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
hostname = socket.gethostname()

log_file = "logs/detection_log.txt"
report_file = "reports/final_report.txt"

SUSPICIOUS_PATH_KEYWORDS = ["\\appdata\\", "\\temp\\", "\\downloads\\"]

alerts = []
info_logs = []

# INFO LOGS
info_logs.append(f"[INFO] Scan started at {timestamp}")
info_logs.append("[INFO] Monitoring mode: Periodic execution (simulated continuous monitoring)")
info_logs.append(f"[INFO] Hostname: {hostname}")

# PROCESS CHECKS
process_count = 0

for proc in psutil.process_iter(['pid', 'name', 'exe']):
    try:
        process_count += 1
        name = proc.info['name']
        path = proc.info['exe']

        if path:
            lower_path = path.lower()
            for keyword in SUSPICIOUS_PATH_KEYWORDS:
                if keyword in lower_path:
                    if is_whitelisted(name):
                        alerts.append(
                            f"[LOW] Process {name} (PID {proc.info['pid']}) running from user directory (whitelisted)"
                        )
                    else:
                        alerts.append(
                            f"[HIGH] Process {name} (PID {proc.info['pid']}) running from suspicious path: {path}"
                        )
                    break
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

info_logs.append(f"[INFO] Total processes scanned: {process_count}")


# SERVICE CHECKS
ps_command = """
Get-WmiObject Win32_Service |
Select-Object Name, State, PathName |
ConvertTo-Json
"""

result = subprocess.run(
    ["powershell", "-Command", ps_command],
    capture_output=True,
    text=True
)

services = json.loads(result.stdout)
service_count = len(services)

for service in services:
    path = service.get("PathName")
    name = service.get("Name")

    if not path:
        alerts.append(
            f"[MEDIUM] Service {name} has missing executable path (State: {service.get('State')})"
        )
        continue

    lower_path = path.lower()
    for keyword in SUSPICIOUS_PATH_KEYWORDS:
        if keyword in lower_path:
            alerts.append(
                f"[HIGH] Service {name} running from suspicious path: {path}"
            )
            break

info_logs.append(f"[INFO] Total services scanned: {service_count}")
info_logs.append("[INFO] Scan completed successfully")

# WRITE LOG FILE
with open(log_file, "a") as log:
    log.write(f"\n=== Detection Run @ {timestamp} ===\n")
    for entry in info_logs:
        log.write(entry + "\n")
    for alert in alerts:
        log.write(alert + "\n")

# WRITE FINAL REPORT
with open(report_file, "w") as report:
    report.write("Windows Service & Process Monitoring Agent\n")
    report.write("==========================================\n\n")

    report.write("Report Overview\n")
    report.write("---------------\n")
    report.write(
        "This report summarizes the findings from a Windows system monitoring scan. "
        "The monitoring agent analyzes running processes, parent–child relationships, "
        "startup services, and execution paths to identify suspicious or unauthorized activity.\n\n"
    )

    report.write(f"Scan Time : {timestamp}\n")
    report.write(f"Host Name : {hostname}\n\n")

    report.write("1. Scan Summary\n")
    report.write("---------------\n")
    report.write(f"- Total Processes Scanned : {process_count}\n")
    report.write(f"- Total Services Scanned  : {service_count}\n\n")

    report.write("2. Process Monitoring Findings\n")
    report.write("-------------------------------\n")
    process_findings = [a for a in alerts if a.startswith("[LOW]") or a.startswith("[HIGH]")]
    if process_findings:
        for finding in process_findings:
            report.write(f"- {finding}\n")
    else:
        report.write("No suspicious process activity detected.\n")
    report.write("\n")

    report.write("3. Service Audit Findings\n")
    report.write("--------------------------\n")
    service_findings = [a for a in alerts if "[SERVICE]" in a or "[MEDIUM]" in a]
    if service_findings:
        for finding in service_findings:
            report.write(f"- {finding}\n")
    else:
        report.write("No suspicious service configurations detected.\n")
    report.write("\n")

    report.write("4. Severity Classification\n")
    report.write("---------------------------\n")
    report.write(
        "- LOW    : Known or whitelisted applications running from user directories.\n"
        "- MEDIUM : Services or configurations requiring manual review.\n"
        "- HIGH   : Processes or services running from locations commonly abused by malware.\n\n"
    )

    report.write("5. Analyst Notes\n")
    report.write("-----------------\n")
    report.write(
        "Some alerts may correspond to legitimate user-installed applications "
        "(e.g., development tools or scripting environments). These are flagged "
        "based on execution location and should be manually reviewed by an analyst "
        "before taking remediation actions.\n\n"
    )

    report.write("6. Conclusion\n")
    report.write("-------------\n")
    if alerts:
        report.write(
            "The monitoring agent detected activity that matches known suspicious patterns. "
            "While not all findings indicate confirmed malware, they highlight areas "
            "that warrant further investigation.\n"
        )
    else:
        report.write(
            "No anomalous or suspicious activity was detected during this scan.\n"
        )


print("Enhanced report and logs generated successfully.")
