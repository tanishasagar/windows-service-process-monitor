# Windows Service & Process Monitoring Agent

## Project Overview

This project is a **Windows Service & Process Monitoring Agent** developed as part of my **Cybersecurity Internship**.  
The objective of the project is to monitor running processes and Windows services in order to identify **suspicious, unauthorized, or potentially malicious activity** using rule-based detection techniques.

The monitoring agent focuses on behaviors commonly abused by malware, such as:
- abnormal parent–child process relationships  
- execution of programs from user-writable directories  
- suspicious or misconfigured startup services  

The project follows a **defensive (Blue Team) security approach**, similar to basic SOC monitoring tools.

---

## Objectives

- Monitor active Windows processes with detailed metadata  
- Analyze parent–child process relationships  
- Audit Windows startup services and configurations  
- Detect unauthorized or suspicious processes and services  
- Generate structured logs and a final security report  
- Reduce false positives using whitelist-based validation  

---

## Tools & Technologies Used

- **Python 3**
- **psutil** – process enumeration and analysis  
- **PowerShell (WMI)** – Windows service auditing  
- **Visual Studio Code** – development environment  

---

## Project Structure
```text

windows-service-process-monitor/
│
├── agent/
│ ├── process_enum.py
│ ├── parent_child_analysis.py
│ ├── service_audit.py
│ ├── unauthorized_detection.py
│ └── report_generator.py
│
├── rules/
│ └── whitelist_processes.txt
│
├── logs/
│ └── detection_log.txt
│
├── reports/
│ └── final_report.txt
│
└── screenshots/
```
---

## Implementation Phases

### Phase 1: Process Enumeration
- Enumerates all running processes
- Captures process name, PID, parent PID, and executable path
- Forms the base dataset for further analysis

---

### Phase 2: Parent–Child Process Analysis
- Maps parent and child process relationships
- Uses rule-based logic to identify suspicious execution chains  
  (for example, Office applications spawning command-line tools)

---

### Phase 3: Windows Service Audit
- Enumerates Windows services using PowerShell (WMI)
- Collects service name, status, and executable path
- Flags services with missing or unusual executable paths

---

### Phase 4: Unauthorized & Suspicious Detection
- Identifies processes running from user-writable directories such as:
  - AppData  
  - Temp  
  - Downloads  
- Applies severity levels (LOW / MEDIUM / HIGH)
- Detects suspicious service configurations

---

### Phase 5: Logging & Reporting
- Generates timestamped logs for every scan
- Supports repeated executions to simulate **continuous monitoring**
- Produces a structured final report summarizing findings, severity, and analyst notes

---

## Whitelist & False Positive Handling

To reduce false positives, a **process whitelist** is implemented using an external configuration file.

Examples of whitelisted processes include:
- `python.exe`
- `Code.exe` (Visual Studio Code)

Development tools such as **VS Code (Code.exe)** initially appeared as high-severity alerts due to execution from user-writable directories.  
After verification, these processes were added to the whitelist and subsequently classified as **LOW severity**, demonstrating analyst validation and rule tuning.

This reflects real SOC workflows, where alerts are reviewed and refined rather than blindly suppressed.

---

## Logging & Monitoring Behavior

- Each execution creates a new **Detection Run** with timestamps
- Logs accumulate over time to provide timeline-based visibility
- Monitoring is implemented through **periodic execution**, simulating continuous system monitoring

---

## Output Artifacts

- **Detection Logs**  
  `logs/detection_log.txt`  
  Contains detailed scan information, severity levels, and multiple monitoring runs.

- **Final Report**  
  `reports/final_report.txt`  
  Summarizes scan results, findings, analyst notes, and conclusions in a structured format.

---

## Learning Outcomes

Through this project, I gained hands-on experience with:
- Windows process and service internals  
- Malware persistence and execution patterns  
- Rule-based threat detection logic  
- SOC-style logging and reporting  
- Handling false positives through whitelisting  

---

## Disclaimer

This project is intended for **educational and defensive security purposes only**.  
It does not perform malware removal or system modification.
