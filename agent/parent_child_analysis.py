import psutil

# Suspicious parent -> child execution rules
SUSPICIOUS_CHAINS = {
    "winword.exe": ["powershell.exe", "cmd.exe"],
    "excel.exe": ["powershell.exe", "cmd.exe"],
    "chrome.exe": ["powershell.exe"],
    "outlook.exe": ["powershell.exe", "cmd.exe"]
}

print("=== Parent–Child Process Relationship Analysis ===\n")

# Step 1: Build PID -> process info map
process_map = {}

for proc in psutil.process_iter(['pid', 'ppid', 'name']):
    try:
        process_map[proc.info['pid']] = {
            "name": proc.info['name'],
            "ppid": proc.info['ppid']
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

# Step 2: Analyze parent-child relationships
for pid, info in process_map.items():
    ppid = info["ppid"]

    if ppid in process_map:
        parent_name = process_map[ppid]["name"]
        child_name = info["name"]

        if parent_name and child_name:
            parent_name = parent_name.lower()
            child_name = child_name.lower()

            if parent_name in SUSPICIOUS_CHAINS:
                if child_name in SUSPICIOUS_CHAINS[parent_name]:
                    print("[ALERT] Suspicious Parent–Child Relationship Detected")
                    print(f"Parent Process : {parent_name} (PID {ppid})")
                    print(f"Child Process  : {child_name} (PID {pid})")
                    print("-" * 50)
