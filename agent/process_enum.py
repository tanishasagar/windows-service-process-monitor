import psutil

print("=== Running Process Enumeration ===\n")

for process in psutil.process_iter(['pid', 'ppid', 'name', 'exe']):
    try:
        print(f"Process Name : {process.info['name']}")
        print(f"PID          : {process.info['pid']}")
        print(f"Parent PID   : {process.info['ppid']}")
        print(f"Path         : {process.info['exe']}")
        print("-" * 40)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
