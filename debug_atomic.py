import subprocess

def check():
    # Test 1: Check loaded module
    print("--- Test 1: Check Loaded Module ---")
    import_cmd = "Import-Module 'C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1' -ErrorAction Stop; Get-Module Invoke-AtomicRedTeam"
    cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", import_cmd]
    print(f"Running command: {cmd}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
    except Exception as e:
        print(f"Exception: {e}")

    # Test 2: Check command existence
    print("\n--- Test 2: Check Command Existence ---")
    import_cmd = "Import-Module 'C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1' -ErrorAction Stop; Get-Command Invoke-AtomicTest"
    cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", import_cmd]
    print(f"Running command: {cmd}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    check()
