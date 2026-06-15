import hashlib
import time
import os
import json
import sys
from datetime import datetime

BASELINE_FILE = "baseline.json"
LOG_FILE = "security_alerts.log"

def log_alert(message):
    """Logs system events with real-time timestamps to console and disk."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_message = f"[{timestamp}] {message}"
    print(formatted_message)
    with open(LOG_FILE, "a") as log_file:
        log_file.write(formatted_message + "\n")

def get_file_hash(filepath):
    """Safely calculates SHA-256 binary hashes of given file assets."""
    try:
        with open(filepath, "rb") as file:
            content = file.read()
            return hashlib.sha256(content).hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def scan_directory(directory_path):
    """Recursively crawls directories mapping filepaths to hash strings."""
    file_hashes = {}
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            # Ignore telemetry footprint files if stored within the same monitored tree
            if BASELINE_FILE in full_path or LOG_FILE in full_path:
                continue
            file_hash = get_file_hash(full_path)
            if file_hash:
                file_hashes[full_path] = file_hash
    return file_hashes

def load_baseline():
    """Reads historical baseline state from persistent local storage."""
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            log_alert(f"SYSTEM ERROR - Baseline parsing failure: {e}")
    return None

def save_baseline(baseline_data):
    """Writes baseline map array to storage disk to preserve state across restarts."""
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(baseline_data, f, indent=4)
    except Exception as e:
        log_alert(f"SYSTEM ERROR - Baseline save failure: {e}")

def main():
    print("=== ZERO-TRUST DIRECTORY INTEGRITY MONITOR ===")
    
    # Check for administrative CLI overrides
    force_rebaseline = "--rebaseline" in sys.argv

    # 1. Dynamic Directory Allocation
    while True:
        directory_to_watch = input("Enter the full path of the folder to monitor: ").strip()
        if os.path.isdir(directory_to_watch):
            break
        print("[!] Invalid directory path. Please attempt configuration again.")

    # 2. Immutable Baseline Extraction Logic
    if force_rebaseline:
        print("\n[!] Administrative Override: Forcing baseline reconstruction...")
        baseline = scan_directory(directory_to_watch)
        save_baseline(baseline)
        print(f"[+] Success: Overwritten baseline for {len(baseline)} files to disk.\n")
    else:
        baseline = load_baseline()
        if baseline is None:
            print("\n[*] Initial Setup: No baseline found. Initializing golden image...")
            baseline = scan_directory(directory_to_watch)
            save_baseline(baseline)
            print(f"[+] Success: Initial baseline captured for {len(baseline)} files.\n")
        else:
            print(f"\n[+] Active Verification: Persistent state locked. Monitoring active...")

    print(f"[*] Security Status: Continuous tracking armed. (Ctrl+C to terminate)")
    
    # 3. Zero-Trust Verification Loop
    while True:
        try:
            time.sleep(2)
            current_snapshot = scan_directory(directory_to_watch)
            
            # Phase A: Check Baseline Assets (Deletions & Modifications)
            for file_path, golden_hash in baseline.items():
                if file_path not in current_snapshot:
                    log_alert(f"CRITICAL ALERT - File DELETED or MISSING: {file_path}")
                elif current_snapshot[file_path] != golden_hash:
                    log_alert(f"CRITICAL ALERT - INTEGRITY VIOLATION (Modified): {file_path}")
                    
            # Phase B: Check for Intrusion Payloads (Creations)
            for file_path in current_snapshot:
                if file_path not in baseline:
                    log_alert(f"WARNING ALERT - Unauthorized File DEPLOYED (Created): {file_path}")
                
        except KeyboardInterrupt:
            print("\n[-] Session Terminated: Monitoring loop killed cleanly.")
            break

if __name__ == "__main__":
    main()
