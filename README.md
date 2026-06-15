# Enterprise-Grade Host Intrusion Detection System (HIDS) - File Integrity Monitor

A high-performance, local Host Intrusion Detection System (HIDS) component built in Python. This security agent recursively monitors critical directory trees for unauthorized structural and content modifications using the SHA-256 cryptographic hashing algorithm. 

Unlike volatile scripts that store baseline states in temporary RAM, this utility implements **JSON state serialization** to mitigate the "Reboot Exploit"—ensuring historical data integrity checks persist across system restarts and agent blackouts.

---

## 🛡️ Core Defensive Capabilities

| Feature | Threat Mitigated | Technical Implementation |
| :--- | :--- | :--- |
| **Persistent Hashing** | Baseline Tampering / Reboot Exploits | State serialization via `json` stored directly to disk (`baseline.json`). |
| **Recursive Folder Crawl** | Shadow Payload Deployments | Dynamic tree traversal using Python's `os.walk` to intercept deep sub-folder injections. |
| **Defensive Exception Handling** | Denial of Service (DoS) via File-Locking | Multi-exception shielding captures `PermissionError` and `FileNotFoundError` without agent failure. |
| **Asynchronous Delta Tracking** | Automated Anti-Forensics | Continuous 2-second sampling engine maps real-time filesystem state against baseline cryptographic arrays. |

---

## 🛠️ System Architecture & Workflow

1. **Initialization & Authentication:** The script boots up and requests a target directory pathway. It verifies the path validity using the `os.path` subsystem before running.
2. **State Validation:** The agent searches for an existing `baseline.json` file. 
   * If **absent**: It automatically crawls the target directory, calculates binary SHA-256 digests for all files, and establishes a trusted cryptographic baseline.
   * If **present**: It extracts historical baseline states into active system memory, maintaining integrity continuity.
3. **Continuous Analysis Loop:** The monitor asynchronously recalculates digests every 120 seconds (optimized to 2 seconds for active debugging). It isolates security deltas into three classifications:
   * **Modifications:** Existing file paths where current hash $\neq$ baseline hash.
   * **Creations:** Unmapped file paths introduced to the directory structure.
   * **Deletions:** Pre-existing file paths purged from the disk layout.

---

## 🚀 Installation & Operation

### Prerequisites
* Python 3.8 or higher installed on the host machine.
* Git version control system configured.

### Deployment Steps
1. Clone the repository down to your local security architecture:
   ```bash
   git clone [https://github.com/mheriIII/Enterprise-File-Integrity-Monitor.git](https://github.com/mheriIII/Enterprise-File-Integrity-Monitor.git)
