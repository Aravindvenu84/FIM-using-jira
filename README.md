# FIM-using-jira

File Integrity Monitoring (FIM) Tool using SHA-256
Overview

This project is a File Integrity Monitoring (FIM) system implemented in Python that uses cryptographic hashing (SHA-256) to detect unauthorized file changes. The tool continuously monitors a directory, compares file hashes against a trusted baseline, logs changes, and sends alerts via email and Jira tickets.

This demonstrates a real-world application of hashing for data integrity verification.

Objectives

Detect file creation, modification, and deletion

Ensure data integrity using SHA-256 hashing

Maintain a baseline of trusted file hashes

Log security events for auditing

Send alerts via Email and Jira

Automate scans using a scheduler

Why Hashing Is Used

Hashing ensures that even a single-byte change in a file results in a completely different hash value.
This makes hashing ideal for:
File integrity monitoring

Tamper detection

Security auditing

This tool uses SHA-256, which is collision-resistant and secure for modern systems.

Hashing Process Logic

File Content
     |
     v
SHA-256 Hash Function
     |
     v
Fixed-Length Hash Value

If the file changes:

Original Hash ≠ New Hash → Integrity Violation Detected
Core Components
1. Hash Calculation

Each file is read in binary mode and hashed using SHA-256.

def calculate_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()
    
Uses chunk-based reading (efficient for large files)

Generates a fixed 256-bit hash


2. Baseline Creation

A baseline is a trusted snapshot of file hashes.

Stored in baseline.json

Used for future comparisons

{
  "./monitor_dir/example.txt": "a1b2c3d4..."
}


3. File Scanning

The tool recursively scans the monitored directory and calculates hashes for all files.

def scan_files():
    hashes = {}
    for root, _, files in os.walk(MONITOR_DIR):
        for file in files:
            path = os.path.join(root, file)
            hashes[path] = calculate_hash(path)
    return hashes

Change Detection Logic

| Change Type  | Description                    |
| ------------ | ------------------------------ |
| **ADDED**    | New file detected              |
| **MODIFIED** | Hash mismatch found            |
| **DELETED**  | File missing from current scan |

Comparison Logic

Current Scan Hashes
        |
        v
Compare with Baseline
        |
        +-- New File → ADDED
        +-- Hash Changed → MODIFIED
        +-- Missing File → DELETED


Logging and Alerts
Event Logging

All detected changes are logged into fim_log.json.

{
  "file": "./monitor_dir/test.txt",
  "change_type": "MODIFIED",
  "timestamp": "2025-01-01T10:30:00",
  "old_hash": "abc123...",
  "new_hash": "xyz789..."
}

Email Alerts

Sends alerts using SMTP (Gmail)

Triggered only when changes are detected

send_email(changes)


Jira Ticket Creation

For every detected change, a Jira issue is automatically created.

Jira Use Case

Security incident tracking

Audit and compliance

Incident response workflow

Automation & Scheduling

The tool runs automatically every hour using the schedule library.

schedule.every(1).hour.do(run_fim)


Security Considerations

Uses SHA-256 (secure & collision-resistant)

Reads files in binary mode

Handles network failures gracefully

Avoids false alerts when no changes are detected

Real-World Use Cases

Host-based intrusion detection

Compliance monitoring (PCI-DSS, ISO 27001)

Detecting malware or unauthorized changes

Protecting configuration files

Conclusion

This File Integrity Monitoring tool demonstrates how cryptographic hashing can be effectively used to ensure data integrity in real-world cybersecurity environments. By combining hashing, logging, automation, and alerting, the system provides a practical and scalable security solution.
