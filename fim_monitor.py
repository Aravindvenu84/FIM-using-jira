import os
import time
import json
import hashlib
import smtplib
import requests
import schedule
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from dotenv import load_dotenv




load_dotenv()

JIRA_DOMAIN = os.getenv("JIRA_DOMAIN")
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY")

SENDER_EMAIL = os.getenv("SENDER_EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")



MONITOR_DIR = "./monitor_dir"
BASELINE_FILE = "baseline.json"
LOG_FILE = "fim_log.json"




def calculate_hash(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        print(f"[HASH] ERROR reading {filepath}: {e}")
        return None




def scan_files():
    hashes = {}
    for root, _, files in os.walk(MONITOR_DIR):
        for file in files:
            path = os.path.join(root, file)
            file_hash = calculate_hash(path)
            if file_hash:
                hashes[path] = file_hash
    return hashes




def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return {}
    try:
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print("[BASELINE] ERROR loading baseline:", e)
        return {}

def save_baseline(data):
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print("[BASELINE] ERROR saving baseline:", e)




def log_event(event):
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        except Exception:
            logs = []

    logs.append(event)

    try:
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=4)
    except Exception as e:
        print("[LOG] ERROR writing log:", e)



def create_jira_ticket(change):
    if not all([JIRA_DOMAIN, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY]):
        print("[JIRA] Configuration missing. Skipping Jira ticket.")
        return

    url = f"https://{JIRA_DOMAIN}/rest/api/3/issue"
    due_date = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")

    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"FIM Alert: {change['change_type']} detected",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": json.dumps(change, indent=2)}
                        ]
                    }
                ]
            },
            "issuetype": {"name": "Task"},
            "duedate": due_date
        }
    }

    try:
        response = requests.post(
            url,
            auth=(JIRA_EMAIL, JIRA_API_TOKEN),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=10
        )

        if response.status_code == 201:
            print("[JIRA] Ticket created")
        else:
            print("[JIRA] ERROR:", response.status_code, response.text)

    except requests.exceptions.ConnectionError:
        print("[JIRA] Network not connected. Ticket not created.")
    except requests.exceptions.Timeout:
        print("[JIRA] Network timeout. Ticket not created.")
    except requests.RequestException as e:
        print("[JIRA] ERROR:", e)




def send_email(changes):
    if not changes:
        return

    if not all([SENDER_EMAIL, EMAIL_PASSWORD, RECEIVER_EMAIL]):
        print("[EMAIL] Email configuration missing. Skipping email.")
        return

    msg = MIMEText(json.dumps(changes, indent=2))
    msg["Subject"] = "FIM Alert: File Changes Detected"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
        server.starttls()
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("[EMAIL] Alert sent")

    except smtplib.SMTPConnectError:
        print("[EMAIL] Network not connected. Email not sent.")
    except smtplib.SMTPAuthenticationError:
        print("[EMAIL] Authentication failed.")
    except Exception as e:
        print("[EMAIL] ERROR:", e)




def run_fim():
    print("[FIM] Scan started:", datetime.now())

    current = scan_files()
    baseline = load_baseline()
    changes = []

   
    for file, hash_val in current.items():
        if file not in baseline:
            changes.append({
                "file": file,
                "change_type": "ADDED",
                "timestamp": datetime.now().isoformat(),
                "new_hash": hash_val
            })
        elif baseline[file] != hash_val:
            changes.append({
                "file": file,
                "change_type": "MODIFIED",
                "timestamp": datetime.now().isoformat(),
                "old_hash": baseline[file],
                "new_hash": hash_val
            })

   
    for file in baseline:
        if file not in current:
            changes.append({
                "file": file,
                "change_type": "DELETED",
                "timestamp": datetime.now().isoformat(),
                "old_hash": baseline[file]
            })

    
    for change in changes:
        log_event(change)
        create_jira_ticket(change)

    send_email(changes)
    save_baseline(current)

    print("[FIM] Scan complete\n")




schedule.every(1).hour.do(run_fim)

if __name__ == "__main__":
    os.makedirs(MONITOR_DIR, exist_ok=True)
    run_fim()

    while True:
        schedule.run_pending()
        time.sleep(30)
