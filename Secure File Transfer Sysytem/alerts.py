"""
Secure File Transfer Monitoring System
Alert Engine Module
"""

import json
import os
from datetime import datetime

ALERT_FILE = "logs/alerts.json"

ALERT_TYPES = {
    "UNAUTHORIZED_TRANSFER": "CRITICAL",
    "INTEGRITY_VIOLATION": "CRITICAL",
    "SENSITIVE_FILE_DELETED": "HIGH",
    "BULK_TRANSFER": "HIGH",
    "SUSPICIOUS_PROCESS": "MEDIUM",
    "UNKNOWN_DESTINATION": "MEDIUM",
    "INFO": "INFO",
}


def load_alerts() -> list:
    """Load alerts safely."""

    os.makedirs("logs", exist_ok=True)

    if not os.path.exists(ALERT_FILE):

        with open(ALERT_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)

        return []

    try:
        with open(ALERT_FILE, "r", encoding="utf-8") as f:

            data = json.load(f)

            if isinstance(data, list):
                return data

            return []

    except Exception:
        return []


def save_alerts(alerts: list):
    """Save alerts safely."""

    os.makedirs("logs", exist_ok=True)

    with open(ALERT_FILE, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)


def raise_alert(
    alert_type: str,
    message: str,
    details: dict = None
):
    """Create and save an alert."""

    severity = ALERT_TYPES.get(alert_type, "INFO")

    alert = {
        "id": f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}",
        "timestamp": datetime.now().isoformat(),
        "type": alert_type,
        "severity": severity,
        "message": message,
        "details": details or {},
        "acknowledged": False,
    }

    alerts = load_alerts()

    alerts.append(alert)

    save_alerts(alerts)

    print(f"\n[{severity}] ALERT [{alert_type}]")
    print(f"Message: {message}")

    return alert


def acknowledge_alert(alert_id: str):
    """Mark an alert as acknowledged."""

    alerts = load_alerts()

    found = False

    for a in alerts:

        if a.get("id") == alert_id:

            a["acknowledged"] = True
            found = True

            print(f"Alert {alert_id} acknowledged.")

    save_alerts(alerts)

    if not found:
        print("Alert ID not found.")


def list_alerts(unacknowledged_only: bool = False):
    """Print all alerts."""

    alerts = load_alerts()

    cleaned_alerts = []

    for a in alerts:

        if not isinstance(a, dict):
            continue

        cleaned_alerts.append({
            "id": a.get("id", "N/A"),
            "timestamp": a.get("timestamp", "N/A"),
            "type": a.get("type", "UNKNOWN"),
            "severity": a.get("severity", "MEDIUM"),
            "message": a.get("message", "No Message"),
            "acknowledged": a.get("acknowledged", False),
        })

    alerts = cleaned_alerts

    if unacknowledged_only:
        alerts = [
            a for a in alerts
            if not a.get("acknowledged", False)
        ]

    if not alerts:
        print("\nNo alerts found.")
        return

    print("\n" + "=" * 60)
    print(" ALERT LOG ")
    print("=" * 60)

    for a in alerts:

        ack = (
            "[ACK]"
            if a.get("acknowledged", False)
            else "[NEW]"
        )

        print(
            f"\n {ack} "
            f"{a.get('severity')} "
            f"- "
            f"{a.get('type')}"
        )

        print(f"    ID   : {a.get('id')}")
        print(f"    Time : {a.get('timestamp')}")
        print(f"    Msg  : {a.get('message')}")

    print("=" * 60)


def detect_bulk_transfer(
    log_file: str = "logs/file_transfer_log.json",
    threshold: int = 50
):
    """Detect bulk transfer activity."""

    if not os.path.exists(log_file):
        return

    try:

        with open(log_file, "r", encoding="utf-8") as f:
            logs = json.load(f)

    except Exception:
        return

    now = datetime.now()

    recent = []

    for ev in logs:

        try:

            timestamp = ev.get("timestamp")

            if not timestamp:
                continue

            t = datetime.fromisoformat(timestamp)

            if (now - t).seconds <= 60:
                recent.append(ev)

        except Exception:
            continue

    if len(recent) >= threshold:

        raise_alert(
            "BULK_TRANSFER",
            f"{len(recent)} file events detected in the last 60 seconds.",
            {
                "event_count": len(recent),
                "threshold": threshold
            }
        )


if __name__ == "__main__":

    list_alerts()