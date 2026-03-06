import pandas as pd
import requests
import smtplib
from datetime import datetime
from email.mime.text import MIMEText


# ── Log Analysis ──────────────────────────────────────────────────────────────

def analyze_logs(file_path):
    log_data = []

    with open(file_path, "r") as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) < 5:
                continue
            date  = parts[0]
            time  = parts[1]
            event = parts[2]
            user  = parts[3]
            ip    = parts[4]
            log_data.append([date, time, event, user, ip])

    if not log_data:
        df = pd.DataFrame(columns=["Date", "Time", "Event", "User", "IP"])
        return df, df, pd.Series(dtype=int)

    df = pd.DataFrame(log_data, columns=["Date", "Time", "Event", "User", "IP"])

    # Normalise event names — upper-case for reliable matching
    df["Event"] = df["Event"].str.upper().str.strip()

    # Failed logins — match any event that contains "FAIL"
    failed_mask   = df["Event"].str.contains("FAIL", na=False)
    failed_logins = df[failed_mask]

    # Suspicious IPs = IPs with >= 3 failed login attempts
    ip_fail_counts = failed_logins["IP"].value_counts()
    suspicious_ips = ip_fail_counts[ip_fail_counts >= 3]

    # Also flag IPs with > 100 total requests (regardless of login failures)
    all_ip_counts   = df["IP"].value_counts()
    high_req_ips    = all_ip_counts[all_ip_counts > 100]
    # Merge: take the higher of the two counts for any overlapping IP
    suspicious_ips  = suspicious_ips.combine(high_req_ips, max, fill_value=0).astype(int)

    return df, failed_logins, suspicious_ips


# IPs exceeding this threshold are force-flagged as CRITICAL SUSPICIOUS
CRITICAL_SUSPICIOUS_THRESHOLD = 40

def attack_severity(count):
    if count > CRITICAL_SUSPICIOUS_THRESHOLD:
        return "CRITICAL_SUSPICIOUS"
    elif count <= 2:
        return "LOW"
    elif count <= 4:
        return "MEDIUM"
    elif count <= 6:
        return "HIGH"
    else:
        return "CRITICAL"


def detect_high_requests(df):
    """Return plain dict {ip: count} for IPs with > 100 total log entries."""
    if df.empty:
        return {}
    ip_counts = df["IP"].value_counts()
    alerts = ip_counts[ip_counts > 100]
    return alerts.to_dict()


# ── Per-IP breakdown ──────────────────────────────────────────────────────────

def get_ip_details(df, ip):
    """Return a dict of stats for a single IP."""
    ip_df       = df[df["IP"] == ip]
    failed_df   = ip_df[ip_df["Event"].str.contains("FAIL", na=False)]
    success_df  = ip_df[ip_df["Event"].str.contains("SUCCESS", na=False)]
    users_tried = ip_df["User"].unique().tolist()
    first_seen  = ip_df[["Date","Time"]].astype(str).agg(" ".join, axis=1).min()
    last_seen   = ip_df[["Date","Time"]].astype(str).agg(" ".join, axis=1).max()
    return {
        "total_requests":    len(ip_df),
        "failed_attempts":   len(failed_df),
        "successful_logins": len(success_df),
        "users_targeted":    users_tried,
        "first_seen":        first_seen,
        "last_seen":         last_seen,
        "severity":          attack_severity(len(failed_df)),
    }


# ── Aggregated stats for Reports tab ─────────────────────────────────────────

def generate_report_data(df, failed, suspicious):
    if df.empty:
        return {}

    event_counts = df["Event"].value_counts().to_dict()
    top_users    = df["User"].value_counts().head(10).to_dict()
    top_ips      = df["IP"].value_counts().head(10).to_dict()
    hourly_events = None

    try:
        df["DateTime"] = pd.to_datetime(
            df["Date"] + " " + df["Time"], errors="coerce"
        )
        hourly_events = (
            df.dropna(subset=["DateTime"])
              .set_index("DateTime")
              .resample("h")["Event"]
              .count()
              .reset_index()
              .rename(columns={"DateTime": "Hour", "Event": "Count"})
        )
    except Exception:
        pass

    severity_breakdown = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "CRITICAL_SUSPICIOUS": 0}
    for count in suspicious.values:
        s = attack_severity(int(count))
        severity_breakdown[s] += 1

    return {
        "total_logs":         len(df),
        "total_failed":       len(failed),
        "total_suspicious":   len(suspicious),
        "unique_ips":         df["IP"].nunique(),
        "unique_users":       df["User"].nunique(),
        "event_counts":       event_counts,
        "top_users":          top_users,
        "top_ips":            top_ips,
        "hourly_events":      hourly_events,
        "severity_breakdown": severity_breakdown,
        "generated_at":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ── Geo-location ──────────────────────────────────────────────────────────────

def get_ip_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data.get("status") == "success":
            return {
                "ip":      ip,
                "country": data.get("country"),
                "lat":     data.get("lat"),
                "lon":     data.get("lon"),
            }
    except Exception:
        pass
    return None


# ── Email Alert ───────────────────────────────────────────────────────────────

def send_alert_email(receiver_email, ip, count):
    sender_email = "jaiswalahrv@gmail.com"
    password     = "zacd scoh olsf jlvl"

    body = f"""
Security Alert!

Suspicious activity detected.

IP Address : {ip}
Requests   : {count}

Possible attack detected on the server.
"""
    message = MIMEText(body)
    message["Subject"] = "🚨 Server Security Alert"
    message["From"]    = sender_email
    message["To"]      = receiver_email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        server.send_message(message)
        server.quit()
    except Exception as e:
        print(f"[Email Error] Could not send alert: {e}")
