# Real-Time Log Monitoring & Cyber Attack Detection Dashboard

A **real-time cybersecurity monitoring system** that analyzes server logs, detects suspicious IP activity, and alerts administrators when potential attacks occur.

The system continuously processes logs, identifies abnormal request patterns, and provides **live visualization of attacks through an interactive dashboard built with Streamlit**.

---

# Project Overview

Modern web servers generate thousands of logs every minute. Manually monitoring these logs for security threats is difficult and inefficient.

This project provides a **real-time log monitoring solution** that:

* Continuously analyzes server logs
* Detects suspicious IP behavior
* Sends automatic email alerts
* Visualizes attack activity on a dashboard

The system helps administrators **quickly detect brute force attacks, bots, and abnormal traffic patterns.**

---

# Key Features

### Real-Time Log Monitoring

Continuously reads and analyzes log files.

### Suspicious IP Detection

Detects IP addresses making **excessive requests within a short time window.**

### Email Alert System

Automatically sends email alerts to the system owner when suspicious activity is detected.

### Cyber Attack Visualization

Interactive dashboard displaying:

* attack trends
* suspicious IPs
* request patterns
* live monitoring metrics

### Admin Login System

Owner logs in with an email to receive alerts.

### CSV / Log Upload Support

Users can upload external server logs for analysis.

---

# System Architecture

```
User / Server Traffic
        │
        ▼
Log Generator (Simulated Server Logs)
        │
        ▼
Log File Storage (.log / .csv)
        │
        ▼
Log Processing Engine
(Python + Pandas)
        │
 ┌──────┼─────────────┐
 ▼      ▼             ▼

Attack Detection   Dashboard UI   Email Alert System
Algorithm          (Streamlit)    (SMTP Mail)

        │
        ▼
Administrator Notification
```

---

# Technology Stack

### Programming Language

**Python**

Used for log processing, analysis, and automation.

---

### Web Dashboard Framework

**Streamlit**

Used to create the interactive monitoring dashboard.

---

### Data Processing

**Pandas**

Handles log parsing, IP request counting, and time-based filtering.

---

### Visualization

**Plotly**

Used for:

* attack charts
* traffic graphs
* suspicious IP visualizations

---

### Email Alert System

Uses Python libraries:

```
smtplib
email.mime
```

To send **security alerts when abnormal activity is detected.**

---

# Required Python Libraries

Install the required dependencies:

```
pip install streamlit
pip install pandas
pip install plotly
pip install streamlit-autorefresh
pip install requests
```

---

# Project Structure

```
log-security-dashboard
│
├── app.py
├── analyzer.py
├── sample.log
├── requirements.txt
└── README.md
```

---

# How to Run the Project

### Step 1 — Clone the Repository

```
git clone https://github.com/your-repo/log-security-dashboard.git
cd log-security-dashboard
```

---

### Step 2 — Install Dependencies

```
pip install -r requirements.txt
```

---

### Step 3 — Run the Dashboard

```
streamlit run app.py
```

---

### Step 4 — Open in Browser

The dashboard will open automatically at:

```
http://localhost:8501
```

---

# How Attack Detection Works

The system continuously analyzes log entries and counts the number of requests made by each IP address.

If an IP makes more than **100 requests within a defined time window**, it is flagged as suspicious.

```
if requests_from_ip > 100:
    trigger_email_alert()
```

This helps detect:

* brute force login attempts
* bot traffic
* denial-of-service attempts

---

# Example Log Entry

```
2026-03-01 00:00:12 FILE ACCESS user=system file=/etc/passwd ip=10.0.0.31
2026-03-01 00:00:25 LOGIN FAILED user=admin ip=10.0.0.25
2026-03-01 00:00:28 LOGIN SUCCESS user=anusha ip=192.168.1.48
```

---

# Future Improvements

Possible upgrades include:

* Machine learning attack detection
* Integration with real web servers
* Automatic IP blocking
* Cloud deployment
* SIEM integration
* Advanced threat intelligence

---

# Use Cases

This system can be used for:

* server security monitoring
* cybersecurity research
* DevOps monitoring tools
* SOC (Security Operations Center) dashboards
* intrusion detection systems

---

# License

This project is created for educational and hackathon purposes.

---

# Authors

Developed by a team of cybersecurity enthusiasts for a **hackathon security monitoring project**.