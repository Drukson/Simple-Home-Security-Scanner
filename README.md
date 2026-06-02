# Home Cyber Guard

Home Cyber Guard is a simple defensive cybersecurity scanner designed for home users.

It helps non-technical users understand what devices are connected to their home network, which ports are open, what services may be running, and what actions they can take to improve their security.

The goal is to make home cybersecurity simple, practical, and easy to understand.

---

## Features

- Home network discovery
- Device detection
- Hostname lookup
- MAC address lookup where available
- Open port scanning
- Nmap service detection
- Risk scoring: Low, Medium, High
- Plain-English guidance for home users
- Scam and phishing text/link checker
- Local device health check
- Firewall status check
- Windows Defender status check
- Suspicious process location review
- HTML report generation
- No database required

---

## Use Case

This tool is designed for:

- Homeowners
- Students learning cybersecurity
- Cybersecurity beginners
- SOC analyst portfolio projects
- Home lab demonstrations
- Awareness and education

It is not designed for offensive security, exploitation, stealth scanning, or unauthorized testing.

Only scan networks you own or have explicit permission to test.

---

## Tech Stack

- Python
- FastAPI
- Nmap
- python-nmap
- psutil
- HTML/CSS/JavaScript
- Uvicorn

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/home-cyber-guard.git
cd home-cyber-guard




2. Create a virtual environment
python -m venv venv
3. Activate the virtual environment

Windows:

venv\Scripts\activate

macOS/Linux:

source venv/bin/activate
4. Install Python packages
pip install fastapi uvicorn python-nmap psutil requests
5. Install Nmap

Windows:

Download and install Nmap from:

https://nmap.org/download.html

macOS:

brew install nmap

Ubuntu/Debian:

sudo apt update
sudo apt install nmap
How to Run

Start the app:

uvicorn app:app --reload

Open in your browser:

http://127.0.0.1:8000



How to Use
Quick Scan

Use Quick Scan for a fast home network check.

It detects:

Connected devices
Device names where available
Common risky open ports
Basic risk level
Simple guidance
Deep Scan

Use Deep Scan for more detailed results.

It uses Nmap to detect:

Running services
Service names
Product names
Software versions where available
Scam Checker

Paste a suspicious SMS, email, or link.

The tool checks for:

Urgency language
Fake login requests
Password warnings
Bank/crypto scams
Delivery scam indicators
Suspicious links
Device Health Check

Checks the local computer for:

Operating system
Firewall status
Antivirus status
Windows Defender status
Suspicious processes
Backup and update guidance
Report

After scanning, click Open HTML Report.

The report includes:

Home security score
Devices found
Open ports
Risk level
Top recommendations
General security advice