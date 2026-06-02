import os
import re
import uuid
import json
import socket
import psutil
import platform
import ipaddress
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import nmap
from fastapi import FastAPI, BackgroundTasks, Query
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="Home Cyber Guard")

SCAN_JOBS = {}

RISKY_PORTS = {
    21: {"name": "FTP", "risk": "Medium", "why": "Old file transfer service. Can expose files if misconfigured."},
    22: {"name": "SSH", "risk": "Medium", "why": "Remote access service. Risky with weak passwords."},
    23: {"name": "Telnet", "risk": "High", "why": "Insecure remote login. Passwords can be exposed."},
    53: {"name": "DNS", "risk": "Low", "why": "Normal on routers, but suspicious on unknown devices."},
    80: {"name": "HTTP", "risk": "Medium", "why": "Web/admin page may be visible."},
    443: {"name": "HTTPS", "risk": "Low", "why": "Secure web/admin page. Check if it is expected."},
    445: {"name": "SMB/File Sharing", "risk": "High", "why": "Windows file sharing. Malware often abuses this."},
    554: {"name": "RTSP Camera Stream", "risk": "Medium", "why": "Camera/video stream may be visible."},
    1900: {"name": "UPnP", "risk": "Medium", "why": "Can automatically expose devices/services."},
    3389: {"name": "Remote Desktop", "risk": "High", "why": "Remote control access to a Windows computer."},
    5900: {"name": "VNC", "risk": "High", "why": "Remote screen access service."},
    8080: {"name": "Alternative Web Admin", "risk": "Medium", "why": "Often used by routers, cameras, printers, apps."},
    8443: {"name": "Alternative HTTPS Admin", "risk": "Medium", "why": "Often used by admin dashboards."},
}

COMMON_PORTS = list(RISKY_PORTS.keys())


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def ping_host(ip):
    system = platform.system().lower()
    cmd = ["ping", "-n", "1", "-w", "400", str(ip)] if system == "windows" else ["ping", "-c", "1", "-W", "1", str(ip)]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def scan_port(ip, port, timeout=0.25):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return True
    except Exception:
        return False


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        return "Unknown device"


def get_mac_vendor_hint(ip):
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(["arp", "-a", str(ip)], text=True, errors="ignore")
        else:
            output = subprocess.check_output(["arp", "-n", str(ip)], text=True, errors="ignore")

        mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", output)
        return mac_match.group(0) if mac_match else "Unknown"
    except Exception:
        return "Unknown"


def guess_device_type(ip, ports):
    if ip.endswith(".1"):
        return "Likely router/gateway"
    if 554 in ports:
        return "Camera / CCTV / IoT device"
    if 445 in ports:
        return "Windows computer or NAS"
    if 3389 in ports:
        return "Windows computer with Remote Desktop"
    if 80 in ports or 443 in ports or 8080 in ports or 8443 in ports:
        return "Router / printer / smart device / web dashboard"
    if 22 in ports:
        return "Linux / macOS / NAS / network device"
    return "Phone / laptop / smart device"


def guidance_for_port(port):
    fixes = {
        21: "Disable FTP if unused. Use SFTP or cloud storage instead.",
        22: "Disable SSH if unused. Use strong passwords or SSH keys.",
        23: "Disable Telnet immediately. It is unsafe.",
        53: "Expected on router only. Investigate if seen on unknown device.",
        80: "Check whether this is a router, printer, camera, or app admin page.",
        443: "Check whether this admin page is expected and protected by a strong password.",
        445: "Turn off file sharing if not needed. Keep Windows updated.",
        554: "Change camera password, update firmware, and isolate cameras on guest Wi-Fi.",
        1900: "Disable UPnP on the router unless required for gaming or media apps.",
        3389: "Disable Remote Desktop unless absolutely needed.",
        5900: "Disable VNC unless required. Use strong passwords.",
        8080: "Check the web/admin dashboard and change default passwords.",
        8443: "Check the admin dashboard and update firmware.",
    }
    return fixes.get(port, "Review this service and disable it if not needed.")


def calculate_device_risk(open_ports):
    high = {23, 445, 3389, 5900}
    medium = {21, 22, 80, 554, 1900, 8080, 8443}

    if any(p in high for p in open_ports):
        return "High"
    if any(p in medium for p in open_ports):
        return "Medium"
    return "Low"


def nmap_service_scan(ip):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=str(ip), arguments="-sV --version-light -T3 --top-ports 30")

        services = []
        if str(ip) not in scanner.all_hosts():
            return services

        for proto in scanner[str(ip)].all_protocols():
            for port, info in scanner[str(ip)][proto].items():
                services.append({
                    "port": port,
                    "protocol": proto,
                    "state": info.get("state", "unknown"),
                    "service": info.get("name", "unknown"),
                    "product": info.get("product", ""),
                    "version": info.get("version", ""),
                    "extra_info": info.get("extrainfo", "")
                })

        return services
    except Exception as e:
        return [{"error": "Nmap unavailable or failed", "details": str(e)}]


def scan_single_host(ip, use_nmap=True):
    ip_str = str(ip)

    if not ping_host(ip_str):
        return None

    open_ports = []

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(scan_port, ip_str, port): port for port in COMMON_PORTS}

        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    open_ports.sort()

    warnings = []
    for port in open_ports:
        info = RISKY_PORTS.get(port, {})
        warnings.append({
            "port": port,
            "service": info.get("name", "Unknown service"),
            "risk": info.get("risk", "Low"),
            "why_it_matters": info.get("why", "Open service detected."),
            "what_to_do": guidance_for_port(port)
        })

    return {
        "ip": ip_str,
        "device_name": get_hostname(ip_str),
        "mac_address": get_mac_vendor_hint(ip_str),
        "device_type_guess": guess_device_type(ip_str, open_ports),
        "risk": calculate_device_risk(open_ports),
        "open_ports": open_ports,
        "services_detected": nmap_service_scan(ip_str) if use_nmap else [],
        "warnings": warnings
    }


def run_network_scan(job_id, mode):
    local_ip = get_local_ip()
    network = ipaddress.ip_network(local_ip + "/24", strict=False)

    SCAN_JOBS[job_id] = {
        "status": "running",
        "progress": 0,
        "result": None
    }

    hosts = list(network.hosts())
    results = []

    max_workers = 80 if mode == "quick" else 40
    use_nmap = mode == "deep"

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(scan_single_host, ip, use_nmap) for ip in hosts]

        for index, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            if result:
                results.append(result)

            SCAN_JOBS[job_id]["progress"] = int(index / len(hosts) * 100)

    results.sort(key=lambda x: tuple(map(int, x["ip"].split("."))))

    score = calculate_home_score(results)
    recommendations = generate_recommendations(results)

    SCAN_JOBS[job_id] = {
        "status": "complete",
        "progress": 100,
        "result": {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "local_ip": local_ip,
            "network_scanned": str(network),
            "mode": mode,
            "home_security_score": score,
            "devices_found": len(results),
            "summary": {
                "high_risk": len([r for r in results if r["risk"] == "High"]),
                "medium_risk": len([r for r in results if r["risk"] == "Medium"]),
                "low_risk": len([r for r in results if r["risk"] == "Low"]),
            },
            "devices": results,
            "top_recommendations": recommendations,
            "general_home_security_advice": [
                "Use WPA2 or WPA3 Wi-Fi security.",
                "Change the router admin password.",
                "Update router firmware.",
                "Disable WPS.",
                "Disable UPnP unless needed.",
                "Put cameras, smart TVs, and IoT devices on guest Wi-Fi.",
                "Keep phones, laptops, browsers, and antivirus updated.",
                "Use a password manager.",
                "Enable MFA on email, banking, cloud storage, and social accounts.",
                "Keep at least one offline or cloud backup."
            ]
        }
    }


def calculate_home_score(devices):
    score = 100
    for d in devices:
        if d["risk"] == "High":
            score -= 12
        elif d["risk"] == "Medium":
            score -= 6

        if "Unknown" in d["device_name"]:
            score -= 2

    return max(score, 0)


def generate_recommendations(devices):
    recs = []

    for d in devices:
        for port in d["open_ports"]:
            if port == 23:
                recs.append("Critical: Disable Telnet on the device using port 23.")
            if port == 3389:
                recs.append("High: Disable Remote Desktop unless you intentionally use it.")
            if port == 445:
                recs.append("High: Review Windows file sharing and disable it if not needed.")
            if port == 1900:
                recs.append("Medium: Disable UPnP on your router if you do not need it.")
            if port == 554:
                recs.append("Medium: Change camera passwords and update camera firmware.")

    recs.extend([
        "Update your router firmware.",
        "Use a separate guest Wi-Fi for smart devices.",
        "Enable automatic updates on all devices.",
        "Use MFA for important accounts."
    ])

    return list(dict.fromkeys(recs))[:10]


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<title>Home Cyber Guard</title>
<style>
body { font-family: Arial; background:#f3f4f6; margin:0; }
header { background:#111827; color:white; padding:24px; }
main { padding:24px; max-width:1200px; margin:auto; }
.card { background:white; border-radius:14px; padding:20px; margin-bottom:18px; box-shadow:0 2px 8px #ddd; }
button { background:#2563eb; color:white; border:0; border-radius:8px; padding:12px 18px; cursor:pointer; margin:4px; }
button.red { background:#dc2626; }
input, textarea { width:100%; padding:12px; margin:8px 0; border-radius:8px; border:1px solid #ccc; }
pre { white-space:pre-wrap; background:#111827; color:#d1fae5; padding:16px; border-radius:10px; max-height:500px; overflow:auto; }
.badge { padding:4px 10px; border-radius:999px; color:white; }
.high { background:#dc2626; }
.medium { background:#f59e0b; }
.low { background:#16a34a; }
</style>
</head>
<body>
<header>
<h1>Home Cyber Guard</h1>
<p>Simple cyber safety scanner for your own home network.</p>
</header>

<main>
<div class="card">
<h2>Network Scan</h2>
<p>Quick scan is faster. Deep scan uses Nmap service detection.</p>
<button onclick="startScan('quick')">Quick Scan</button>
<button onclick="startScan('deep')">Deep Scan with Nmap</button>
<p id="progress"></p>
<pre id="scanResult"></pre>
</div>

<div class="card">
<h2>Device Health Check</h2>
<button onclick="deviceHealth()">Check This Computer</button>
<pre id="healthResult"></pre>
</div>

<div class="card">
<h2>Scam / Phishing Checker</h2>
<textarea id="scamText" rows="5" placeholder="Paste suspicious SMS, email, or link here"></textarea>
<button onclick="checkScam()">Check Scam Risk</button>
<pre id="scamResult"></pre>
</div>

<div class="card">
<h2>Report</h2>
<button onclick="openReport()">Open HTML Report</button>
</div>
</main>

<script>
let currentJob = null;

async function startScan(mode) {
    document.getElementById("scanResult").innerText = "Starting scan...";
    const res = await fetch('/scan/start?mode=' + mode);
    const data = await res.json();
    currentJob = data.job_id;
    pollScan();
}

async function pollScan() {
    if (!currentJob) return;
    const res = await fetch('/scan/status/' + currentJob);
    const data = await res.json();

    document.getElementById("progress").innerText = "Status: " + data.status + " | Progress: " + data.progress + "%";

    if (data.status === "complete") {
        document.getElementById("scanResult").innerText = JSON.stringify(data.result, null, 2);
        localStorage.setItem("last_scan", JSON.stringify(data.result));
    } else {
        setTimeout(pollScan, 1000);
    }
}

async function deviceHealth() {
    const res = await fetch('/device-health');
    const data = await res.json();
    document.getElementById("healthResult").innerText = JSON.stringify(data, null, 2);
}

async function checkScam() {
    const text = document.getElementById("scamText").value;
    const res = await fetch('/scam-check', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({text})
    });
    const data = await res.json();
    document.getElementById("scamResult").innerText = JSON.stringify(data, null, 2);
}

function openReport() {
    if (!currentJob) {
        alert("Run a scan first.");
        return;
    }
    window.open('/report/' + currentJob, '_blank');
}
</script>
</body>
</html>
"""


@app.get("/scan/start")
def start_scan(background_tasks: BackgroundTasks, mode: str = Query("quick", pattern="^(quick|deep)$")):
    job_id = str(uuid.uuid4())
    SCAN_JOBS[job_id] = {"status": "queued", "progress": 0, "result": None}
    background_tasks.add_task(run_network_scan, job_id, mode)
    return {"job_id": job_id, "status": "started", "mode": mode}


@app.get("/scan/status/{job_id}")
def scan_status(job_id: str):
    return SCAN_JOBS.get(job_id, {"status": "not_found", "progress": 0, "result": None})


@app.get("/device-health")
def device_health():
    system = platform.system()
    checks = {
        "computer_name": socket.gethostname(),
        "operating_system": platform.platform(),
        "firewall": check_firewall_status(),
        "antivirus": check_antivirus_status(),
        "startup_process_review": check_suspicious_processes(),
        "disk_encryption_guidance": "Check BitLocker on Windows or FileVault on macOS.",
        "backup_guidance": "Use cloud backup or an external drive. Keep at least one backup disconnected.",
        "recommended_actions": [
            "Enable firewall.",
            "Enable antivirus real-time protection.",
            "Install operating system updates.",
            "Remove unknown startup apps.",
            "Use standard user account for daily work.",
            "Avoid installing unknown browser extensions."
        ]
    }
    return checks


def check_firewall_status():
    system = platform.system().lower()

    try:
        if system == "windows":
            output = subprocess.check_output(
                ["netsh", "advfirewall", "show", "allprofiles"],
                text=True,
                errors="ignore"
            )
            return {"status": "checked", "details": output[:3000]}

        if system == "darwin":
            output = subprocess.check_output(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                text=True,
                errors="ignore"
            )
            return {"status": "checked", "details": output}

        if system == "linux":
            output = subprocess.check_output(["sh", "-c", "ufw status || firewall-cmd --state"], text=True, errors="ignore")
            return {"status": "checked", "details": output}

    except Exception as e:
        return {"status": "unknown", "details": str(e)}

    return {"status": "unsupported", "details": "Manual check recommended."}


def check_antivirus_status():
    system = platform.system().lower()

    if system == "windows":
        try:
            cmd = [
                "powershell",
                "-Command",
                "Get-MpComputerStatus | Select-Object AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled,QuickScanAge,FullScanAge | ConvertTo-Json"
            ]
            output = subprocess.check_output(cmd, text=True, errors="ignore")
            return {"status": "checked", "details": json.loads(output)}
        except Exception as e:
            return {"status": "unknown", "details": str(e)}

    return {
        "status": "manual_check_recommended",
        "details": "Use your built-in security app or trusted antivirus to confirm real-time protection is enabled."
    }


def check_suspicious_processes():
    suspicious = []

    risky_locations = ["downloads", "temp", "appdata\\local\\temp", "/tmp"]

    for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
        try:
            exe = proc.info.get("exe") or ""
            lowered = exe.lower()

            if any(loc in lowered for loc in risky_locations):
                suspicious.append({
                    "pid": proc.info.get("pid"),
                    "name": proc.info.get("name"),
                    "path": exe,
                    "reason": "Running from Downloads or temporary folder."
                })
        except Exception:
            pass

    return {
        "suspicious_count": len(suspicious),
        "items": suspicious[:20],
        "guidance": "This is not proof of malware. Review unknown programs and scan them with antivirus."
    }


@app.post("/scam-check")
def scam_check(payload: dict):
    text = payload.get("text", "")
    lowered = text.lower()

    signals = []

    keywords = {
        "urgent": "Creates urgency.",
        "verify": "Asks you to verify something.",
        "password": "Mentions password.",
        "bank": "Mentions banking.",
        "crypto": "Mentions crypto.",
        "gift": "Mentions gift or prize.",
        "prize": "Mentions prize.",
        "refund": "Mentions refund.",
        "delivery": "Mentions delivery.",
        "click": "Asks you to click.",
        "login": "Mentions login.",
        "suspended": "Threatens account suspension.",
        "limited time": "Uses pressure tactic."
    }

    for word, reason in keywords.items():
        if word in lowered:
            signals.append(reason)

    urls = re.findall(r"https?://\\S+|www\\.\\S+", text)

    for url in urls:
        if not url.startswith("https://"):
            signals.append("Link does not clearly use HTTPS.")
        if "@" in url:
            signals.append("Link contains @ symbol, which can hide the destination.")
        if len(url) > 100:
            signals.append("Link is unusually long.")

    risk = "Low"
    if len(signals) >= 5:
        risk = "High"
    elif len(signals) >= 2:
        risk = "Medium"

    return {
        "risk": risk,
        "signals": list(dict.fromkeys(signals)),
        "urls_found": urls,
        "plain_english_guidance": [
            "Do not click links from unexpected messages.",
            "Do not enter passwords after clicking message links.",
            "Open the official app or website manually.",
            "Call the company using a trusted phone number.",
            "Never send gift cards, crypto, or bank details to strangers."
        ]
    }


@app.get("/report/{job_id}", response_class=HTMLResponse)
def report(job_id: str):
    job = SCAN_JOBS.get(job_id)

    if not job or not job.get("result"):
        return "<h1>No report available</h1><p>Run a scan first.</p>"

    result = job["result"]

    device_rows = ""
    for d in result["devices"]:
        device_rows += f"""
        <tr>
            <td>{d['ip']}</td>
            <td>{d['device_name']}</td>
            <td>{d['device_type_guess']}</td>
            <td>{d['risk']}</td>
            <td>{', '.join(map(str, d['open_ports']))}</td>
        </tr>
        """

    rec_items = "".join(f"<li>{r}</li>" for r in result["top_recommendations"])

    return f"""
    <html>
    <head>
        <title>Home Cyber Guard Report</title>
        <style>
            body {{ font-family: Arial; padding: 30px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; }}
            th {{ background: #111827; color: white; }}
        </style>
    </head>
    <body>
        <h1>Home Cyber Guard Report</h1>
        <p><b>Scan Time:</b> {result['scan_time']}</p>
        <p><b>Network:</b> {result['network_scanned']}</p>
        <h2>Home Security Score: {result['home_security_score']}/100</h2>

        <h2>Summary</h2>
        <pre>{json.dumps(result['summary'], indent=2)}</pre>

        <h2>Top Recommendations</h2>
        <ol>{rec_items}</ol>

        <h2>Devices</h2>
        <table>
            <tr>
                <th>IP</th>
                <th>Name</th>
                <th>Type Guess</th>
                <th>Risk</th>
                <th>Open Ports</th>
            </tr>
            {device_rows}
        </table>

        <h2>General Advice</h2>
        <ul>
            {''.join(f'<li>{a}</li>' for a in result['general_home_security_advice'])}
        </ul>
    </body>
    </html>
    """