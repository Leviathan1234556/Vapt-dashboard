import concurrent.futures
import subprocess
import sys
import json
import os
import re

target = sys.argv[1]

def run_command(command):
    try:
        return subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        return e.output

def classify_risk(text):
    text = text.lower()
    if any(k in text for k in ["root shell", "phpinfo", "trace method", "outdated", "directory indexing", "xst", "sql injection", "admin"]):
        return "Critical"
    elif any(k in text for k in ["x-frame-options", "x-content-type-options", "uncommon header", "server info leak"]):
        return "Warning"
    else:
        return "Normal"

def extract_rustscan_ports(output):
    ports = []
    lines = output.splitlines()
    capture = False
    for line in lines:
        if line.strip().startswith("PORT") and "STATE" in line:
            capture = True
            continue
        if capture:
            if not line.strip() or not re.match(r"^\d+/tcp", line.strip()):
                break
            parts = line.split()
            ports.append({
                "port": parts[0],
                "state": parts[1],
                "service": parts[2] if len(parts) > 2 else "unknown"
            })
    return ports

def extract_zap_findings(output):
    findings = []
    for line in output.splitlines():
        if "FAIL-" in line or "[ZAP-Baseline]" in line or "PASS" in line:
            findings.append(line.strip())
    return findings

def clean_nuclei_output(raw_output):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned = ansi_escape.sub('', raw_output)
    findings = []
    for line in cleaned.splitlines():
        if re.search(r'(CVE-\d{4}-\d+|phpinfo|admin|\.php|\.asp|\.aspx|vulnerable|panel|exposed|login|shell)', line, re.IGNORECASE):
            findings.append(line.strip())
    return findings

def extract_testssl_summary(output):
    summary = []
    for line in output.splitlines():
        if re.search(r'(SSL|TLS|VULNERABLE|NOT VULNERABLE)', line, re.IGNORECASE):
            summary.append(line.strip())
    return summary

def is_https_open(ip):
    result = subprocess.getoutput(f"nmap -p 443 {ip}")
    return 'open' in result

host_dir = os.path.abspath("scanner")
container_dir = "/zap/wrk"

def run_rustscan():
    raw = run_command(["rustscan", "-a", target, "--", "-sS"])
    return raw, extract_rustscan_ports(raw)

def run_zap():
    raw = run_command([
        "docker", "run", "-v", f"{host_dir}:{container_dir}", "-t",
        "zaproxy/zap-weekly", "zap-baseline.py", "-t", f"http://{target}", "-J", "zap_result.json"
    ])
    return raw, extract_zap_findings(raw)

def run_nuclei():
    raw = run_command(["nuclei", "-target", target, "-silent"])
    return raw, clean_nuclei_output(raw)

def run_testssl():
    if is_https_open(target):
        raw = run_command(["scanner/testssl/testssl.sh", target])
        return raw, extract_testssl_summary(raw)
    else:
        return "HTTPS not available. Skipping testssl.sh.", ["HTTPS not available. Skipping testssl.sh."]

with concurrent.futures.ThreadPoolExecutor() as executor:
    future_rustscan = executor.submit(run_rustscan)
    future_zap = executor.submit(run_zap)
    future_nuclei = executor.submit(run_nuclei)
    future_testssl = executor.submit(run_testssl)

    rustscan_raw, rustscan_data = future_rustscan.result()
    zap_raw, zap_data = future_zap.result()
    nuclei_raw, nuclei_data = future_nuclei.result()
    testssl_raw, testssl_data = future_testssl.result()

combined_text = rustscan_raw + '\n' + zap_raw + '\n' + nuclei_raw + '\n' + testssl_raw
risk_level = classify_risk(combined_text)

output = {
    "target": target,
    "risk_level": risk_level,
    "rustscan": rustscan_data,
    "zap": zap_data,
    "nuclei": nuclei_data,
    "testssl": testssl_data
}

print(json.dumps(output))
