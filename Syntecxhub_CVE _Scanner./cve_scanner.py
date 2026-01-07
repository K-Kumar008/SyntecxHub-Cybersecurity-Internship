#!/usr/bin/env python3

import subprocess
import re
import requests
import time
import socket
import sys
from tabulate import tabulate

# =========================
# CONFIG (MANDATORY)
# =========================
NVD_API_KEY = "PUT_YOUR_API_KEY_HERE"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HEADERS = {
    "User-Agent": "CVE-Scanner-Educational/1.0",
    "Accept": "application/json",
    "apiKey": NVD_API_KEY
}

# =========================
# SEVERITY
# =========================
def severity(score):
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    else:
        return "N/A"

# =========================
# RESOLVE DOMAIN → IP
# =========================
def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Cannot resolve target")
        sys.exit(1)

# =========================
# RUN NMAP
# =========================
def run_nmap(target):
    print(f"[+] Running Nmap on {target}")
    try:
        cmd = ["nmap", "-sV", target]
        return subprocess.check_output(cmd).decode()
    except:
        print("[-] Nmap scan failed")
        sys.exit(1)

# =========================
# PARSE SERVICES
# =========================
def parse_services(output):
    services = []
    for line in output.split("\n"):
        if re.match(r"^\d+/tcp", line):
            parts = line.split()
            port = parts[0]
            service = parts[2]
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            services.append((port, service, version))
    return services

# =========================
# NVD CVE LOOKUP (FIXED)
# =========================
def search_cves(service):
    params = {
        "keywordSearch": service,
        "resultsPerPage": 5
    }

    try:
        r = requests.get(NVD_URL, headers=HEADERS, params=params, timeout=20)
        data = r.json()
    except:
        return []

    vulns = data.get("vulnerabilities", [])
    results = []

    for v in vulns:
        cve_id = v["cve"]["id"]
        metrics = v["cve"].get("metrics", {})
        score = 0.0

        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        results.append((cve_id, severity(score)))

    time.sleep(1)
    return results

# =========================
# MAIN
# =========================
def main():
    print("\n=== Vulnerability / CVE Scanner ===\n")

    target = input("Enter IP or Domain: ").strip()
    ip = resolve_target(target)
    print(f"[+] Target IP: {ip}\n")

    nmap_output = run_nmap(target)
    services = parse_services(nmap_output)

    if not services:
        print("[-] No services detected")
        return

    report = []

    for port, service, version in services:
        cves = search_cves(service)

        if not cves:
            report.append([ip, port, service, version, "None", "N/A"])
        else:
            for cve_id, sev in cves:
                report.append([ip, port, service, version, cve_id, sev])

    print("\n=== Scan Results ===\n")
    print(tabulate(
        report,
        headers=["IP Address", "Port", "Service", "Version", "CVE", "Severity"],
        tablefmt="grid"
    ))

    print("\n⚠️ Educational & authorized testing only\n")

# =========================
if __name__ == "__main__":
    main()
