import requests
import urllib.parse
import time
import logging
from concurrent.futures import ThreadPoolExecutor

# ---------------- CONFIG ---------------- #

MAX_WORKERS = 5
REQUEST_DELAY = 0.5  # rate limiting (seconds)
TIMEOUT = 5

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "sqlstate",
    "syntax error",
    "mysql_fetch"
]

logging.basicConfig(
    filename="results.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ---------------- FUNCTIONS ---------------- #

def load_payloads():
    try:
        with open("payloads.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[-] payloads.txt not found")
        return []

def is_vulnerable(response):
    content = response.text.lower()
    return any(error in content for error in SQL_ERRORS)

def test_parameter(base_url, param, payload):
    parsed = urllib.parse.urlparse(base_url)
    params = urllib.parse.parse_qs(parsed.query)

    original_value = params.get(param, [""])[0]
    params[param] = original_value + payload

    new_query = urllib.parse.urlencode(params, doseq=True)
    test_url = parsed._replace(query=new_query).geturl()

    try:
        response = requests.get(test_url, timeout=TIMEOUT)
        time.sleep(REQUEST_DELAY)

        if is_vulnerable(response):
            message = f"[+] SQLi indicator | Param: {param} | Payload: {payload} | URL: {test_url}"
            print(message)
            logging.info(message)

    except requests.exceptions.RequestException as e:
        logging.warning(f"Request failed: {test_url} | {e}")

def main():
    target = input("Enter target URL (DVWA/local only): ").strip()
    payloads = load_payloads()

    if not payloads:
        return

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        print("[-] No GET parameters found to test")
        return

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for param in params:
            for payload in payloads:
                executor.submit(test_parameter, target, param, payload)

# ---------------- RUN ---------------- #

if __name__ == "__main__":
    main()
