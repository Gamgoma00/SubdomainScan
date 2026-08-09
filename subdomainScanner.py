#!/usr/bin/env python3
"""
SubdomainScan Pro - High Performance Subdomain Enumeration Tool
Optimized with DNS pre-filtering and Thread-safe Connection Pools.
"""

import requests
import sys
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
import time
import urllib3

# Suppress insecure request warnings from verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Output styling
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class SubdomainScanner:
    def __init__(self, domain: str, wordlist: str, threads: int = 50, timeout: int = 3):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.valid_subdomains = []
        
        # Configure a thread-safe connection pool for concurrent workers
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=threads, pool_maxsize=threads)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def load_wordlist(self) -> List[str]:
        try:
            with open(self.wordlist, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{RED}[!] Error: Wordlist '{self.wordlist}' not found.{RESET}")
            sys.exit(1)

    def check_subdomain(self, sub_prefix: str, protocol: str) -> Tuple[str, bool, str, str]:
        hostname = f"{sub_prefix}.{self.domain}"
        url = f"{protocol}://{hostname}"
        ip_address = "N/A"
        
        # Phase 1: Fast DNS Resolution to avoid wasteful HTTP timeouts on dead records
        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            return (url, False, "DNS NotFound", ip_address)

        # Phase 2: Active HTTP status interrogation for verified DNS targets
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            # Accept all non-404 status codes as live (including 403, 500, etc.)
            if response.status_code != 404:
                return (url, True, str(response.status_code), ip_address)
            return (url, False, "404", ip_address)
                
        except requests.exceptions.Timeout:
            return (url, False, "Timeout", ip_address)
        except requests.exceptions.ConnectionError:
            return (url, False, "Connection Error", ip_address)
        except Exception as e:
            return (url, False, f"Error: {str(e)}", ip_address)

    def check_wildcard(self) -> bool:
        """Detect whether the target domain uses a catch-all Wildcard DNS rule."""
        wildcard_sub = f"vulnerabilities-test-x1y2z3-{int(time.time())}"
        hostname = f"{wildcard_sub}.{self.domain}"
        try:
            socket.gethostbyname(hostname)
            return True
        except socket.gaierror:
            return False

    def scan(self, protocol: str = 'http'):
        subdomains = self.load_wordlist()
        print(f"{BLUE}[*] Loaded {len(subdomains)} subdomains from wordlist.{RESET}")
        
        print(f"{YELLOW}[*] Checking for Wildcard DNS...{RESET}")
        if self.check_wildcard():
            print(f"{RED}[!] Warning: Wildcard DNS detected! Target resolves ANY random host. Expect potential false positives.{RESET}")
        
        print(f"{YELLOW}[*] Starting scan on {self.domain} using {self.threads} threads...{RESET}\n")
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.check_subdomain, sub, protocol): sub 
                for sub in subdomains
            }
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                url, is_valid, status, ip = future.result()
                
                if is_valid:
                    self.valid_subdomains.append((url, status, ip))
                    print(f"{GREEN}[+] FOUND: {url} (Status: {status}) -> [IP: {ip}]{RESET}")
                
                if completed % 100 == 0:
                    print(f"{BLUE}[*] Progress: {completed}/{len(subdomains)}{RESET}")
        
        self.print_summary(time.time() - start_time)

    def print_summary(self, elapsed_time: float):
        print(f"\n{BLUE}{'='*60}{RESET}")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        print(f"Total valid subdomains found: {len(self.valid_subdomains)}")
        print(f"{BLUE}{'='*60}{RESET}")
        for url, status, ip in self.valid_subdomains:
            print(f"  {GREEN}✓{RESET} {url:<40} [Status: {status:<4}] [IP: {ip}]")

def main():
    parser = argparse.ArgumentParser(description='SubdomainScan Pro')
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-w', '--wordlist', default='subdomains.txt', help='Path to wordlist')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=3, help='Timeout in seconds')
    parser.add_argument('--https', action='store_true', help='Use HTTPS')
    
    args = parser.parse_args()
    protocol = 'https' if args.https else 'http'
    
    scanner = SubdomainScanner(args.domain, args.wordlist, args.threads, args.timeout)
    try:
        scanner.scan(protocol=protocol)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan manually interrupted by user.{RESET}")

if __name__ == "__main__":
    main()
