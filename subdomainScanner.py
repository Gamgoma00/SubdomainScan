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
        self.domain = domain.strip().lower()
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
            # Open with errors='ignore' to gracefully bypass non-UTF-8 bytes found in lists like rockyou
            with open(self.wordlist, 'r', errors='ignore') as f:
                subdomains = []
                for line in f:
                    cleaned = line.strip().lower()
                    # Skip empty lines, comment lines, or invalid prefixes
                    if not cleaned or cleaned.startswith('#') or cleaned.startswith('.'):
                        continue
                    subdomains.append(cleaned)
                return subdomains
        except FileNotFoundError:
            print(f"{RED}[!] Error: Wordlist '{self.wordlist}' not found.{RESET}")
            sys.exit(1)

    def check_subdomain(self, sub_prefix: str, protocol: str) -> Tuple[str, bool, str, str]:
        # Extra layer of defense against malformed IDNA labels
        if not sub_prefix or sub_prefix.startswith('.') or ' ' in sub_prefix:
            return (f"{protocol}://{sub_prefix}.{self.domain}", False, "Invalid Input", "N/A")

        hostname = f"{sub_prefix}.{self.domain}"
        url = f"{protocol}://{hostname}"
        ip_address = "N/A"
        
        # Phase 1: Fast DNS Resolution with catch-all Unicode/IDNA Error Handling
        try:
            ip_address = socket.gethostbyname(hostname)
        except (socket.gaierror, UnicodeEncodeError):
            return (url, False, "DNS NotFound", ip_address)

        # Phase 2: Active HTTP status interrogation for verified DNS targets
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
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
        except (socket.gaierror, UnicodeEncodeError):
            return False

    def scan(self, protocol: str = 'http'):
        subdomains = self.load_wordlist()
        if not subdomains:
            print(f"{RED}[!] Error: No valid subdomains loaded from wordlist.{RESET}")
            return
            
        print(f"{BLUE}[*] Loaded {len(subdomains)} clean subdomains from wordlist.{RESET}")
        
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
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan (e.g., vulnweb.com)')
    parser.add_argument('-w', '--wordlist', default='subdomains.txt', help='Path to wordlist')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=3, help='Timeout in seconds')
    parser.add_argument('--https', action='store_true', help='Use HTTPS')
    
    args = parser.parse_args()
    protocol = 'https' if args.https else 'http'
    
    # Strip any potential accidental spaces or accidental web prefixes from domain parameter
    clean_domain = args.domain.replace("http://", "").replace("https://", "").split('/')[0]
    
    scanner = SubdomainScanner(clean_domain, args.wordlist, args.threads, args.timeout)
    try:
        scanner.scan(protocol=protocol)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan manually interrupted by user.{RESET}")

if __name__ == "__main__":
    main()
