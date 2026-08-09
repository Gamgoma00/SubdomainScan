#!/usr/bin/env python3
"""
DirScan Pro - High Performance Web Directory & File Brute-Forcer
Optimized with Connection Pools and Thread-Safe Interrogations.
"""

import requests
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
import time
import urllib3

# Suppress insecure request warnings from verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class DirectoryScanner:
    def __init__(self, target_url: str, wordlist: str, threads: int = 50, timeout: int = 3):
        # Ensure the target URL starts with a protocol and ends without a trailing slash
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"http://{target_url}"
        self.target_url = target_url.rstrip('/')
        
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.discovered_routes = []
        
        # Configure a thread-safe connection pool for massive parallel HTTP requests
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=threads, pool_maxsize=threads)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def load_wordlist(self) -> List[str]:
        try:
            with open(self.wordlist, 'r', errors='ignore') as f:
                routes = []
                for line in f:
                    cleaned = line.strip()
                    # Skip empty lines or wordlist metadata comments
                    if not cleaned or cleaned.startswith('#'):
                        continue
                    # Remove leading slashes if present in wordlist
                    routes.append(cleaned.lstrip('/'))
                return routes
        except FileNotFoundError:
            print(f"{RED}[!] Error: Wordlist '{self.wordlist}' not found.{RESET}")
            sys.exit(1)

    def check_route(self, path: str) -> Tuple[str, int, int]:
        url = f"{self.target_url}/{path}"
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False, # Catch raw 301/302 redirects without jumping blindly
                verify=False
            )
            return (url, response.status_code, len(response.content))
        except requests.exceptions.RequestException:
            return (url, 0, 0)

    def scan(self):
        paths = self.load_wordlist()
        if not paths:
            print(f"{RED}[!] Error: Empty wordlist.{RESET}")
            return
            
        print(f"{BLUE}[*] Loaded {len(paths)} clean injection paths from wordlist.{RESET}")
        print(f"{YELLOW}[*] Attacking target base URL: {self.target_url}{RESET}")
        print(f"{YELLOW}[*] Launching execution engine with {self.threads} threads...{RESET}\n")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_route, p): p for p in paths}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                url, status, size = future.result()
                
                # Filter out obvious 404 dead-ends
                if status != 404 and status != 0:
                    self.discovered_routes.append((url, status, size))
                    # Colorize based on status codes (Green for 200 OK, Yellow for Redirection)
                    color = GREEN if status == 200 else YELLOW
                    print(f"{color}[+] FOUND: {url} (Status: {status}) [Size: {size} bytes]{RESET}")
                
                if completed % 500 == 0:
                    print(f"{BLUE}[*] Progress: {completed}/{len(paths)}{RESET}")
        
        self.print_summary(time.time() - start_time)

    def print_summary(self, elapsed_time: float):
        print(f"\n{BLUE}{'='*60}{RESET}")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        print(f"Total valid endpoints discovered: {len(self.discovered_routes)}")
        print(f"{BLUE}{'='*60}{RESET}")
        for url, status, size in self.discovered_routes:
            print(f"  {GREEN}✓{RESET} {url:<50} [Status: {status:<3}] [Size: {size}]")

def main():
    parser = argparse.ArgumentParser(description='DirScan Pro')
    parser.add_argument('-u', '--url', required=True, help='Target base URL (e.g., http://testaspnet.vulnweb.com)')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to discovery wordlist')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=3, help='Timeout in seconds')
    
    args = parser.parse_args()
    
    scanner = DirectoryScanner(args.url, args.wordlist, args.threads, args.timeout)
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan manually terminated by user.{RESET}")

if __name__ == "__main__":
    main()
