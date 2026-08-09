#!/usr/bin/env python3
"""
SubdomainScan - Fast & Reliable Subdomain Enumeration Tool
Scans for active subdomains using DNS resolution and HTTP status codes
"""

import requests
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import List, Tuple
import time

# Color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class SubdomainScanner:
    def __init__(self, domain: str, wordlist: str, threads: int = 50, timeout: int = 5):
        """
        Initialize the SubdomainScanner
        
        Args:
            domain: Target domain to scan
            wordlist: Path to wordlist file
            threads: Number of concurrent threads
            timeout: Request timeout in seconds
        """
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.valid_subdomains = []
        self.session = requests.Session()
        self.session.timeout = timeout
        
    def load_wordlist(self) -> List[str]:
        """Load subdomains from wordlist file"""
        try:
            with open(self.wordlist, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            print(f"{BLUE}[*] Loaded {len(subdomains)} subdomains from {self.wordlist}{RESET}")
            return subdomains
        except FileNotFoundError:
            print(f"{RED}[!] Error: Wordlist file '{self.wordlist}' not found{RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{RED}[!] Error reading wordlist: {e}{RESET}")
            sys.exit(1)
    
    def check_subdomain(self, subdomain: str, protocol: str = 'http') -> Tuple[str, bool]:
        """
        Check if a subdomain is valid
        
        Args:
            subdomain: Subdomain to check
            protocol: HTTP protocol to use (http/https)
            
        Returns:
            Tuple of (url, is_valid)
        """
        url = f"{protocol}://{subdomain}.{self.domain}"
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            
            # Consider any response except 404 as valid
            if response.status_code != 404:
                return (url, True, response.status_code)
            else:
                return (url, False, response.status_code)
                
        except requests.exceptions.Timeout:
            return (url, False, "Timeout")
        except requests.exceptions.ConnectionError:
            return (url, False, "Connection Error")
        except Exception as e:
            return (url, False, str(e))
    
    def scan(self, protocol: str = 'http', try_https: bool = False):
        """
        Scan all subdomains using threading
        
        Args:
            protocol: Initial protocol (http/https)
            try_https: Also try HTTPS
        """
        subdomains = self.load_wordlist()
        
        print(f"{YELLOW}[*] Starting subdomain scan on {self.domain}...{RESET}")
        print(f"{YELLOW}[*] Using {self.threads} threads{RESET}\n")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.check_subdomain, sub, protocol): sub 
                for sub in subdomains
            }
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                try:
                    url, is_valid, status = future.result()
                    
                    if is_valid:
                        self.valid_subdomains.append((url, status))
                        print(f"{GREEN}[+] FOUND: {url} (Status: {status}){RESET}")
                    
                    # Progress indicator
                    if completed % 100 == 0:
                        print(f"{BLUE}[*] Progress: {completed}/{len(subdomains)}{RESET}")
                        
                except Exception as e:
                    print(f"{RED}[!] Error: {e}{RESET}")
        
        elapsed = time.time() - start_time
        self.print_summary(elapsed)
    
    def print_summary(self, elapsed_time: float):
        """Print scan summary"""
        print(f"\n{BLUE}{'='*50}{RESET}")
        print(f"{BLUE}[*] Scan Complete!{RESET}")
        print(f"{BLUE}{'='*50}{RESET}")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        print(f"Total subdomains found: {len(self.valid_subdomains)}")
        
        if self.valid_subdomains:
            print(f"\n{GREEN}Valid Subdomains:{RESET}")
            for url, status in self.valid_subdomains:
                print(f"  {GREEN}✓{RESET} {url} [{status}]")
        else:
            print(f"\n{YELLOW}No valid subdomains found.{RESET}")

def main():
    parser = argparse.ArgumentParser(
        description='SubdomainScan - Fast subdomain enumeration tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 subdomainScanner.py -d example.com
  python3 subdomainScanner.py -d example.com -w wordlists/subdomains.txt -t 100
  python3 subdomainScanner.py -d example.com -w wordlists/subdomains.txt --https
        '''
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-w', '--wordlist', default='subdomains.txt', 
                        help='Path to subdomain wordlist (default: subdomains.txt)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                        help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=5,
                        help='Request timeout in seconds (default: 5)')
    parser.add_argument('--https', action='store_true', 
                        help='Scan using HTTPS instead of HTTP')
    
    args = parser.parse_args()
    
    protocol = 'https' if args.https else 'http'
    scanner = SubdomainScanner(
        domain=args.domain,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout
    )
    
    try:
        scanner.scan(protocol=protocol)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
