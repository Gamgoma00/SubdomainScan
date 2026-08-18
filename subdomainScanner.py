#!/usr/bin/env python3
"""
DirScan Pro - High Performance Async Web Directory & File Brute-Forcer
Optimized with Asyncio, Connection Pooling, and Smart Wordlist Handling.
"""

import asyncio
import sys
import argparse
import time
import httpx
from typing import List, Tuple

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class AsyncDirectoryScanner:
    def __init__(self, target_url: str, wordlist: str, concurrency: int = 100, timeout: int = 3, tech_filter: str = None):
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"http://{target_url}"
        self.target_url = target_url.rstrip('/')
        
        self.wordlist = wordlist
        self.concurrency = concurrency
        self.timeout = timeout
        self.tech_filter = tech_filter
        self.discovered_routes = []

    def load_wordlist(self) -> List[str]:
        """تحسين قائمة الكلمات وتصفيتها بناءً على التقنية إن وجدت"""
        try:
            with open(self.wordlist, 'r', errors='ignore') as f:
                routes = []
                for line in f:
                    cleaned = line.strip()
                    if not cleaned or cleaned.startswith('#'):
                        continue
                    
                    # 1. فلترة قائمة الكلمات بناءً على التقنية (Wordlist Optimization)
                    if self.tech_filter and not self._matches_tech(cleaned, self.tech_filter):
                        continue

                    routes.append(cleaned.lstrip('/'))
                return routes
        except FileNotFoundError:
            print(f"{RED}[!] Error: Wordlist '{self.wordlist}' not found.{RESET}")
            sys.exit(1)

    def _matches_tech(self, path: str, tech: str) -> bool:
        """فلترة بسيطة لربط المسارات بالتقنية المحددة"""
        tech = tech.lower()
        if tech in ['wordpress', 'wp'] and ('wp-' in path or 'wordpress' in path):
            return True
        elif tech in ['aspnet', 'asp'] and (path.endswith('.aspx') or path.endswith('.asp')):
            return True
        elif tech in ['php'] and path.endswith('.php'):
            return True
        return False

    async def check_route(self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, path: str) -> Tuple[str, int, int]:
        """فحص المسار بشكل Asynchronous لعدم حجز الـ Threads"""
        url = f"{self.target_url}/{path}"
        async with semaphore:  # التحكم في عدد الطلبات المتزامنة
            try:
                response = await client.get(url, timeout=self.timeout, follow_redirects=False)
                return (url, response.status_code, len(response.content))
            except httpx.RequestError:
                return (url, 0, 0)

    async def scan(self):
        paths = self.load_wordlist()
        if not paths:
            print(f"{RED}[!] Error: Empty or unmatched wordlist.{RESET}")
            return
            
        print(f"{BLUE}[*] Loaded {len(paths)} clean injection paths.{RESET}")
        print(f"{YELLOW}[*] Attacking target base URL: {self.target_url}{RESET}")
        print(f"{YELLOW}[*] Launching Async Engine with concurrency limit: {self.concurrency}...{RESET}\n")
        
        start_time = time.time()
        semaphore = asyncio.Semaphore(self.concurrency)

        # 2. إدارة جلسات الاتصال (Connection Pooling & Keep-Alive)
        limits = httpx.Limits(max_keepalive_connections=self.concurrency, max_connections=self.concurrency)
        
        # 3. استخدام AsyncClient للبرمجة غير المتزامنة (Asynchronous I/O)
        async with httpx.AsyncClient(limits=limits, verify=False) as client:
            tasks = [self.check_route(client, semaphore, p) for p in paths]
            
            completed = 0
            for future in asyncio.as_completed(tasks):
                completed += 1
                url, status, size = await future
                
                if status != 404 and status != 0:
                    self.discovered_routes.append((url, status, size))
                    color = GREEN if status == 200 else YELLOW
                    print(f"{color}[+] FOUND: {url} (Status: {status}) [Size: {size} bytes]{RESET}")
                
                if completed % 500 == 0 or completed == len(paths):
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
    parser = argparse.ArgumentParser(description='DirScan Pro Async')
    parser.add_argument('-u', '--url', required=True, help='Target base URL')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to discovery wordlist')
    parser.add_argument('-c', '--concurrency', type=int, default=100, help='Max concurrent requests')
    parser.add_argument('--timeout', type=int, default=3, help='Timeout in seconds')
    parser.add_argument('--tech', type=str, choices=['wordpress', 'aspnet', 'php'], help='Filter wordlist for specific technology')
    
    args = parser.parse_args()
    
    scanner = AsyncDirectoryScanner(args.url, args.wordlist, args.concurrency, args.timeout, args.tech)
    try:
        asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan manually terminated by user.{RESET}")

if __name__ == "__main__":
    main()
