Spring Security Bypass Fuzz (Spring Security Killer)
Project Overview
Spring Security Bypass Fuzz is an advanced, automated dictionary generator designed for Red Team operations and security research. It specifically targets authentication bypass vulnerabilities and access control list (ACL) misconfigurations within the Spring Framework ecosystem.

Unlike generic fuzzing tools, this project utilizes context-aware mutation logic based on the parsing discrepancies between Spring MVC, Spring Security, and middleware (e.g., Nginx, Tomcat). It generates high-value payloads aimed at uncovering "Unauth" (unauthorized access) vulnerabilities in modern microservices and API gateways.

Key Features
⚡ Smart Mutation Engine: Instead of random string concatenation, it employs tactic-based mutations targeting known Spring parsing quirks (e.g., AntPathMatcher vs. PathPatternParser).

🎯 Deep Bypass Techniques:

Matrix Variables: Exploits semicolon truncation logic (e.g., /admin;x/users).

Path Normalization: Leverages URL decoding and traversal discrepancies (e.g., ..;/, //, /./).

Whitelist Impersonation: Masquerades sensitive endpoints as static resources (e.g., *.js, *.css, /login) to bypass strict filter chains.

Encoding Confusion: Generates Double-URL and Unicode encoded payloads to evade WAFs.

⚖️ Weighted Sorting Algorithm: Implements a priority queue system that places high-probability bypass payloads at the top of the list, optimizing testing efficiency during limited engagement windows.

🔄 Automated Workflow: Automatically detects target lists, analyzes path sensitivity (e.g., distinguishing Actuator endpoints from standard APIs), and outputs timestamped dictionaries ready for Burp Suite Intruder or ffuf.

Technical Scope
Target Frameworks: Spring Boot 1.x - 3.x, Spring MVC, Spring Cloud Gateway, Shiro.

Vulnerability Coverage:

Broken Access Control (IDOR / Unauth)

CVE-2016-5007 (Path Traversal)

CVE-2022-22978 (Regex Newline Bypass)

CVE-2023-20860 (Double Wildcard Pattern Mismatch)

Context-Path Confusion
