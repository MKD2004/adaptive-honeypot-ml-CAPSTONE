"""
cve_intelligence/config.py

Single source of truth for every constant, threshold, URL, and mapping
used across the CVE Intelligence pipeline.

All secrets are read from environment variables — never hardcoded.
"""
from __future__ import annotations

import os
from typing import Dict, List, Tuple

# ── API Credentials (set via environment) ─────────────────────────────────────
NVD_API_KEY: str | None = os.environ.get("NVD_API_KEY")  # None → unauthenticated (slower)
FIRST_API_KEY: str | None = os.environ.get("FIRST_API_KEY")  # optional

# ── API Base URLs ─────────────────────────────────────────────────────────────
NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL: str = "https://api.first.org/data/1.0/epss"
# Fixed: official GitLab raw endpoint (not the old Offensive Security CSV)
EXPLOITDB_CSV_URL: str = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

# ── NVD Rate-limit delays (seconds) ───────────────────────────────────────────
NVD_DELAY_AUTHENTICATED: float = 0.6    # ≥ 1 request / s with key
NVD_DELAY_UNAUTHENTICATED: float = 6.0  # ≥ 1 request / 6 s without key
NVD_RETRY_SLEEP: float = 30.0           # sleep after 403 / 429
NVD_RESULTS_PER_PAGE: int = 100
NVD_MAX_TOTAL: int = 500

# ── NVD Date Format ───────────────────────────────────────────────────────────
# Fixed: strict UTC with Z designator, no hardcoded timezone offset
NVD_DATE_FORMAT: str = "%Y-%m-%dT%H:%M:%S.000Z"

# ── EPSS ──────────────────────────────────────────────────────────────────────
EPSS_BATCH_SIZE: int = 100

# ── HTTP request defaults ─────────────────────────────────────────────────────
REQUEST_TIMEOUT: int = 30  # seconds

# ── Priority scoring weights ──────────────────────────────────────────────────
W_CVSS: float = 0.40   # normalised CVSS  (0–1)
W_EPSS: float = 0.35   # EPSS score       (0–1)
W_KEV: float = 0.25    # binary KEV bonus

# ── Priority tier thresholds ──────────────────────────────────────────────────
TIER_P1: float = 0.75   # Immediate
TIER_P2: float = 0.55   # High
TIER_P3: float = 0.35   # Medium
# below P3 → P4 Low

# ── Trending window ───────────────────────────────────────────────────────────
TRENDING_WINDOW_DAYS: int = 7

# ── Pipeline defaults ─────────────────────────────────────────────────────────
DEFAULT_LOOKBACK_DAYS: int = 7
TOP_N_RESULTS: int = 20

# ══════════════════════════════════════════════════════════════════════════════
# CWE → Attack Type mapping
# Source: MITRE CWE categories → actionable honeypot attack types
# ══════════════════════════════════════════════════════════════════════════════
CWE_ATTACK_MAP: Dict[str, str] = {
    # ── Injection ──────────────────────────────────────────────────────────────
    "CWE-89":  "SQL Injection",
    "CWE-564": "SQL Injection",
    "CWE-943": "SQL Injection",
    "CWE-79":  "XSS",
    "CWE-80":  "XSS",
    "CWE-83":  "XSS",
    "CWE-87":  "XSS",
    "CWE-116": "XSS",
    "CWE-78":  "Command Injection",
    "CWE-77":  "Command Injection",
    "CWE-88":  "Command Injection",
    "CWE-917": "Expression Injection",
    "CWE-74":  "Injection",
    "CWE-75":  "Injection",
    "CWE-90":  "LDAP Injection",
    "CWE-91":  "XML Injection",
    "CWE-643": "XPath Injection",
    "CWE-113": "HTTP Header Injection",
    # ── Memory Safety ─────────────────────────────────────────────────────────
    "CWE-120": "Buffer Overflow",
    "CWE-121": "Buffer Overflow",
    "CWE-122": "Buffer Overflow",
    "CWE-123": "Buffer Overflow",
    "CWE-124": "Buffer Overflow",
    "CWE-125": "Out-of-Bounds Read",
    "CWE-126": "Buffer Overflow",
    "CWE-127": "Buffer Overflow",
    "CWE-787": "Out-of-Bounds Write",
    "CWE-788": "Out-of-Bounds Access",
    "CWE-119": "Buffer Overflow",
    "CWE-416": "Use-After-Free",
    "CWE-415": "Double Free",
    "CWE-476": "Null Pointer Dereference",
    "CWE-401": "Memory Leak",
    "CWE-824": "Uninitialised Pointer",
    # ── Authentication & Access ───────────────────────────────────────────────
    "CWE-287": "Authentication Bypass",
    "CWE-288": "Authentication Bypass",
    "CWE-306": "Authentication Bypass",
    "CWE-307": "Brute Force",
    "CWE-308": "Brute Force",
    "CWE-309": "Authentication Bypass",
    "CWE-798": "Hardcoded Credentials",
    "CWE-259": "Hardcoded Credentials",
    "CWE-522": "Credential Exposure",
    "CWE-521": "Weak Password Policy",
    "CWE-256": "Credential Exposure",
    "CWE-312": "Credential Exposure",
    # ── Privilege Escalation ──────────────────────────────────────────────────
    "CWE-269": "Privilege Escalation",
    "CWE-266": "Privilege Escalation",
    "CWE-250": "Privilege Escalation",
    "CWE-732": "Insecure Permissions",
    "CWE-284": "Broken Access Control",
    "CWE-285": "Broken Access Control",
    "CWE-863": "Broken Access Control",
    "CWE-862": "Broken Access Control",
    # ── Denial of Service ─────────────────────────────────────────────────────
    "CWE-400":  "DoS",
    "CWE-770":  "DoS",
    "CWE-834":  "DoS",
    "CWE-835":  "DoS",
    "CWE-674":  "DoS",
    "CWE-369":  "DoS",
    "CWE-1333": "ReDoS",
    # ── Path Traversal ────────────────────────────────────────────────────────
    "CWE-22": "Path Traversal",
    "CWE-23": "Path Traversal",
    "CWE-24": "Path Traversal",
    "CWE-25": "Path Traversal",
    "CWE-36": "Path Traversal",
    # ── File Inclusion ────────────────────────────────────────────────────────
    "CWE-98":  "Remote File Inclusion",
    "CWE-829": "Local File Inclusion",
    # ── SSRF / Request Forgery ────────────────────────────────────────────────
    "CWE-918": "SSRF",
    "CWE-352": "CSRF",
    # ── Cryptography ─────────────────────────────────────────────────────────
    "CWE-326": "Weak Cryptography",
    "CWE-327": "Weak Cryptography",
    "CWE-330": "Weak Randomness",
    "CWE-347": "Signature Bypass",
    # ── Deserialisation ───────────────────────────────────────────────────────
    "CWE-502": "Insecure Deserialisation",
    # ── Information Disclosure ────────────────────────────────────────────────
    "CWE-200": "Information Disclosure",
    "CWE-209": "Information Disclosure",
    "CWE-203": "Information Disclosure",
    # ── Race Condition ────────────────────────────────────────────────────────
    "CWE-362": "Race Condition",
    "CWE-366": "Race Condition",
    # ── RCE / Code Execution ──────────────────────────────────────────────────
    "CWE-94": "Code Injection / RCE",
    "CWE-95": "Code Injection / RCE",
    "CWE-96": "Code Injection / RCE",
    "CWE-97": "Code Injection / RCE",
    # ── Open Redirect ─────────────────────────────────────────────────────────
    "CWE-601": "Open Redirect",
    # ── Improper Input Validation ─────────────────────────────────────────────
    "CWE-20": "Improper Input Validation",
}

# ── Keyword fallback map (description → attack type) ─────────────────────────
# Each entry: (list_of_keywords, attack_type_string)
KEYWORD_MAP: List[Tuple[List[str], str]] = [
    (["sql injection", "sqli", "sql query"],                    "SQL Injection"),
    (["cross-site scripting", "xss", "script injection"],       "XSS"),
    (["cross-site request forgery", "csrf"],                    "CSRF"),
    (["server-side request forgery", "ssrf"],                   "SSRF"),
    (["command injection", "os command", "shell injection"],    "Command Injection"),
    (["remote code execution", "rce", "arbitrary code"],        "Code Injection / RCE"),
    (["buffer overflow", "stack overflow", "heap overflow"],    "Buffer Overflow"),
    (["use-after-free", "use after free"],                      "Use-After-Free"),
    (["out-of-bounds", "out of bounds"],                        "Out-of-Bounds Read"),
    (["path traversal", "directory traversal", "../"],          "Path Traversal"),
    (["authentication bypass", "bypass auth", "improper auth"], "Authentication Bypass"),
    (["privilege escalation", "escalate privilege",
      "local privilege"],                                        "Privilege Escalation"),
    (["denial of service", " dos ", "resource exhaustion"],     "DoS"),
    (["information disclosure", "sensitive data",
      "information leak"],                                       "Information Disclosure"),
    (["deserializ", "deserialization"],                         "Insecure Deserialisation"),
    (["hardcoded credential", "hardcoded password",
      "default credential"],                                     "Hardcoded Credentials"),
    (["brute force", "brute-force", "password guess"],          "Brute Force"),
    (["file inclusion", "local file", "remote file"],           "File Inclusion"),
    (["open redirect"],                                         "Open Redirect"),
    (["race condition", "time-of-check"],                       "Race Condition"),
    (["xml external", "xxe"],                                   "XXE"),
    (["cryptograph", "weak cipher", "insecure hash"],           "Weak Cryptography"),
    (["integer overflow", "integer underflow"],                  "Integer Overflow"),
]

# ══════════════════════════════════════════════════════════════════════════════
# Honeypot template library
# ══════════════════════════════════════════════════════════════════════════════
HONEYPOT_TEMPLATES: Dict[str, Dict] = {
    "SQL Injection": {
        "service":           "MySQL / PostgreSQL emulator",
        "ports":             [3306, 5432],
        "endpoint":          "/api/db, /login, /search?q=",
        "interaction_level": "high",
        "emulation":         "Accept SQL queries; log malicious payloads; return fake data rows",
        "fake_data":         "users table with fake PII, products table",
        "detection":         "Log UNION SELECT, SLEEP(), DROP, '--' patterns",
    },
    "XSS": {
        "service":           "Web app with reflected / stored XSS sinks",
        "ports":             [80, 443, 8080],
        "endpoint":          "/search, /comment, /profile?name=",
        "interaction_level": "medium",
        "emulation":         "Reflect <script> payloads in response; capture exfil URLs",
        "fake_data":         "Forum, blog, e-commerce site with user content",
        "detection":         "Log <script>, onerror, javascript: in parameters",
    },
    "Command Injection": {
        "service":           "Linux shell emulator (bash-emulated)",
        "ports":             [22, 80, 8443],
        "endpoint":          "/api/exec, /ping?host=, /cmd?",
        "interaction_level": "high",
        "emulation":         "Execute benign shell; log piped commands; capture reverse-shell attempts",
        "fake_data":         "Fake /etc/passwd, /etc/shadow, crontab",
        "detection":         "Log ;, &&, |, $(), backtick, nc, curl|bash",
    },
    "Code Injection / RCE": {
        "service":           "Application server (PHP/Java/Node emulator)",
        "ports":             [80, 443, 8080, 4848],
        "endpoint":          "/upload, /deserialize, /eval, /execute",
        "interaction_level": "high",
        "emulation":         "Accept payloads; sandbox execution; log all commands",
        "fake_data":         "Web root with fake config files, .env, web.xml",
        "detection":         "Log eval(), exec(), Runtime.exec(), system() calls",
    },
    "Buffer Overflow": {
        "service":           "Vulnerable C daemon emulator",
        "ports":             [21, 23, 110, 9999],
        "endpoint":          "TCP banner / custom protocol handler",
        "interaction_level": "medium",
        "emulation":         "Accept oversized input; log shellcode patterns; simulate crash",
        "fake_data":         "FTP / Telnet service with fake filesystem",
        "detection":         "Log NOP sleds, shellcode signatures, large input packets",
    },
    "Use-After-Free": {
        "service":           "Browser / native app emulator",
        "ports":             [80, 443],
        "endpoint":          "/heap-spray, /object-access",
        "interaction_level": "medium",
        "emulation":         "Simulate memory corruption; log exploitation attempts",
        "fake_data":         "Fake heap layout responses",
        "detection":         "Log heap-spray patterns, memory address probes",
    },
    "Out-of-Bounds Read": {
        "service":           "File parser / media handler emulator",
        "ports":             [80, 443, 8080],
        "endpoint":          "/upload/image, /parse/doc, /api/file",
        "interaction_level": "medium",
        "emulation":         "Accept malformed files; log crash-inducing inputs",
        "fake_data":         "Fake file parsing responses with junk data",
        "detection":         "Log malformed headers, large offset values",
    },
    "Out-of-Bounds Write": {
        "service":           "Memory-safe emulation layer",
        "ports":             [80, 443],
        "endpoint":          "/write-buffer, /parse",
        "interaction_level": "medium",
        "emulation":         "Simulate write errors; log boundary violations",
        "fake_data":         "Fake memory dump responses",
        "detection":         "Log oversized write payloads",
    },
    "Authentication Bypass": {
        "service":           "Web login / OAuth / SSO emulator",
        "ports":             [80, 443, 8443],
        "endpoint":          "/login, /admin, /api/token, /oauth/authorize",
        "interaction_level": "high",
        "emulation":         "Accept all credentials; log bypass techniques; grant fake access",
        "fake_data":         "Admin panel with fake users, config, audit logs",
        "detection":         "Log JWT forging, null byte, type confusion attacks",
    },
    "Brute Force": {
        "service":           "SSH / RDP / Web login emulator",
        "ports":             [22, 3389, 80, 443],
        "endpoint":          "/login, /wp-login.php, SSH banner",
        "interaction_level": "medium",
        "emulation":         "Delay responses; log all credential attempts; allow periodic 'success'",
        "fake_data":         "Fake shell / desktop with decoy files",
        "detection":         "Log IP, username, password combos; detect credential stuffing",
    },
    "Privilege Escalation": {
        "service":           "Linux / Windows OS emulator (low-privilege shell)",
        "ports":             [22, 4444, 5985],
        "endpoint":          "Shell access, WinRM",
        "interaction_level": "high",
        "emulation":         "Provide restricted shell; log sudo, SUID, kernel exploit attempts",
        "fake_data":         "Fake /proc, /sys, kernel version (exploitable-looking)",
        "detection":         "Log sudo abuse, SUID binaries, exploit kit signatures",
    },
    "Broken Access Control": {
        "service":           "REST API emulator",
        "ports":             [80, 443, 8080],
        "endpoint":          "/api/user/{id}, /admin/config, /internal/",
        "interaction_level": "medium",
        "emulation":         "Return fake data for IDOR; log parameter manipulation",
        "fake_data":         "User objects, admin endpoints, config payloads",
        "detection":         "Log IDOR attempts, horizontal privilege escalation",
    },
    "DoS": {
        "service":           "Network service with rate-limiting emulator",
        "ports":             [80, 443, 53, 123],
        "endpoint":          "/* (all paths), DNS, NTP",
        "interaction_level": "low",
        "emulation":         "Accept flood traffic; log source IPs; simulate slow response",
        "fake_data":         "Minimal response payloads",
        "detection":         "Log high-rate requests, amplification patterns, slowloris",
    },
    "ReDoS": {
        "service":           "Regex-heavy web service emulator",
        "ports":             [80, 443],
        "endpoint":          "/validate, /search, /filter",
        "interaction_level": "low",
        "emulation":         "Log inputs with backtracking regex patterns",
        "fake_data":         "Fake validation service",
        "detection":         "Log inputs matching catastrophic backtracking signatures",
    },
    "Path Traversal": {
        "service":           "File server emulator",
        "ports":             [21, 80, 443, 8080],
        "endpoint":          "/download?file=, /view?path=, /static/",
        "interaction_level": "medium",
        "emulation":         "Serve fake sensitive files (/etc/passwd, config); log traversal",
        "fake_data":         "Fake /etc/passwd, /etc/shadow, .env, web.config",
        "detection":         "Log ../, %2e%2e, encoded traversal sequences",
    },
    "Remote File Inclusion": {
        "service":           "PHP web app emulator",
        "ports":             [80, 443],
        "endpoint":          "/index.php?page=, /include?url=",
        "interaction_level": "medium",
        "emulation":         "Simulate remote file fetching; log external URLs",
        "fake_data":         "Fake PHP app with include() paths",
        "detection":         "Log external URL parameters, shell upload attempts",
    },
    "Local File Inclusion": {
        "service":           "PHP web app emulator",
        "ports":             [80, 443],
        "endpoint":          "/index.php?file=, /view?template=",
        "interaction_level": "medium",
        "emulation":         "Return fake file contents; log sensitive file access",
        "fake_data":         "Fake /proc/self/environ, PHP config, log files",
        "detection":         "Log ../, /proc/, /etc/ in file parameters",
    },
    "SSRF": {
        "service":           "Web app with outbound request emulator",
        "ports":             [80, 443, 8080],
        "endpoint":          "/fetch?url=, /proxy?target=, /webhook",
        "interaction_level": "high",
        "emulation":         "Simulate requests to internal IPs; log metadata endpoint probes",
        "fake_data":         "Fake AWS metadata (169.254.169.254), internal services",
        "detection":         "Log internal IP ranges, cloud metadata URLs, localhost",
    },
    "CSRF": {
        "service":           "Web app without CSRF protection",
        "ports":             [80, 443],
        "endpoint":          "/transfer, /settings, /change-password",
        "interaction_level": "low",
        "emulation":         "Accept cross-origin requests; log referer/origin abuse",
        "fake_data":         "Fake account actions, balance transfers",
        "detection":         "Log missing CSRF tokens, cross-origin POST with cookies",
    },
    "Information Disclosure": {
        "service":           "Web/API server with exposed endpoints",
        "ports":             [80, 443, 8080, 9200],
        "endpoint":          "/.git/, /backup/, /swagger-ui, /actuator",
        "interaction_level": "medium",
        "emulation":         "Return fake sensitive data; log enumeration",
        "fake_data":         "Fake .git, config files, API docs with dummy secrets",
        "detection":         "Log directory enumeration, error message probing",
    },
    "Insecure Deserialisation": {
        "service":           "Java / PHP deserialisation endpoint emulator",
        "ports":             [80, 443, 8080, 4848],
        "endpoint":          "/api/data, /viewstate, /cookie (base64)",
        "interaction_level": "high",
        "emulation":         "Accept serialised objects; log gadget chains; sandbox exec",
        "fake_data":         "Fake Java serialised objects, PHP unserialize endpoints",
        "detection":         "Log ysoserial payloads, Java magic bytes (aced 0005)",
    },
    "Hardcoded Credentials": {
        "service":           "IoT / embedded device emulator",
        "ports":             [22, 23, 80, 8080, 554],
        "endpoint":          "/login (admin/admin, root/root, etc.)",
        "interaction_level": "medium",
        "emulation":         "Accept default creds; log attacker source; grant fake shell",
        "fake_data":         "Fake router / camera admin panel",
        "detection":         "Log default credential usage, scanning patterns",
    },
    "Weak Cryptography": {
        "service":           "TLS / crypto service emulator",
        "ports":             [443, 993, 995],
        "endpoint":          "TLS handshake (SSLv3/TLS1.0 enabled)",
        "interaction_level": "low",
        "emulation":         "Negotiate weak ciphers; log downgrade attacks",
        "fake_data":         "Fake SSL certificate, weak cipher suites",
        "detection":         "Log BEAST, POODLE, CRIME, DROWN attack patterns",
    },
    "XXE": {
        "service":           "XML processing endpoint emulator",
        "ports":             [80, 443, 8080],
        "endpoint":          "/xml-parse, /soap, /api/xml",
        "interaction_level": "medium",
        "emulation":         "Process DOCTYPE; return fake entity content; log OOB attempts",
        "fake_data":         "Fake /etc/passwd, internal URL responses",
        "detection":         "Log DOCTYPE, ENTITY, SYSTEM declarations",
    },
    "Race Condition": {
        "service":           "Concurrent transaction emulator",
        "ports":             [80, 443],
        "endpoint":          "/checkout, /transfer, /redeem",
        "interaction_level": "medium",
        "emulation":         "Allow parallel requests; log TOCTOU exploitation patterns",
        "fake_data":         "Fake e-commerce checkout, gift card redemption",
        "detection":         "Log simultaneous identical requests from same session",
    },
    "Open Redirect": {
        "service":           "Web app redirect emulator",
        "ports":             [80, 443],
        "endpoint":          "/redirect?url=, /go?to=, /out?link=",
        "interaction_level": "low",
        "emulation":         "Issue redirects to attacker URLs; log phishing chains",
        "fake_data":         "Fake OAuth flow redirect",
        "detection":         "Log external URLs in redirect parameters",
    },
    "Integer Overflow": {
        "service":           "Network protocol / math service emulator",
        "ports":             [80, 443, 8080],
        "endpoint":          "/calculate, /allocate, /protocol-handler",
        "interaction_level": "medium",
        "emulation":         "Accept large integers; log overflow trigger patterns",
        "fake_data":         "Fake allocation service",
        "detection":         "Log MAX_INT values, wrap-around inputs",
    },
    "Other / Unknown": {
        "service":           "Generic web/network service emulator",
        "ports":             [80, 443, 22, 8080],
        "endpoint":          "/* (generic handler)",
        "interaction_level": "low",
        "emulation":         "Log all requests; fingerprint attacker tools",
        "fake_data":         "Generic response with fake server headers",
        "detection":         "Log all anomalous HTTP / TCP traffic",
    },
}

# ── Emulator config-string templates ─────────────────────────────────────────
CONFIG_STRING_TEMPLATES: Dict[str, str] = {
    "SQL Injection":           'banner="MySQL_5.7" db_emulator="True" log_sqli="True"',
    "XSS":                     'banner="Apache_2.4" reflect_xss="True" log_xss="True"',
    "Command Injection":       'banner="OpenSSH_8.2" shell_emulator="True" log_cmdi="True"',
    "Code Injection / RCE":    'banner="Tomcat_9.0" rce_emulator="True" log_rce="True"',
    "Buffer Overflow":         'banner="vsftpd_2.3.4" overflow_emulator="True"',
    "Use-After-Free":          'banner="Chrome_88" heap_emulator="True"',
    "Out-of-Bounds Read":      'banner="libpng_1.6" oob_emulator="True"',
    "Out-of-Bounds Write":     'banner="libjpeg_9d" oobw_emulator="True"',
    "Authentication Bypass":   'banner="nginx_1.18" auth_bypass="True" log_bypass="True"',
    "Brute Force":             'banner="OpenSSH_7.4" delay_ms="500" log_attempts="True"',
    "Privilege Escalation":    'banner="Linux_4.15" privesc_emulator="True"',
    "Broken Access Control":   'banner="Express_4.18" idor_emulator="True"',
    "DoS":                     'banner="Apache_2.2" rate_limit="False" log_flood="True"',
    "ReDoS":                   'banner="Node_14" regex_emulator="True"',
    "Path Traversal":          'banner="IIS_10.0" traversal_emulator="True" serve_fake_files="True"',
    "Remote File Inclusion":   'banner="PHP_5.6" rfi_emulator="True"',
    "Local File Inclusion":    'banner="PHP_7.4" lfi_emulator="True"',
    "SSRF":                    'banner="Spring_2.5" ssrf_emulator="True" expose_metadata="True"',
    "CSRF":                    'banner="Django_3.2" csrf_disabled="True"',
    "Information Disclosure":  'banner="Apache_2.4" expose_git="True" expose_env="True"',
    "Insecure Deserialisation":'banner="Tomcat_8.5" deserializer="True" log_gadgets="True"',
    "Hardcoded Credentials":   'banner="Hikvision_DVR" default_creds="admin:admin"',
    "Weak Cryptography":       'banner="OpenSSL_1.0.2" allow_sslv3="True" allow_rc4="True"',
    "XXE":                     'banner="Axis_2.0" xxe_emulator="True"',
    "Race Condition":          'banner="Rails_6.0" toctou_emulator="True"',
    "Open Redirect":           'banner="Flask_2.0" open_redirect="True"',
    "Integer Overflow":        'banner="zlib_1.2.11" int_overflow_emulator="True"',
    "Other / Unknown":         'banner="Generic_1.0" generic_emulator="True"',
}
