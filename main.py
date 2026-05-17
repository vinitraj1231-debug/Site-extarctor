# ============================================================
#  Elite Security Audit Bot — main.py
#  Authorized passive reconnaissance only.
#  Never exploits, never bypasses auth, never accesses private systems.
# ============================================================

import asyncio
import aiofiles
import dns.resolver
import ipaddress
import json
import logging
import os
import re
import socket
import sqlite3
import shutil
import ssl
import tempfile
import time
from collections import deque
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import aiohttp
from aiogram import Bot, Dispatcher, Router, F
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    Message,
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    CallbackQuery,
)
from aiogram.utils.keyboard import InlineKeyboardBuilder
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

# ─── CONFIG ────────────────────────────────────────────────
BOT_TOKEN      = os.getenv("BOT_TOKEN", "").strip()
OWNER_ID       = int(os.getenv("OWNER_ID", "0"))
MAX_PAGES      = int(os.getenv("MAX_PAGES", "40"))
MAX_DEPTH      = int(os.getenv("MAX_DEPTH", "3"))
REQUEST_TIMEOUT= int(os.getenv("REQUEST_TIMEOUT", "15"))
DB_PATH        = os.getenv("DB_PATH", "audit.db")

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN missing in .env")

# ─── LOGGING ───────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("audit-bot")

# ─── CONSTANTS ─────────────────────────────────────────────
SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin/login",
    "/dashboard", "/panel", "/cpanel", "/wp-admin",
    "/login", "/signin", "/auth", "/manage", "/backend",
    "/control", "/site/admin", "/admin/index.php",
    "/phpmyadmin", "/pma", "/dbadmin", "/mysql",
]

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local",
    "/.env.production", "/config.php", "/wp-config.php",
    "/database.yml", "/settings.py", "/secrets.yml",
    "/debug", "/test", "/phpinfo.php", "/info.php",
    "/swagger.json", "/swagger.yaml", "/openapi.json",
    "/api-docs", "/api/docs", "/graphql",
    "/backup.zip", "/backup.tar.gz", "/dump.sql",
    "/.DS_Store", "/Thumbs.db", "/web.config",
    "/server-status", "/server-info",
    "/.svn/entries", "/.hg/", "/.bzr/", "/.ssh/id_rsa",
    "/.ssh/id_rsa.pub", "/.ssh/authorized_keys",
    "/.vscode/sftp.json", "/.vscode/settings.json",
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/Dockerfile", "/docker-compose.yml", "/adminer.php",
    "/backup/", "/backups/", "/old/", "/temp/", "/tmp/",
    "/sql.zip", "/db.sql", "/mysql.sql", "/config.js", "/config.json",
    "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php.save",
    "/.aws/credentials", "/.npmrc", "/.python_history",
]

TECH_SIGNATURES = {
    "WordPress":   [r"wp-content", r"wp-includes", r"wordpress"],
    "Laravel":     [r"laravel_session", r"csrf-token", r"XSRF-TOKEN"],
    "React":       [r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"react\.production"],
    "Next.js":     [r"__NEXT_DATA__", r"_next/static"],
    "Vue.js":      [r"__VUE__", r"vue\.runtime"],
    "Nuxt":        [r"__NUXT__", r"nuxt"],
    "Angular":     [r"ng-version", r"angular\.js"],
    "jQuery":      [r"jquery[-\.](\d+\.\d+)"],
    "Bootstrap":   [r"bootstrap\.min\.css", r"bootstrap\.bundle"],
    "Tailwind":    [r"tailwindcss"],
    "Cloudflare":  [r"cf-ray", r"cloudflare"],
    "Nginx":       [r"nginx"],
    "Apache":      [r"apache"],
    "PHP":         [r"x-powered-by.*php", r"\.php"],
    "ASP.NET":     [r"__VIEWSTATE", r"asp\.net"],
    "Django":      [r"csrfmiddlewaretoken", r"django"],
    "Express":     [r"x-powered-by.*express"],
    "Google Analytics": [r"google-analytics\.com", r"gtag\("],
    "Hotjar":      [r"hotjar"],
    "Sentry":      [r"sentry\.io", r"@sentry"],
    "Firebase":    [r"firebaseapp\.com", r"firebase"],
    "Stripe":      [r"stripe\.com/v3"],
    "Razorpay":    [r"razorpay"],
    "Drupal":      [r"Drupal\.settings", r"sites/all", r"drupal\.js"],
    "Joomla":      [r"joomla!", r"Joomla\.getOptions"],
    "Magento":     [r"magento", r"mage/"],
    "Shopify":     [r"shopify", r"cdn\.shopify\.com"],
    "Ghost":       [r"ghost-sdk", r"ghost\.org"],
    "Gatsby":      [r"gatsby-init", r"gatsby-app"],
    "Hugo":        [r"gohugo\.io"],
    "Jekyll":      [r"jekyll rb", r"jekyll-gist"],
    "Vite":        [r"@vite/client"],
    "Webpack":     [r"webpack"],
    "Babel":       [r"babel-polyfill"],
    "Materialize": [r"materialize\.min\.css", r"materialize\.js"],
    "Bulma":       [r"bulma\.min\.css"],
    "Semantic UI": [r"semantic\.min\.css", r"semantic\.js"],
    "UIKit":       [r"uikit\.min\.css", r"uikit\.js"],
    "Font Awesome":[r"font-awesome", r"fa-solid"],
    "Lodash":      [r"lodash\.min\.js"],
    "Moment.js":   [r"moment\.min\.js"],
    "Docker":      [r"docker"],
    "Kubernetes":  [r"kubernetes", r"k8s"],
    "Jenkins":     [r"jenkins"],
}

JS_SECRET_PATTERNS = {
    "Google API Key":      r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase Config":     r"firebase.*apiKey.*AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key":      r"AKIA[0-9A-Z]{16}",
    "JWT Token":           r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Stripe Publishable":  r"pk_(live|test)_[0-9a-zA-Z]{24,}",
    "Razorpay Key":        r"rzp_(live|test)_[A-Za-z0-9]{14,}",
    "Bearer Token":        r"[Bb]earer [A-Za-z0-9\-._~+/]{20,}",
    "Basic Auth in URL":   r"https?://[^:]+:[^@]+@",
    "Private Key Header":  r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "Mapbox Token":        r"pk\.eyJ1IjoiW[A-Za-z0-9\-_]+",
    "Twilio":              r"SK[0-9a-fA-F]{32}",
    "Slack Token":         r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "GitHub Token":        r"ghp_[a-zA-Z0-9]{36}",
    "Mailgun API Key":     r"key-[0-9a-zA-Z]{32}",
    "SendGrid API Key":    r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Heroku API Key":      r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Square Access Token": r"sqOatp-[0-9A-Za-z\-_]{22}",
    "Connection String":   r"(mongodb|postgres|mysql|redis|mongodb\+srv):\/\/[^\"'\s]+",
}

OWASP_MAP = {
    "missing_csp":              ("A05:2021 Security Misconfiguration", "Medium"),
    "missing_x_frame":          ("A05:2021 Security Misconfiguration", "Medium"),
    "missing_hsts":             ("A02:2021 Cryptographic Failures", "Medium"),
    "missing_content_type":     ("A05:2021 Security Misconfiguration", "Low"),
    "open_directory":           ("A05:2021 Security Misconfiguration", "High"),
    "exposed_git":              ("A05:2021 Security Misconfiguration", "High"),
    "exposed_env":              ("A02:2021 Cryptographic Failures", "Critical"),
    "exposed_config":           ("A02:2021 Cryptographic Failures", "High"),
    "exposed_backup":           ("A05:2021 Security Misconfiguration", "High"),
    "swagger_exposed":          ("A01:2021 Broken Access Control", "Medium"),
    "graphql_exposed":          ("A01:2021 Broken Access Control", "Medium"),
    "debug_exposed":            ("A05:2021 Security Misconfiguration", "High"),
    "weak_cors":                ("A01:2021 Broken Access Control", "High"),
    "js_secret_leak":           ("A02:2021 Cryptographic Failures", "Critical"),
    "admin_panel_found":        ("A01:2021 Broken Access Control", "Medium"),
    "clickjacking":             ("A05:2021 Security Misconfiguration", "Medium"),
    "ssl_expired":              ("A02:2021 Cryptographic Failures", "Critical"),
    "ssl_self_signed":          ("A02:2021 Cryptographic Failures", "High"),
    "info_disclosure_header":   ("A05:2021 Security Misconfiguration", "Low"),
    "php_info_exposed":         ("A05:2021 Security Misconfiguration", "High"),
    "exposed_ssh_key":          ("A02:2021 Cryptographic Failures", "Critical"),
    "exposed_docker_file":      ("A05:2021 Security Misconfiguration", "Medium"),
    "exposed_source_meta":      ("A05:2021 Security Misconfiguration", "Medium"),
    "exposed_npmrc":            ("A02:2021 Cryptographic Failures", "High"),
    "exposed_aws_creds":        ("A02:2021 Cryptographic Failures", "Critical"),
}

SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
    "Info":     "🔵",
}

URL_PATTERN = re.compile(
    r"""(?:https?://[^\s"'<>{}|\\^`\[\]]+|/[A-Za-z0-9_\-./?=&%#]+)""",
    re.IGNORECASE,
)

# ─── DATABASE ──────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            username    TEXT,
            target      TEXT NOT NULL,
            started_at  TEXT NOT NULL,
            finished_at TEXT,
            page_count  INTEGER DEFAULT 0,
            finding_count INTEGER DEFAULT 0,
            report_json TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_scan(user_id: int, username: str, target: str, data: dict) -> int:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO scans (user_id, username, target, started_at, finished_at,
                           page_count, finding_count, report_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        username or "",
        target,
        data.get("started_at", ""),
        data.get("finished_at", ""),
        data.get("page_count", 0),
        data.get("finding_count", 0),
        json.dumps(data, ensure_ascii=False),
    ))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_history(user_id: int, limit: int = 10) -> List[dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT id, target, started_at, page_count, finding_count
        FROM scans WHERE user_id = ?
        ORDER BY id DESC LIMIT ?
    """, (user_id, limit))
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "target": r[1], "started_at": r[2],
             "pages": r[3], "findings": r[4]} for r in rows]


def get_scan_json(scan_id: int, user_id: int) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT report_json FROM scans WHERE id = ? AND user_id = ?",
              (scan_id, user_id))
    row = c.fetchone()
    conn.close()
    if row and row[0]:
        return json.loads(row[0])
    return None


# ─── DATACLASSES ───────────────────────────────────────────
@dataclass
class Finding:
    key: str
    title: str
    description: str
    owasp: str = ""
    severity: str = "Info"
    url: str = ""
    evidence: str = ""


@dataclass
class PageResult:
    url: str
    status: int
    title: str = ""
    content_type: str = ""
    tech: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    assets: List[str] = field(default_factory=list)
    js_endpoints: List[str] = field(default_factory=list)
    missing_headers: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


# ─── UTILITIES ─────────────────────────────────────────────
def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError("Invalid URL")
    return urlunparse(parsed._replace(fragment=""))


def is_public_target(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host in {"localhost", "127.0.0.1", "::1"}:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local)
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                ip = ipaddress.ip_address(info[4][0])
                if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                    return False
        except Exception:
            pass
    return True


def same_host(base: str, target: str) -> bool:
    return (urlparse(base).hostname or "").lower() == (urlparse(target).hostname or "").lower()


def clean_url(url: str) -> str:
    return urlunparse(urlparse(url)._replace(fragment=""))


def owasp_info(key: str) -> Tuple[str, str]:
    return OWASP_MAP.get(key, ("General Finding", "Info"))


def finding(key: str, title: str, desc: str, url: str = "", evidence: str = "") -> Finding:
    owasp, sev = owasp_info(key)
    return Finding(key=key, title=title, description=desc,
                   owasp=owasp, severity=sev, url=url, evidence=evidence)


# ─── TECH DETECTION ────────────────────────────────────────
def extract_tech(html: str, headers: Dict[str, str]) -> List[str]:
    blob = (html or "") + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
    found = []
    for tech, patterns in TECH_SIGNATURES.items():
        for p in patterns:
            if re.search(p, blob, re.IGNORECASE):
                found.append(tech)
                break
    return sorted(set(found))


# ─── HEADER ANALYSIS ───────────────────────────────────────
def analyze_headers(headers: Dict[str, str], url: str) -> Tuple[List[str], List[Finding]]:
    keys = {k.lower() for k in headers}
    missing = [h for h in SECURITY_HEADERS if h not in keys]
    findings = []

    if "content-security-policy" not in keys:
        findings.append(finding("missing_csp",
            "Missing Content-Security-Policy",
            "CSP header absent. XSS and data injection risks increase without it.",
            url))
    if "x-frame-options" not in keys:
        findings.append(finding("clickjacking",
            "Clickjacking Risk (Missing X-Frame-Options)",
            "Page can be embedded in iframes. Potential clickjacking attack surface.",
            url))
    if "strict-transport-security" not in keys and url.startswith("https://"):
        findings.append(finding("missing_hsts",
            "Missing HSTS Header",
            "HSTS not set. Downgrade attacks to HTTP are possible.",
            url))
    if "x-content-type-options" not in keys:
        findings.append(finding("missing_content_type",
            "Missing X-Content-Type-Options",
            "MIME-type sniffing attacks possible without this header.",
            url))

    # Info disclosure
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/"]):
        findings.append(finding("info_disclosure_header",
            "Server Version Disclosure",
            f"Server header reveals version: {server}. Reduces attacker's recon effort.",
            url, evidence=server))
    if powered:
        findings.append(finding("info_disclosure_header",
            "X-Powered-By Disclosure",
            f"Technology stack exposed: {powered}",
            url, evidence=powered))

    # Weak CORS
    cors = headers.get("access-control-allow-origin", "")
    if cors == "*":
        findings.append(finding("weak_cors",
            "Wildcard CORS Policy",
            "Access-Control-Allow-Origin: * allows any origin to read responses.",
            url, evidence=cors))

    return missing, findings


# ─── JS ANALYSIS ───────────────────────────────────────────
def extract_links_and_assets(base_url: str, html: str) -> Tuple[List[str], List[str], str]:
    soup = BeautifulSoup(html, "lxml")
    links, assets = set(), set()
    for tag in soup.find_all(True):
        for attr in ("href", "src", "action", "data-src", "data-url"):
            val = tag.get(attr)
            if not val:
                continue
            abs_url = clean_url(urljoin(base_url, val))
            if abs_url.startswith(("http://", "https://")):
                if same_host(base_url, abs_url):
                    links.add(abs_url)
            if any(abs_url.lower().endswith(e) for e in
                   (".js", ".css", ".png", ".jpg", ".jpeg",
                    ".webp", ".gif", ".svg", ".ico", ".woff2")):
                assets.add(abs_url)
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    return sorted(links), sorted(assets), title


def extract_js_endpoints(js_text: str, base_url: str) -> List[str]:
    results = set()
    for m in URL_PATTERN.findall(js_text or ""):
        candidate = m.strip().rstrip(");,\"'`")
        if candidate.startswith(("http://", "https://")):
            if same_host(base_url, candidate):
                results.add(clean_url(candidate))
        elif candidate.startswith("/"):
            abs_url = clean_url(urljoin(base_url, candidate))
            if same_host(base_url, abs_url):
                results.add(abs_url)
    # API-style paths
    for m in re.findall(
        r"""["'`](\/(?:api|graphql|admin|v\d|rest|gql|auth|oauth)[^"'`\s]+)["'`]""",
        js_text or "", re.IGNORECASE
    ):
        abs_url = clean_url(urljoin(base_url, m))
        if same_host(base_url, abs_url):
            results.add(abs_url)
    return sorted(results)


def scan_js_secrets(js_text: str, js_url: str) -> List[Finding]:
    findings = []
    for label, pattern in JS_SECRET_PATTERNS.items():
        match = re.search(pattern, js_text or "")
        if match:
            evidence = match.group(0)
            # Redact middle portion for safety
            if len(evidence) > 20:
                evidence = evidence[:8] + "***" + evidence[-4:]
            findings.append(finding(
                "js_secret_leak",
                f"Potential Secret in JS: {label}",
                f"Pattern matching '{label}' found in JavaScript file. Review immediately.",
                js_url,
                evidence=evidence,
            ))
    return findings


# ─── SSL ANALYSIS ──────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBIND", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9000: "Portainer", 27017: "MongoDB"
}


async def scan_port(ip: str, port: int) -> Optional[int]:
    try:
        conn = asyncio.open_connection(ip, port)
        _, writer = await asyncio.wait_for(conn, timeout=2.0)
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None


async def port_scan(hostname: str) -> List[Tuple[int, str]]:
    try:
        ip = socket.gethostbyname(hostname)
    except:
        return []

    tasks = [scan_port(ip, port) for port in COMMON_PORTS.keys()]
    results = await asyncio.gather(*tasks)
    open_ports = [(p, COMMON_PORTS[p]) for p in results if p is not None]
    return open_ports


async def extract_site_code(root_url: str, pages_data: List[dict]) -> str:
    """Download and zip site frontend code"""
    temp_dir = tempfile.mkdtemp(prefix="site_extract_")
    # Use a single session for all requests
    async with aiohttp.ClientSession() as session:
        try:
            for page in pages_data:
                parsed = urlparse(page["url"])
                # Create local path based on URL path
                local_path = parsed.path
                if not local_path or local_path.endswith("/"):
                    local_path += "index.html"
                if local_path.startswith("/"):
                    local_path = local_path[1:]

                full_local_path = os.path.join(temp_dir, local_path)
                os.makedirs(os.path.dirname(full_local_path), exist_ok=True)

                try:
                    async with session.get(page["url"]) as resp:
                        if resp.status == 200:
                            content = await resp.read()
                            async with aiofiles.open(full_local_path, mode='wb') as f:
                                await f.write(content)
                except Exception as e:
                    log.debug("Failed to extract page %s: %s", page["url"], e)

            # Also download assets
            all_assets = set()
            for page in pages_data:
                all_assets.update(page.get("assets", []))

            for asset_url in all_assets:
                try:
                    parsed_asset = urlparse(asset_url)
                    local_asset_path = parsed_asset.path
                    if local_asset_path.startswith("/"):
                        local_asset_path = local_asset_path[1:]

                    full_asset_path = os.path.join(temp_dir, local_asset_path)
                    os.makedirs(os.path.dirname(full_asset_path), exist_ok=True)

                    async with session.get(asset_url) as resp:
                        if resp.status == 200:
                            content = await resp.read()
                            async with aiofiles.open(full_asset_path, mode='wb') as f:
                                await f.write(content)
                except Exception as e:
                    log.debug("Failed to extract asset %s: %s", asset_url, e)

            # Use a safe way to create a temp zip file
            fd, zip_path_base = tempfile.mkstemp(suffix="")
            os.close(fd)
            zip_final_path = shutil.make_archive(zip_path_base, 'zip', temp_dir)
            return zip_final_path
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


async def get_dns_records(domain: str) -> Dict[str, List[str]]:
    records = {}
    types = ["A", "MX", "TXT", "NS", "CNAME", "SOA"]
    for t in types:
        try:
            answers = dns.resolver.resolve(domain, t)
            records[t] = [str(r) for r in answers]
        except:
            continue
    return records


def detect_waf(headers: Dict[str, str], html: str) -> Optional[str]:
    waf_sigs = {
        "Cloudflare": ["cf-ray", "__cfduid", "cloudflare-nginx", "cloudflare"],
        "Akamai": ["akamai-x-cache", "akamai-ghost", "akamai"],
        "Sucuri": ["x-sucuri-id", "sucuri", "sucuri.net"],
        "Imperva": ["x-iinfo", "incap_ses", "visid_incap", "incapsula"],
        "F5 BIG-IP": ["f5_cspm", "bigipserver", "f5"],
        "AWS WAF": ["x-amz-cf-id", "aws-waf"],
        "ModSecurity": ["mod_security", "modsecurity"],
    }

    blob = (html or "").lower()
    header_str = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()

    for waf, sigs in waf_sigs.items():
        for sig in sigs:
            if sig in header_str or sig in blob:
                return waf
    return None


async def get_subdomains(domain: str) -> List[str]:
    """Passive subdomain enumeration using crt.sh"""
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    timeout = aiohttp.ClientTimeout(total=20)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get("common_name", "")
                        if name:
                            # May contain wildcards or multiple names separated by \n
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if sub.endswith(domain) and "*" not in sub:
                                    subdomains.add(sub)
                        alt_names = entry.get("name_value", "")
                        if alt_names:
                            for sub in alt_names.split("\n"):
                                sub = sub.strip().lower()
                                if sub.endswith(domain) and "*" not in sub:
                                    subdomains.add(sub)
    except Exception as e:
        log.debug("Subdomain enum error for %s: %s", domain, e)
    return sorted(list(subdomains))


async def check_ssl(hostname: str) -> List[Finding]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def _check():
            conn = ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=10),
                server_hostname=hostname,
            )
            cert = conn.getpeercert()
            conn.close()
            return cert

        cert = await loop.run_in_executor(None, _check)
        if cert:
            expire_str = cert.get("notAfter", "")
            if expire_str:
                expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_dt - datetime.utcnow()).days
                if days_left < 0:
                    findings.append(finding("ssl_expired",
                        "SSL Certificate Expired",
                        f"Certificate expired {abs(days_left)} days ago.",
                        f"https://{hostname}", evidence=expire_str))
                elif days_left < 30:
                    findings.append(finding("ssl_expired",
                        f"SSL Certificate Expires Soon ({days_left} days)",
                        "Certificate nearing expiry. Renew immediately.",
                        f"https://{hostname}", evidence=expire_str))
    except ssl.SSLCertVerificationError:
        findings.append(finding("ssl_self_signed",
            "SSL Certificate Invalid / Self-Signed",
            "Certificate failed validation. May be self-signed or from untrusted CA.",
            f"https://{hostname}"))
    except Exception as e:
        log.debug("SSL check error for %s: %s", hostname, e)
    return findings


# ─── HTTP FETCH ────────────────────────────────────────────
async def fetch(session: aiohttp.ClientSession, url: str
                ) -> Tuple[int, Dict[str, str], str]:
    try:
        async with session.get(url, allow_redirects=True) as resp:
            text = await resp.text(errors="ignore")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, text
    except asyncio.TimeoutError:
        return 0, {}, ""
    except Exception as e:
        log.debug("fetch error %s: %s", url, e)
        return 0, {}, ""


async def probe(session: aiohttp.ClientSession, url: str) -> Tuple[int, Dict[str, str]]:
    try:
        async with session.get(url, allow_redirects=False) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers
    except Exception:
        return 0, {}


# ─── SENSITIVE PATH SCANNER ────────────────────────────────
async def scan_sensitive_paths(session: aiohttp.ClientSession,
                                root_url: str) -> List[Finding]:
    findings = []
    base = "{scheme}://{netloc}".format(**urlparse(root_url)._asdict())

    tasks = [(path, probe(session, base + path)) for path in SENSITIVE_PATHS]
    results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

    for (path, _), result in zip(tasks, results):
        if isinstance(result, Exception):
            continue
        status, hdrs = result
        if status in (200, 206):
            full_url = base + path
            if ".git" in path:
                findings.append(finding("exposed_git",
                    "Exposed .git Directory",
                    "Git repository data publicly accessible. Source code may be downloadable.",
                    full_url))
            elif ".env" in path or "secrets" in path:
                findings.append(finding("exposed_env",
                    "Exposed Environment File",
                    "Environment file is publicly accessible. May contain DB passwords, API keys.",
                    full_url))
            elif path.endswith((".zip", ".tar.gz", ".sql")):
                findings.append(finding("exposed_backup",
                    "Exposed Backup File",
                    "Backup or dump file publicly accessible.",
                    full_url))
            elif "swagger" in path or "openapi" in path or "api-docs" in path:
                findings.append(finding("swagger_exposed",
                    "API Documentation Exposed",
                    "Swagger/OpenAPI docs are public. Review if this is intentional.",
                    full_url))
            elif "graphql" in path:
                findings.append(finding("graphql_exposed",
                    "GraphQL Endpoint Exposed",
                    "GraphQL endpoint reachable. Check for introspection queries.",
                    full_url))
            elif "phpinfo" in path or "info.php" in path:
                findings.append(finding("php_info_exposed",
                    "PHP Info Page Exposed",
                    "phpinfo() page leaks server config, PHP version, loaded modules.",
                    full_url))
            elif path in ("/debug", "/test"):
                findings.append(finding("debug_exposed",
                    "Debug / Test Endpoint Exposed",
                    "Debug or test route accessible in production.",
                    full_url))
            elif "config" in path or "database" in path or "settings" in path:
                findings.append(finding("exposed_config",
                    "Exposed Config File",
                    "Configuration file is publicly accessible.",
                    full_url))
            elif "id_rsa" in path:
                findings.append(finding("exposed_ssh_key",
                    "Exposed SSH Private Key",
                    "SSH private key is publicly accessible. Severe security risk.",
                    full_url))
            elif "Dockerfile" in path or "docker-compose" in path:
                findings.append(finding("exposed_docker_file",
                    "Exposed Docker Configuration",
                    "Docker configuration files can reveal internal infrastructure details.",
                    full_url))
            elif "package.json" in path or "composer.json" in path:
                findings.append(finding("exposed_source_meta",
                    "Exposed Dependency File",
                    "Package manifest files reveal technology stack and versions.",
                    full_url))
            elif ".npmrc" in path:
                findings.append(finding("exposed_npmrc",
                    "Exposed .npmrc File",
                    "May contain npm registry tokens or auth credentials.",
                    full_url))
            elif ".aws/credentials" in path:
                findings.append(finding("exposed_aws_creds",
                    "Exposed AWS Credentials",
                    "AWS credentials file is publicly accessible.",
                    full_url))

        # Open directory listing
        if status == 200 and "text/html" in hdrs.get("content-type", ""):
            # We already have html from status, minimal check by path
            if path.endswith("/"):
                findings.append(finding("open_directory",
                    "Possible Open Directory Listing",
                    f"Directory index may be enabled at {path}",
                    base + path))

    return findings


# ─── ADMIN PANEL DISCOVERY ─────────────────────────────────
async def scan_admin_paths(session: aiohttp.ClientSession,
                            root_url: str) -> List[Finding]:
    findings = []
    base = "{scheme}://{netloc}".format(**urlparse(root_url)._asdict())
    tasks = [probe(session, base + path) for path in ADMIN_PATHS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for path, result in zip(ADMIN_PATHS, results):
        if isinstance(result, Exception):
            continue
        status, _ = result
        if status in (200, 301, 302, 403):
            label = "Accessible" if status in (200,) else f"Redirects/Forbidden ({status})"
            findings.append(finding("admin_panel_found",
                f"Admin Path Found: {path} [{label}]",
                f"Admin or management path detected at {path}. Verify access controls.",
                base + path, evidence=f"HTTP {status}"))
    return findings


# ─── CORE CRAWLER ──────────────────────────────────────────
async def crawl_site(root_url: str,
                     progress_cb=None,
                     max_pages: int = MAX_PAGES,
                     max_depth: int = MAX_DEPTH) -> dict:

    started_at = datetime.utcnow().isoformat()
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    ua = "Mozilla/5.0 (compatible; SecurityAuditBot/2.0; +authorized-passive-audit)"
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    results: List[PageResult] = []
    visited: Set[str] = set()
    queue = deque([(root_url, 0)])
    all_findings: List[Finding] = []

    async with aiohttp.ClientSession(
        timeout=timeout,
        headers={"User-Agent": ua},
        connector=connector
    ) as session:

        # robots.txt
        robots_text, _ = "", {}
        status, _, robots_text = await fetch(session, urljoin(root_url, "/robots.txt"))

        # sitemap.xml
        _, _, sitemap_text = await fetch(session, urljoin(root_url, "/sitemap.xml"))
        if sitemap_text and "<urlset" in sitemap_text.lower():
            locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", sitemap_text, re.IGNORECASE)
            for loc in locs[:100]:
                loc = clean_url(loc.strip())
                if loc.startswith(("http://", "https://")) and same_host(root_url, loc):
                    queue.appendleft((loc, 0))

        if progress_cb:
            await progress_cb("🔍 Crawling pages...")

        # Main crawl loop
        while queue and len(results) < max_pages:
            current, depth = queue.popleft()
            current = clean_url(current)
            if current in visited:
                continue
            visited.add(current)

            status, resp_headers, html = await fetch(session, current)
            if status == 0:
                continue

            content_type = resp_headers.get("content-type", "")
            missing_h, hdr_findings = analyze_headers(resp_headers, current)

            page = PageResult(
                url=current,
                status=status,
                content_type=content_type,
                missing_headers=missing_h,
                findings=hdr_findings,
            )

            if "text/html" in content_type.lower():
                links, assets, title = extract_links_and_assets(current, html)
                page.links  = links
                page.assets = assets
                page.title  = title
                page.tech   = extract_tech(html, resp_headers)

                # Scan HTML content for secrets
                html_secrets = scan_js_secrets(html, current)
                page.findings.extend(html_secrets)

                # Check open directory listing in body
                if html and re.search(r"Index of /|Directory listing", html, re.IGNORECASE):
                    page.findings.append(finding("open_directory",
                        "Open Directory Listing",
                        "Web server is showing directory contents.",
                        current))

                if depth < max_depth:
                    for link in links:
                        if same_host(root_url, link) and link not in visited:
                            queue.append((link, depth + 1))

                # JS analysis
                js_urls = [u for u in assets if u.lower().endswith(".js")]
                for js_url in js_urls[:15]:
                    _, _, js_text = await fetch(session, js_url)
                    if js_text:
                        eps = extract_js_endpoints(js_text, current)
                        page.js_endpoints.extend(eps)
                        page.findings.extend(scan_js_secrets(js_text, js_url))

                page.js_endpoints = sorted(set(page.js_endpoints))
            else:
                page.tech = extract_tech("", resp_headers)

            results.append(page)
            all_findings.extend(page.findings)

        if progress_cb:
            await progress_cb("🔐 Scanning sensitive paths...")

        # Sensitive path scan
        sens_findings = await scan_sensitive_paths(session, root_url)
        all_findings.extend(sens_findings)

        if progress_cb:
            await progress_cb("🚪 Checking admin panels...")

        # Admin path scan
        admin_findings = await scan_admin_paths(session, root_url)
        all_findings.extend(admin_findings)

    if progress_cb:
        await progress_cb("🔒 Checking SSL certificate...")

    # SSL check
    hostname = urlparse(root_url).hostname or ""
    if hostname and root_url.startswith("https://"):
        ssl_findings = await check_ssl(hostname)
        all_findings.extend(ssl_findings)

    # Aggregate
    all_tech = sorted(set(x for p in results for x in p.tech))
    all_links = sorted(set(x for p in results for x in p.links))
    all_assets = sorted(set(x for p in results for x in p.assets))
    all_js_eps = sorted(set(x for p in results for x in p.js_endpoints))

    findings_list = [asdict(f) for f in all_findings]
    severity_counts = {}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    finished_at = datetime.utcnow().isoformat()

    return {
        "target":          root_url,
        "started_at":      started_at,
        "finished_at":     finished_at,
        "page_count":      len(results),
        "finding_count":   len(findings_list),
        "tech":            all_tech,
        "links":           all_links,
        "assets":          all_assets,
        "js_endpoints":    all_js_eps,
        "robots_txt":      bool(robots_text),
        "sitemap_xml":     bool(sitemap_text and "<urlset" in sitemap_text.lower()),
        "findings":        findings_list,
        "severity_counts": severity_counts,
        "pages":           [asdict(p) for p in results],
    "subdomains":      await get_subdomains(hostname),
    "dns":             await get_dns_records(hostname),
    "open_ports":      await port_scan(hostname),
    "waf":             detect_waf(resp_headers, html) if results else None,
    }


# ─── REPORT BUILDERS ───────────────────────────────────────
def build_text_report(data: dict) -> str:
    lines = []
    sep = "=" * 60
    lines.append(sep)
    lines.append("  ELITE SECURITY AUDIT REPORT")
    lines.append(sep)
    lines.append(f"Target    : {data['target']}")
    lines.append(f"WAF       : {data.get('waf') or 'None detected'}")
    lines.append(f"Started   : {data['started_at']}")
    lines.append(f"Finished  : {data['finished_at']}")
    lines.append(f"Pages     : {data['page_count']}")
    lines.append(f"Findings  : {data['finding_count']}")
    sc = data.get("severity_counts", {})
    lines.append(
        f"Severity  : Critical={sc.get('Critical',0)} High={sc.get('High',0)} "
        f"Medium={sc.get('Medium',0)} Low={sc.get('Low',0)}"
    )
    lines.append("")
    lines.append("DNS RECORDS:")
    dns_data = data.get("dns", {})
    if dns_data:
        for rt, rv in dns_data.items():
            lines.append(f"  {rt}: {', '.join(rv)}")
    else:
        lines.append("  None found")

    lines.append("")
    lines.append("SUBDOMAINS:")
    subs = data.get("subdomains", [])
    if subs:
        lines.append(", ".join(subs[:50]))
        if len(subs) > 50: lines.append(f" (+{len(subs)-50} more)")
    else:
        lines.append("  None found")

    lines.append("")
    lines.append("OPEN PORTS:")
    ports = data.get("open_ports", [])
    if ports:
        for p, s in ports:
            lines.append(f"  {p} ({s})")
    else:
        lines.append("  None found")

    lines.append("")
    lines.append("TECHNOLOGIES DETECTED:")
    lines.append(", ".join(data["tech"]) if data["tech"] else "  None")
    lines.append("")
    lines.append(f"robots.txt  : {'Found' if data.get('robots_txt') else 'Not found'}")
    lines.append(f"sitemap.xml : {'Found' if data.get('sitemap_xml') else 'Not found'}")
    lines.append("")
    lines.append("FINDINGS:")
    lines.append("-" * 60)

    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    findings = data.get("findings", [])
    for sev in severity_order:
        sev_findings = [f for f in findings if f.get("severity") == sev]
        if not sev_findings:
            continue
        emoji = SEVERITY_EMOJI.get(sev, "•")
        lines.append(f"\n{emoji} {sev.upper()} ({len(sev_findings)})")
        for f in sev_findings:
            lines.append(f"  [{f['title']}]")
            lines.append(f"    URL     : {f.get('url','')}")
            lines.append(f"    OWASP   : {f.get('owasp','')}")
            lines.append(f"    Detail  : {f.get('description','')}")
            if f.get("evidence"):
                lines.append(f"    Evidence: {f['evidence']}")
    lines.append("")
    lines.append("-" * 60)
    lines.append("JS ENDPOINTS DISCOVERED:")
    for ep in data.get("js_endpoints", [])[:50]:
        lines.append(f"  {ep}")
    lines.append("")
    lines.append("CRAWLED PAGES:")
    for p in data.get("pages", []):
        lines.append(f"  [{p['status']}] {p['url']}")
        if p.get("title"):
            lines.append(f"         Title: {p['title']}")
    lines.append("")
    lines.append(sep)
    lines.append("DISCLAIMER: This report was generated for authorized security")
    lines.append("auditing purposes only. Unauthorized use is prohibited.")
    lines.append(sep)
    return "\n".join(lines)


def build_text_report_old(data: dict) -> str:
    lines = []
    sep = "=" * 60
    lines.append(sep)
    lines.append("  ELITE SECURITY AUDIT REPORT")
    lines.append(sep)
    lines.append(f"Target    : {data['target']}")
    lines.append(f"Started   : {data['started_at']}")
    lines.append(f"Finished  : {data['finished_at']}")
    lines.append(f"Pages     : {data['page_count']}")
    lines.append(f"Findings  : {data['finding_count']}")
    sc = data.get("severity_counts", {})
    lines.append(
        f"Severity  : Critical={sc.get('Critical',0)} High={sc.get('High',0)} "
        f"Medium={sc.get('Medium',0)} Low={sc.get('Low',0)}"
    )
    lines.append("")
    lines.append("TECHNOLOGIES DETECTED:")
    lines.append(", ".join(data["tech"]) if data["tech"] else "  None")
    lines.append("")
    lines.append(f"robots.txt  : {'Found' if data.get('robots_txt') else 'Not found'}")
    lines.append(f"sitemap.xml : {'Found' if data.get('sitemap_xml') else 'Not found'}")
    lines.append("")
    lines.append("FINDINGS:")
    lines.append("-" * 60)

    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    findings = data.get("findings", [])
    for sev in severity_order:
        sev_findings = [f for f in findings if f.get("severity") == sev]
        if not sev_findings:
            continue
        emoji = SEVERITY_EMOJI.get(sev, "•")
        lines.append(f"\n{emoji} {sev.upper()} ({len(sev_findings)})")
        for f in sev_findings:
            lines.append(f"  [{f['title']}]")
            lines.append(f"    URL     : {f.get('url','')}")
            lines.append(f"    OWASP   : {f.get('owasp','')}")
            lines.append(f"    Detail  : {f.get('description','')}")
            if f.get("evidence"):
                lines.append(f"    Evidence: {f['evidence']}")
    lines.append("")
    lines.append("-" * 60)
    lines.append("JS ENDPOINTS DISCOVERED:")
    for ep in data.get("js_endpoints", [])[:50]:
        lines.append(f"  {ep}")
    lines.append("")
    lines.append("CRAWLED PAGES:")
    for p in data.get("pages", []):
        lines.append(f"  [{p['status']}] {p['url']}")
        if p.get("title"):
            lines.append(f"         Title: {p['title']}")
    lines.append("")
    lines.append(sep)
    lines.append("DISCLAIMER: This report was generated for authorized security")
    lines.append("auditing purposes only. Unauthorized use is prohibited.")
    lines.append(sep)
    return "\n".join(lines)


def build_html_report(data: dict) -> str:
    sc = data.get("severity_counts", {})
    findings = data.get("findings", [])
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]

    def severity_color(sev):
        return {
            "Critical": "#ff2d55", "High": "#ff6b35",
            "Medium": "#ffd700", "Low": "#4cd964", "Info": "#5ac8fa"
        }.get(sev, "#fff")

    finding_rows = ""
    for sev in severity_order:
        sev_findings = [f for f in findings if f.get("severity") == sev]
        for f in sev_findings:
            color = severity_color(sev)
            finding_rows += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge" style="background:{color};color:#000">{sev}</span>
                    <strong>{f['title']}</strong>
                </div>
                <div class="finding-body">
                    <p>{f.get('description','')}</p>
                    <table>
                        <tr><td><b>URL</b></td><td><code>{f.get('url','—')}</code></td></tr>
                        <tr><td><b>OWASP</b></td><td>{f.get('owasp','—')}</td></tr>
                        {"<tr><td><b>Evidence</b></td><td><code>" + f['evidence'] + "</code></td></tr>" if f.get('evidence') else ""}
                    </table>
                </div>
            </div>"""

    tech_badges = "".join(
        f'<span class="tech-badge">{t}</span>' for t in data.get("tech", [])
    ) or "<span style='color:#888'>None detected</span>"

    pages_rows = "".join(
        f"<tr><td>{p['status']}</td><td><a href='{p['url']}' target='_blank'>{p['url']}</a></td>"
        f"<td>{p.get('title','')}</td></tr>"
        for p in data.get("pages", [])
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Audit — {data['target']}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d0d0d; color: #e0e0e0; font-family: 'Courier New', monospace; padding: 24px; }}
  h1 {{ color: #00e5ff; font-size: 1.8rem; margin-bottom: 8px; }}
  h2 {{ color: #00e5ff; font-size: 1.1rem; margin: 24px 0 12px; border-bottom: 1px solid #333; padding-bottom: 4px; }}
  .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 16px 0; }}
  .meta-card {{ background: #1a1a2e; border: 1px solid #333; border-radius: 8px; padding: 12px; }}
  .meta-card span {{ font-size: 0.75rem; color: #888; display: block; }}
  .meta-card strong {{ font-size: 1.1rem; color: #fff; }}
  .severity-row {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; }}
  .sev-box {{ padding: 10px 20px; border-radius: 8px; text-align: center; }}
  .finding-card {{ background: #1a1a2e; border-left: 4px solid #444; border-radius: 6px; margin: 10px 0; }}
  .finding-header {{ padding: 10px 14px; display: flex; align-items: center; gap: 10px; }}
  .finding-body {{ padding: 0 14px 12px; font-size: 0.88rem; color: #ccc; }}
  .finding-body table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  .finding-body td {{ padding: 4px 8px; border-bottom: 1px solid #222; vertical-align: top; }}
  .finding-body td:first-child {{ color: #888; width: 80px; }}
  .badge {{ padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; }}
  .tech-badge {{ background: #1e3a5f; color: #5ac8fa; padding: 4px 12px; border-radius: 20px;
                 font-size: 0.8rem; margin: 4px; display: inline-block; }}
  table.pages-table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
  table.pages-table th {{ background: #1a1a2e; color: #888; padding: 8px; text-align: left; }}
  table.pages-table td {{ padding: 6px 8px; border-bottom: 1px solid #1e1e1e; }}
  table.pages-table a {{ color: #5ac8fa; text-decoration: none; }}
  code {{ background: #111; padding: 2px 6px; border-radius: 4px; font-size: 0.82rem; word-break: break-all; }}
  .disclaimer {{ background: #1a0a0a; border: 1px solid #552222; padding: 12px; border-radius: 6px;
                 color: #ff6b6b; font-size: 0.8rem; margin-top: 24px; }}
</style>
</head>
<body>
<h1>⚡ Elite Security Audit Report</h1>
<div style="color:#888;font-size:0.85rem">Generated: {data['finished_at']} UTC</div>

<div class="meta-grid">
  <div class="meta-card"><span>Target</span><strong>{data['target']}</strong></div>
  <div class="meta-card"><span>Pages Crawled</span><strong>{data['page_count']}</strong></div>
  <div class="meta-card"><span>Total Findings</span><strong>{data['finding_count']}</strong></div>
  <div class="meta-card"><span>Technologies</span><strong>{len(data.get('tech',[]))}</strong></div>
</div>

<div class="severity-row">
  <div class="sev-box" style="background:#3d0015;color:#ff2d55">🔴 Critical: {sc.get('Critical',0)}</div>
  <div class="sev-box" style="background:#3d1500;color:#ff6b35">🟠 High: {sc.get('High',0)}</div>
  <div class="sev-box" style="background:#3d3500;color:#ffd700">🟡 Medium: {sc.get('Medium',0)}</div>
  <div class="sev-box" style="background:#0a3d0a;color:#4cd964">🟢 Low: {sc.get('Low',0)}</div>
</div>

<h2>Technologies Detected</h2>
<div>{tech_badges}</div>

<h2>Findings</h2>
{finding_rows if finding_rows else '<p style="color:#888">No findings.</p>'}

<h2>Crawled Pages</h2>
<table class="pages-table">
  <tr><th>Status</th><th>URL</th><th>Title</th></tr>
  {pages_rows}
</table>

<div class="disclaimer">
⚠️ DISCLAIMER: This report was generated for <strong>authorized security auditing purposes only</strong>.
Unauthorized use of this tool against systems you do not own or have explicit written permission to test
is illegal and may violate the IT Act 2000 (India) and other applicable laws.
</div>
</body>
</html>"""


# ─── TELEGRAM SUMMARY ──────────────────────────────────────
def build_telegram_summary(data: dict) -> str:
    sc = data.get("severity_counts", {})
    tech_str = ", ".join(data["tech"][:8]) if data["tech"] else "None"
    crit = sc.get("Critical", 0)
    high = sc.get("High", 0)
    med  = sc.get("Medium", 0)
    low  = sc.get("Low", 0)

    # Top findings preview
    top = []
    for sev in ["Critical", "High", "Medium"]:
        for f in data.get("findings", []):
            if f["severity"] == sev and len(top) < 5:
                emoji = SEVERITY_EMOJI.get(sev, "•")
                top.append(f"{emoji} {f['title']}")

    top_str = "\n".join(top) if top else "✅ No high-severity findings"

    return (
        f"🎯 <b>Scan Complete</b>\n"
        f"<code>{data['target']}</code>\n\n"
        f"📊 <b>Summary</b>\n"
        f"• WAF: <b>{data.get('waf') or 'None'}</b>\n"
        f"• Pages crawled: <b>{data['page_count']}</b>\n"
        f"• Total findings: <b>{data['finding_count']}</b>\n"
        f"• 🔴 Critical: <b>{crit}</b>  🟠 High: <b>{high}</b>\n"
        f"• 🟡 Medium: <b>{med}</b>  🟢 Low: <b>{low}</b>\n\n"
        f"🛠 <b>Technologies</b>\n{tech_str}\n\n"
        f"🌐 <b>Recon:</b>\n"
        f"• Subdomains: <b>{len(data.get('subdomains', []))}</b>\n"
        f"• Open Ports: <b>{len(data.get('open_ports', []))}</b>\n\n"
        f"🔍 <b>Top Findings</b>\n{top_str}\n\n"
        f"📎 Full report attached below."
    )


# ─── ROUTER + HANDLERS ─────────────────────────────────────
router = Router()

# Active scans tracker (user_id -> bool)
active_scans: Set[int] = set()


def main_keyboard():
    builder = InlineKeyboardBuilder()
    builder.button(text="📜 History", callback_data="history")
    builder.button(text="ℹ️ Help",    callback_data="help")
    builder.button(text="📦 Extract Source", callback_data="extract_info")
    builder.adjust(2)
    return builder.as_markup()


def scan_result_keyboard(scan_id: int):
    builder = InlineKeyboardBuilder()
    builder.button(text="📥 Export JSON", callback_data=f"export_json:{scan_id}")
    builder.button(text="🌐 HTML Report", callback_data=f"export_html:{scan_id}")
    builder.adjust(2)
    return builder.as_markup()


@router.message(CommandStart())
async def start_handler(message: Message):
    await message.answer(
        "⚡ <b>Elite Security Audit Bot</b>\n\n"
        "Authorized passive security reconnaissance tool.\n\n"
        "<b>Commands:</b>\n"
        "/scan &lt;url&gt; — Full security audit\n"
        "/extract &lt;url&gt; — Extract site code\n"
        "/subdomains &lt;url&gt; — Subdomain enum\n"
        "/ports &lt;url&gt; — Port scan\n"
        "/dns &lt;url&gt; — DNS recon\n"
        "/headers &lt;url&gt; — Headers only\n"
        "/tech &lt;url&gt; — Tech detection\n"
        "/js &lt;url&gt; — JS endpoint analysis\n"
        "/admin &lt;url&gt; — Admin panel probe\n"
        "/history — Past scans\n"
        "/export &lt;id&gt; — Export scan by ID\n\n"
        "⚠️ Only scan sites you own or have written permission to test.",
        parse_mode="HTML",
        reply_markup=main_keyboard(),
    )


@router.message(Command("scan"))
async def scan_handler(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply("Usage: /scan https://example.com")
        return

    user_id = message.from_user.id
    if user_id in active_scans:
        await message.reply("⏳ You already have a scan running. Please wait.")
        return

    try:
        target = normalize_url(args[1].strip())
        if not is_public_target(target):
            await message.reply("🚫 Blocked: Private/local addresses not allowed.")
            return
    except Exception:
        await message.reply("❌ Invalid URL.")
        return

    # Disclaimer
    disclaimer_kb = InlineKeyboardBuilder()
    disclaimer_kb.button(text="✅ I have authorization — Proceed", callback_data=f"confirm_scan:{target}")
    disclaimer_kb.button(text="❌ Cancel", callback_data="cancel_scan")
    disclaimer_kb.adjust(1)

    await message.reply(
        f"⚠️ <b>Authorization Required</b>\n\n"
        f"Target: <code>{target}</code>\n\n"
        f"By proceeding you confirm that you are the owner or have <b>explicit written permission</b> "
        f"to perform a security audit on this target.\n\n"
        f"Unauthorized scanning may violate laws including IT Act 2000 (India) and CFAA (USA).",
        parse_mode="HTML",
        reply_markup=disclaimer_kb.as_markup(),
    )


@router.callback_query(F.data.startswith("confirm_scan:"))
async def confirm_scan_callback(call: CallbackQuery):
    target = call.data.split(":", 1)[1]
    user_id = call.from_user.id
    username = call.from_user.username or ""

    if user_id in active_scans:
        await call.answer("Scan already running!", show_alert=True)
        return

    active_scans.add(user_id)
    await call.message.edit_text(
        f"🚀 <b>Scan Started</b>\n<code>{target}</code>\n\n⏳ Initializing...",
        parse_mode="HTML",
    )

    status_msg = call.message

    async def progress(msg: str):
        try:
            await status_msg.edit_text(
                f"🚀 <b>Scanning:</b> <code>{target}</code>\n\n{msg}",
                parse_mode="HTML",
            )
        except Exception:
            pass

    try:
        data = await crawl_site(target, progress_cb=progress)
        scan_id = save_scan(user_id, username, target, data)

        summary = build_telegram_summary(data)
        await status_msg.edit_text(summary, parse_mode="HTML",
                                   reply_markup=scan_result_keyboard(scan_id))

        # Send text report as file
        report_text = build_text_report(data)
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt",
                                         encoding="utf-8", prefix="audit_") as f:
            f.write(report_text)
            txt_path = f.name

        await call.message.answer_document(
            FSInputFile(txt_path, filename=f"audit_{urlparse(target).hostname}.txt"),
            caption="📄 Text report",
        )

    except Exception as e:
        log.exception("Scan failed")
        await status_msg.edit_text(f"❌ Scan failed: {e}")
    finally:
        active_scans.discard(user_id)


@router.callback_query(F.data == "cancel_scan")
async def cancel_scan_callback(call: CallbackQuery):
    await call.message.edit_text("❌ Scan cancelled.")


@router.callback_query(F.data.startswith("export_json:"))
async def export_json_callback(call: CallbackQuery):
    scan_id = int(call.data.split(":")[1])
    data = get_scan_json(scan_id, call.from_user.id)
    if not data:
        await call.answer("Scan not found.", show_alert=True)
        return
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json",
                                     encoding="utf-8", prefix="audit_") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        path = f.name
    await call.message.answer_document(
        FSInputFile(path, filename=f"audit_{scan_id}.json"),
        caption="📦 JSON export",
    )
    await call.answer()


@router.callback_query(F.data.startswith("export_html:"))
async def export_html_callback(call: CallbackQuery):
    scan_id = int(call.data.split(":")[1])
    data = get_scan_json(scan_id, call.from_user.id)
    if not data:
        await call.answer("Scan not found.", show_alert=True)
        return
    html = build_html_report(data)
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html",
                                     encoding="utf-8", prefix="audit_") as f:
        f.write(html)
        path = f.name
    await call.message.answer_document(
        FSInputFile(path, filename=f"audit_{scan_id}.html"),
        caption="🌐 HTML report — open in browser",
    )
    await call.answer()


@router.callback_query(F.data == "history")
async def history_callback(call: CallbackQuery):
    await _send_history(call.message, call.from_user.id)
    await call.answer()


@router.callback_query(F.data == "help")
async def help_callback(call: CallbackQuery):
    await call.message.answer(
        "<b>Commands</b>\n\n"
        "/scan &lt;url&gt; — Full passive security audit\n"
        "/extract &lt;url&gt; — Extract site code & assets\n"
        "/subdomains &lt;url&gt; — Subdomain enumeration\n"
        "/ports &lt;url&gt; — Common port scanner\n"
        "/dns &lt;url&gt; — DNS reconnaissance\n"
        "/headers &lt;url&gt; — Security header check only\n"
        "/tech &lt;url&gt; — Technology fingerprinting\n"
        "/js &lt;url&gt; — JavaScript endpoint extractor\n"
        "/admin &lt;url&gt; — Admin path discovery\n"
        "/history — Your scan history\n"
        "/export &lt;id&gt; — Export a past scan\n\n"
        "All scans are <b>passive</b>. No exploitation, no auth bypass.",
        parse_mode="HTML",
    )
    await call.answer()


@router.callback_query(F.data == "extract_info")
async def extract_info_callback(call: CallbackQuery):
    await call.message.answer(
        "📦 <b>Site Code Extraction</b>\n\n"
        "Use <code>/extract &lt;url&gt;</code> to download the frontend source code (HTML, JS, CSS) of a website.\n\n"
        "The bot will crawl the site and bundle all discovered assets into a ZIP file for you.",
        parse_mode="HTML",
    )
    await call.answer()


@router.message(Command("history"))
async def history_handler(message: Message):
    await _send_history(message, message.from_user.id)


async def _send_history(message: Message, user_id: int):
    rows = get_history(user_id)
    if not rows:
        await message.answer("📭 No scans yet. Use /scan &lt;url&gt; to start.",
                             parse_mode="HTML")
        return
    lines = ["📜 <b>Your Recent Scans</b>\n"]
    for r in rows:
        lines.append(
            f"<b>#{r['id']}</b> — <code>{r['target']}</code>\n"
            f"  {r['started_at'][:19]} | {r['pages']} pages | {r['findings']} findings\n"
            f"  /export {r['id']}"
        )
    await message.answer("\n".join(lines), parse_mode="HTML")


@router.message(Command("export"))
async def export_handler(message: Message):
    args = message.text.split()
    if len(args) < 2 or not args[1].isdigit():
        await message.reply("Usage: /export &lt;scan_id&gt;", parse_mode="HTML")
        return
    scan_id = int(args[1])
    data = get_scan_json(scan_id, message.from_user.id)
    if not data:
        await message.reply("❌ Scan not found or not yours.")
        return

    builder = InlineKeyboardBuilder()
    builder.button(text="📥 JSON", callback_data=f"export_json:{scan_id}")
    builder.button(text="🌐 HTML", callback_data=f"export_html:{scan_id}")
    builder.adjust(2)
    await message.reply(
        f"Export scan #{scan_id}: <code>{data['target']}</code>",
        parse_mode="HTML",
        reply_markup=builder.as_markup(),
    )


@router.message(Command("headers"))
async def headers_handler(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply("Usage: /headers https://example.com")
        return
    try:
        target = normalize_url(args[1].strip())
        if not is_public_target(target):
            await message.reply("🚫 Private address blocked.")
            return
    except Exception:
        await message.reply("❌ Invalid URL.")
        return

    wait = await message.reply("⏳ Checking headers...")
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        status, resp_headers, _ = await fetch(session, target)
    if status == 0:
        await wait.edit_text("❌ Could not reach target.")
        return

    missing, findings = analyze_headers(resp_headers, target)
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]

    lines = [f"🔐 <b>Header Analysis</b>\n<code>{target}</code>\n"]
    lines.append(f"Status: <b>{status}</b>\n")

    if missing:
        lines.append("❌ <b>Missing Security Headers:</b>")
        for h in missing:
            lines.append(f"  • {h}")
    else:
        lines.append("✅ All key security headers present.")

    if findings:
        lines.append("\n<b>Findings:</b>")
        for f_ in findings:
            emoji = SEVERITY_EMOJI.get(f_["severity"], "•")
            lines.append(f"{emoji} {f_['title']}")

    await wait.edit_text("\n".join(lines), parse_mode="HTML")


@router.message(Command("tech"))
async def tech_handler(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply("Usage: /tech https://example.com")
        return
    try:
        target = normalize_url(args[1].strip())
        if not is_public_target(target):
            await message.reply("🚫 Private address blocked.")
            return
    except Exception:
        await message.reply("❌ Invalid URL.")
        return

    wait = await message.reply("⏳ Detecting technologies...")
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        status, resp_headers, html = await fetch(session, target)
    if status == 0:
        await wait.edit_text("❌ Could not reach target.")
        return

    tech = extract_tech(html, resp_headers)
    lines = [f"🛠 <b>Technology Detection</b>\n<code>{target}</code>\n"]
    if tech:
        for t in tech:
            lines.append(f"  ✅ {t}")
    else:
        lines.append("  ⚠️ No known technologies detected.")
    await wait.edit_text("\n".join(lines), parse_mode="HTML")


@router.message(Command("js"))
async def js_handler(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply("Usage: /js https://example.com")
        return
    try:
        target = normalize_url(args[1].strip())
        if not is_public_target(target):
            await message.reply("🚫 Private address blocked.")
            return
    except Exception:
        await message.reply("❌ Invalid URL.")
        return

    wait = await message.reply("⏳ Fetching and analyzing JS files...")
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        _, _, html = await fetch(session, target)
        _, assets, _ = extract_links_and_assets(target, html)
        js_urls = [u for u in assets if u.endswith(".js")][:10]
        all_eps, all_secrets = [], []
        for js_url in js_urls:
            _, _, js_text = await fetch(session, js_url)
            if js_text:
                eps = extract_js_endpoints(js_text, target)
                secs = scan_js_secrets(js_text, js_url)
                all_eps.extend(eps)
                all_secrets.extend(secs)

    lines = [f"🔎 <b>JS Analysis</b>\n<code>{target}</code>\n"]
    lines.append(f"JS files found: <b>{len(js_urls)}</b>")
    lines.append(f"Endpoints extracted: <b>{len(set(all_eps))}</b>")

    if all_secrets:
        lines.append(f"\n⚠️ <b>Potential Secrets ({len(all_secrets)}):</b>")
        for s in all_secrets[:10]:
            emoji = SEVERITY_EMOJI.get(s["severity"], "•")
            lines.append(f"{emoji} {s['title']}")
    else:
        lines.append("\n✅ No obvious secrets detected in JS.")

    if all_eps:
        lines.append(f"\n<b>Sample Endpoints:</b>")
        for ep in sorted(set(all_eps))[:15]:
            lines.append(f"  <code>{ep}</code>")

    await wait.edit_text("\n".join(lines), parse_mode="HTML")


@router.message(Command("subdomains"))
async def subdomains_handler(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply("Usage: /subdomains example.com")
        return

    target = args[1].strip()
    # Strip scheme if present
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path.split("/")[0]

    wait = await message.reply(f"🔍 Enumerating subdomains for <code>{domain}</code>...")
    subs = await get_subdomains(domain)

    if not subs:
        await wait.edit_text(f"❌ No subdomains found for <code>{domain}</code>.")
        return

    lines = [f"🌐 <b>Subdomains found for {domain}:</b>\n"]
    for s in subs[:100]: # Limit to 100 for telegram
        lines.append(f"• <code>{s}</code>")

    if len(subs) > 100:
        lines.append(f"\n<i>... and {len(subs) - 100} more.</i>")

    await wait.edit_text("\n".join(lines), parse_mode="HTML")


@router.message(Command("ports"))
async def ports_handler(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply("Usage: /ports https://example.com")
        return
    try:
        target = normalize_url(args[1].strip())
        hostname = urlparse(target).hostname
    except Exception:
        await message.reply("❌ Invalid URL.")
        return

    wait = await message.reply(f"🔌 Scanning common ports for <code>{hostname}</code>...")
    open_ports = await port_scan(hostname)

    if not open_ports:
        await wait.edit_text(f"✅ No common open ports found for <code>{hostname}</code>.")
        return

    lines = [f"🔌 <b>Open Ports found for {hostname}:</b>\n"]
    for port, service in open_ports:
        lines.append(f"• <code>{port}</code> ({service})")

    await wait.edit_text("\n".join(lines), parse_mode="HTML")


@router.message(Command("extract"))
async def extract_handler(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply("Usage: /extract https://example.com")
        return

    try:
        target = normalize_url(args[1].strip())
    except Exception:
        await message.reply("❌ Invalid URL.")
        return

    wait = await message.reply(f"📦 <b>Extracting site code:</b> <code>{target}</code>\n\n⏳ This may take a while...")

    try:
        # We need a crawl first to find assets
        data = await crawl_site(target, max_pages=15) # Limit for extract command
        zip_file = await extract_site_code(target, data["pages"])

        await message.reply_document(
            FSInputFile(zip_file, filename=f"source_{urlparse(target).hostname}.zip"),
            caption=f"✅ Extracted source for {target}\nPages: {len(data['pages'])}"
        )
        if os.path.exists(zip_file):
            os.remove(zip_file)
        await wait.delete()
    except Exception as e:
        log.exception("Extraction failed")
        await wait.edit_text(f"❌ Extraction failed: {e}")


@router.message(Command("dns"))
async def dns_handler(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply("Usage: /dns example.com")
        return

    target = args[1].strip()
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path.split("/")[0]

    wait = await message.reply(f"🔍 Fetching DNS records for <code>{domain}</code>...")
    records = await get_dns_records(domain)

    if not records:
        await wait.edit_text(f"❌ No DNS records found for <code>{domain}</code>.")
        return

    lines = [f"📋 <b>DNS Records for {domain}:</b>\n"]
    for rtype, rvals in records.items():
        lines.append(f"<b>{rtype}:</b>")
        for val in rvals:
            lines.append(f"  • <code>{val}</code>")
        lines.append("")

    await wait.edit_text("\n".join(lines), parse_mode="HTML")


@router.message(Command("admin"))
async def admin_handler(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply("Usage: /admin https://example.com")
        return
    try:
        target = normalize_url(args[1].strip())
        if not is_public_target(target):
            await message.reply("🚫 Private address blocked.")
            return
    except Exception:
        await message.reply("❌ Invalid URL.")
        return

    wait = await message.reply("⏳ Probing admin paths...")
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        findings = await scan_admin_paths(session, target)

    lines = [f"🚪 <b>Admin Path Probe</b>\n<code>{target}</code>\n"]
    if findings:
        for f_ in findings:
            emoji = SEVERITY_EMOJI.get(f_["severity"], "•")
            lines.append(f"{emoji} {f_['title']}")
            lines.append(f"   <code>{f_['url']}</code>")
    else:
        lines.append("✅ No common admin paths found.")

    await wait.edit_text("\n".join(lines), parse_mode="HTML")


@router.message(Command("report"))
async def report_handler(message: Message):
    await message.reply(
        "Use /history to see scan IDs, then /export &lt;id&gt; to download.",
        parse_mode="HTML",
    )


# ─── MAIN ──────────────────────────────────────────────────
async def main():
    init_db()
    log.info("Database initialized: %s", DB_PATH)
    bot = Bot(token=BOT_TOKEN, parse_mode="HTML")
    dp  = Dispatcher()
    dp.include_router(router)
    log.info("Bot starting...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
