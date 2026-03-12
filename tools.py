"""
pyknock/tools.py
────────────────
Wrappers around real system pentesting tools.
Each function returns a ToolResult with raw output + parsed metadata.
"""

from __future__ import annotations
import subprocess
import shutil
import socket
import time
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ToolResult:
    tool: str
    command: str
    stdout: str
    stderr: str
    elapsed: float
    success: bool
    metadata: dict = field(default_factory=dict)  # parsed highlights


def _run(cmd: list[str], timeout: int = 90) -> tuple[str, str, bool, float]:
    """Execute a subprocess and return (stdout, stderr, success, elapsed)."""
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout, proc.stderr, proc.returncode == 0, time.time() - t0
    except subprocess.TimeoutExpired:
        return "", f"[timeout after {timeout}s]", False, time.time() - t0
    except FileNotFoundError:
        return "", f"[command not found: {cmd[0]}]", False, time.time() - t0
    except Exception as e:
        return "", str(e), False, time.time() - t0


def _available(binary: str) -> bool:
    return shutil.which(binary) is not None


# ─────────────────────────────────────────────────────────────
# Individual tool wrappers
# ─────────────────────────────────────────────────────────────

def ping_host(target: str) -> ToolResult:
    """ICMP ping — check host reachability."""
    cmd = ["ping", "-c", "4", "-W", "2", target]
    stdout, stderr, ok, elapsed = _run(cmd, timeout=15)
    meta: dict = {}
    if "bytes from" in stdout:
        meta["alive"] = True
        m = re.search(r"min/avg/max.*?([\d.]+)/([\d.]+)/([\d.]+)", stdout)
        if m:
            meta["avg_ms"] = m.group(2)
    else:
        meta["alive"] = False
    return ToolResult("ping", " ".join(cmd), stdout, stderr, elapsed, ok, meta)


def resolve_dns(target: str) -> ToolResult:
    """Resolve DNS — IP addresses, MX, NS records."""
    results = []
    meta: dict = {"records": []}

    for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        if _available("dig"):
            cmd = ["dig", "+short", rtype, target]
            stdout, _, _, _ = _run(cmd, 10)
            if stdout.strip():
                meta["records"].append({"type": rtype, "value": stdout.strip()})
                results.append(f"[{rtype}]\n{stdout.strip()}")
        else:
            try:
                ips = socket.getaddrinfo(target, None)
                for r in ips:
                    meta["records"].append({"type": "A", "value": r[4][0]})
                    results.append(f"[A] {r[4][0]}")
                break
            except Exception as e:
                results.append(f"resolve error: {e}")

    combined = "\n".join(results)
    return ToolResult("dns", f"dig {target} (A/MX/NS/TXT)", combined, "", 0.5, bool(results), meta)


def whois_lookup(target: str) -> ToolResult:
    """WHOIS registrar/org lookup."""
    if not _available("whois"):
        return ToolResult("whois", f"whois {target}", "", "whois not installed", 0, False)
    cmd = ["whois", target]
    stdout, stderr, ok, elapsed = _run(cmd, 20)
    meta: dict = {}
    for key, pattern in [
        ("registrar",     r"(?:Registrar|registrar):\s*(.+)"),
        ("org",           r"(?:Org(?:anization)?|org):\s*(.+)"),
        ("creation_date", r"(?:Creation Date|created):\s*(.+)"),
        ("expiry_date",   r"(?:Expir\w+ Date|expires):\s*(.+)"),
        ("name_servers",  r"Name Server:\s*(.+)"),
    ]:
        m = re.search(pattern, stdout, re.IGNORECASE)
        if m:
            meta[key] = m.group(1).strip()
    return ToolResult("whois", " ".join(cmd), stdout[:3000], stderr, elapsed, ok, meta)


def nmap_quick(target: str) -> ToolResult:
    """Fast nmap port scan — top 1000 ports, version detection."""
    if not _available("nmap"):
        return ToolResult("nmap_quick", f"nmap {target}", "", "nmap not installed", 0, False)
    cmd = ["nmap", "-sV", "--open", "-T4", "--top-ports", "1000", target]
    stdout, stderr, ok, elapsed = _run(cmd, 120)
    meta = _parse_nmap(stdout)
    return ToolResult("nmap_quick", " ".join(cmd), stdout, stderr, elapsed, ok, meta)


def nmap_full(target: str) -> ToolResult:
    """Full nmap scan — all ports, OS detection, scripts."""
    if not _available("nmap"):
        return ToolResult("nmap_full", f"nmap -p- {target}", "", "nmap not installed", 0, False)
    cmd = ["nmap", "-sV", "-sC", "-O", "--open", "-T4", "-p-", target]
    stdout, stderr, ok, elapsed = _run(cmd, 300)
    meta = _parse_nmap(stdout)
    return ToolResult("nmap_full", " ".join(cmd), stdout, stderr, elapsed, ok, meta)


def nmap_vuln_scan(target: str) -> ToolResult:
    """Nmap NSE vuln scripts scan."""
    if not _available("nmap"):
        return ToolResult("nmap_vuln", f"nmap --script vuln {target}", "", "nmap not installed", 0, False)
    cmd = ["nmap", "--script", "vuln,safe,default", "-sV", "-T4", target]
    stdout, stderr, ok, elapsed = _run(cmd, 180)
    meta = _parse_nmap(stdout)
    return ToolResult("nmap_vuln", " ".join(cmd), stdout, stderr, elapsed, ok, meta)


def _parse_nmap(output: str) -> dict:
    """Extract open ports/services from nmap output."""
    meta: dict = {"open_ports": [], "services": [], "os": None}
    for line in output.splitlines():
        m = re.match(r"(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)", line)
        if m:
            port_entry = {
                "port": int(m.group(1)),
                "proto": m.group(2),
                "service": m.group(3),
                "version": m.group(4).strip(),
            }
            meta["open_ports"].append(m.group(1))
            meta["services"].append(port_entry)
    os_m = re.search(r"OS details:\s*(.+)", output)
    if os_m:
        meta["os"] = os_m.group(1).strip()
    return meta


def http_headers(target: str, port: int = 80, https: bool = False) -> ToolResult:
    """Fetch HTTP headers with curl."""
    scheme = "https" if https else "http"
    url = f"{scheme}://{target}:{port}/"
    cmd = ["curl", "-sI", "--max-time", "10", "--insecure", "-L", url]
    stdout, stderr, ok, elapsed = _run(cmd, 20)
    meta: dict = {"headers": {}, "status": None, "server": None}
    for line in stdout.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            meta["status"] = parts[1] if len(parts) > 1 else None
        elif ": " in line:
            k, v = line.split(": ", 1)
            meta["headers"][k.lower()] = v.strip()
    meta["server"] = meta["headers"].get("server", None)
    return ToolResult("http_headers", " ".join(cmd), stdout, stderr, elapsed, ok, meta)


def ssl_check(target: str, port: int = 443) -> ToolResult:
    """Check SSL/TLS certificate info via openssl."""
    if not _available("openssl"):
        return ToolResult("ssl_check", f"openssl s_client {target}:{port}", "", "openssl not found", 0, False)
    cmd = ["openssl", "s_client", "-connect", f"{target}:{port}",
           "-servername", target, "-brief"]
    stdout, stderr, ok, elapsed = _run(cmd, 15)
    combined = stdout + stderr
    meta: dict = {}
    for key, pattern in [
        ("subject",    r"subject=(.+)"),
        ("issuer",     r"issuer=(.+)"),
        ("not_after",  r"notAfter=(.+)"),
        ("protocol",   r"Protocol\s*:\s*(.+)"),
        ("cipher",     r"Cipher\s*:\s*(.+)"),
    ]:
        m = re.search(pattern, combined, re.IGNORECASE)
        if m:
            meta[key] = m.group(1).strip()
    return ToolResult("ssl_check", " ".join(cmd), combined[:2000], "", elapsed, ok, meta)


def traceroute(target: str) -> ToolResult:
    """Traceroute to target."""
    binary = "traceroute" if _available("traceroute") else "tracepath"
    if not _available(binary):
        return ToolResult("traceroute", f"traceroute {target}", "", "traceroute not found", 0, False)
    cmd = [binary, "-m", "15", target]
    stdout, stderr, ok, elapsed = _run(cmd, 30)
    hops = [l for l in stdout.splitlines() if re.match(r"\s*\d+", l)]
    return ToolResult("traceroute", " ".join(cmd), stdout, stderr, elapsed, ok, {"hops": len(hops)})


def banner_grab(target: str, port: int) -> ToolResult:
    """Grab service banner via nc/curl."""
    cmd = ["curl", "-sm", "5", "--insecure", f"telnet://{target}:{port}"]
    stdout, stderr, ok, elapsed = _run(cmd, 10)
    return ToolResult("banner_grab", f"banner grab {target}:{port}", stdout + stderr, "", elapsed, ok,
                      {"banner": (stdout + stderr).strip()[:200]})


def subdomain_enum(domain: str) -> ToolResult:
    """Enumerate subdomains via DNS brute-force (wordlist subset)."""
    common = ["www", "mail", "ftp", "dev", "api", "admin", "vpn", "staging",
              "test", "app", "portal", "secure", "remote", "cdn", "static",
              "blog", "shop", "support", "docs", "git", "jenkins", "jira",
              "smtp", "pop", "imap", "ns1", "ns2", "mx", "webmail"]
    found: list[str] = []
    for sub in common:
        fqdn = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(2)
            ip = socket.gethostbyname(fqdn)
            found.append(f"{fqdn}  →  {ip}")
        except socket.gaierror:
            pass
    output = "\n".join(found) if found else "No subdomains found."
    return ToolResult("subdomain_enum", f"DNS brute {domain}", output, "", 0, True,
                      {"found": found})


def robots_sitemap(target: str, port: int = 80, https: bool = False) -> ToolResult:
    """Fetch robots.txt and sitemap.xml."""
    scheme = "https" if https else "http"
    out_parts = []
    for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]:
        url = f"{scheme}://{target}:{port}{path}"
        cmd = ["curl", "-sL", "--max-time", "8", "--insecure", url]
        stdout, _, _, _ = _run(cmd, 12)
        if stdout.strip() and "404" not in stdout[:50]:
            out_parts.append(f"=== {path} ===\n{stdout[:800]}")
    combined = "\n\n".join(out_parts) if out_parts else "Nothing interesting in robots/sitemap."
    return ToolResult("robots_sitemap", f"GET robots/sitemap on {target}:{port}", combined, "", 0, True, {})


# ─────────────────────────────────────────────────────────────
# Tool registry — AI can reference these by name
# ─────────────────────────────────────────────────────────────

TOOL_REGISTRY: dict[str, dict] = {
    "ping":           {"fn": ping_host,           "args": ["target"],               "desc": "ICMP reachability"},
    "dns":            {"fn": resolve_dns,          "args": ["target"],               "desc": "DNS record enumeration"},
    "whois":          {"fn": whois_lookup,         "args": ["target"],               "desc": "WHOIS registrar lookup"},
    "nmap_quick":     {"fn": nmap_quick,           "args": ["target"],               "desc": "Top-1000 port scan + versions"},
    "nmap_full":      {"fn": nmap_full,            "args": ["target"],               "desc": "All-ports scan + OS + scripts"},
    "nmap_vuln":      {"fn": nmap_vuln_scan,       "args": ["target"],               "desc": "NSE vuln scripts"},
    "http_headers":   {"fn": http_headers,         "args": ["target"],               "desc": "HTTP header analysis"},
    "ssl_check":      {"fn": ssl_check,            "args": ["target"],               "desc": "SSL/TLS certificate check"},
    "traceroute":     {"fn": traceroute,           "args": ["target"],               "desc": "Network path to target"},
    "subdomain_enum": {"fn": subdomain_enum,       "args": ["target"],               "desc": "Subdomain brute-force"},
    "robots_sitemap": {"fn": robots_sitemap,       "args": ["target"],               "desc": "robots.txt / sitemap.xml"},
    "banner_grab":    {"fn": banner_grab,          "args": ["target", "port"],       "desc": "Service banner grab"},
}


def run_tool(name: str, target: str, **kwargs) -> Optional[ToolResult]:
    entry = TOOL_REGISTRY.get(name)
    if not entry:
        return None
    fn = entry["fn"]
    return fn(target, **kwargs)
