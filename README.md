# ⚡ PyKnock — Autonomous AI Pentesting Agent

```
 ██████╗ ██╗   ██╗██╗  ██╗███╗   ██╗ ██████╗  ██████╗██╗  ██╗
 ██╔══██╗╚██╗ ██╔╝██║ ██╔╝████╗  ██║██╔═══██╗██╔════╝██║ ██╔╝
 ██████╔╝ ╚████╔╝ █████╔╝ ██╔██╗ ██║██║   ██║██║     █████╔╝ 
 ██╔═══╝   ╚██╔╝  ██╔═██╗ ██║╚██╗██║██║   ██║██║     ██╔═██╗ 
 ██║        ██║   ██║  ██╗██║ ╚████║╚██████╔╝╚██████╗██║  ██╗
 ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝
   ⚡ Autonomous AI Pentesting Agent  |  Powered by Claude
```

PyKnock is an **autonomous pentesting agent** that uses Claude AI to iteratively
scan, enumerate, and analyse a target — so you can sit back and watch the terminal go wham.

---

## 🚀 Quickstart

```bash
# Install dependencies
pip install anthropic rich

# Install system tools (Debian/Ubuntu)
sudo apt install nmap dnsutils whois openssl

# Run a scan
export ANTHROPIC_API_KEY=sk-ant-...
python pyknock.py -t scanme.nmap.org

# Or pass the key inline
python pyknock.py -t 192.168.1.1 -k sk-ant-... --max-iter 8
```

---

## 🧠 How It Works

```
┌─────────────────────────────────────────────────────┐
│                    PyKnock Loop                     │
│                                                     │
│  1. Auto-run initial recon (ping, dns, whois)       │
│       ↓                                             │
│  2. Claude analyses ALL results so far              │
│       ↓                                             │
│  3. Claude picks next 1-3 tools to run              │
│       ↓                                             │
│  4. Tools execute, output fed back to Claude        │
│       ↓                                             │
│  5. Claude surfaces findings with severity          │
│       ↓                                             │
│  6. Repeat until done or max-iterations hit         │
│       ↓                                             │
│  7. Save Markdown + JSON reports                    │
└─────────────────────────────────────────────────────┘
```

---

## 🔧 Tool Arsenal (12 tools)

| Tool | Description |
|------|-------------|
| `ping` | ICMP reachability + latency |
| `dns` | A/AAAA/MX/NS/TXT record enumeration |
| `whois` | Registrar, org, creation/expiry dates |
| `nmap_quick` | Top-1000 ports, service version detection |
| `nmap_full` | All 65535 ports + OS detection + NSE scripts |
| `nmap_vuln` | NSE vulnerability scripts |
| `http_headers` | HTTP response headers, server banner |
| `ssl_check` | TLS cert validity, cipher, expiry |
| `traceroute` | Network path mapping |
| `subdomain_enum` | DNS brute-force (30 common prefixes) |
| `robots_sitemap` | robots.txt, sitemap.xml, security.txt |
| `banner_grab` | Raw service banner on any port |

---

## 📁 Project Structure

```
pyknock/
├── pyknock.py     — CLI entry point, argument parsing, legal consent
├── agent.py       — Claude AI orchestration loop, decision engine
├── tools.py       — All pentesting tool wrappers + ToolResult dataclass
├── display.py     — Rich terminal UI (banners, spinners, tables, panels)
└── report.py      — Markdown + JSON report generator
```

---

## 📋 CLI Options

```
  -t, --target     Target hostname or IP  (required)
  -k, --api-key    Anthropic API key      (or env: ANTHROPIC_API_KEY)
  -o, --output     Report output dir      (default: ./reports)
  --max-iter       Max AI cycles          (default: 12, max: 20)
  --version        Show version
  -h, --help       Show help
```

---

## 📄 Sample Output

```
┌─────────────────────────── ◈ PHASE: RECON ───────────────────────────┐
│  Initial host discovery and information gathering                    │
└──────────────────────────────────────────────────────────────────────┘

  ▶ ping  ping -c 4 scanme.nmap.org
    64 bytes from 45.33.32.156: icmp_seq=1 ttl=53 time=42.1 ms
  ✔ ping  1.8s  1 finding(s)

  ▶ dns   dig scanme.nmap.org
    [A] 45.33.32.156
  ✔ dns   0.3s  1 finding(s)

╭──────────────────────── 🤖 AI ANALYSIS ───────────────────────────╮
│  Host is alive with an avg RTT of 42ms. DNS resolves to           │
│  45.33.32.156. I can see the target is reachable — next I'll      │
│  run a port scan to enumerate services.                           │
╰───────────────────────────────────────────────────────────────────╯

  ▶ nmap_quick  nmap -sV --open -T4 --top-ports 1000 scanme.nmap.org
    22/tcp  open  ssh     OpenSSH 6.6.1p1
    80/tcp  open  http    Apache httpd 2.4.7
  ✔ nmap_quick  18.4s  2 finding(s)

  🔴 [HIGH]     Open SSH on Legacy Version   OpenSSH 6.6.1 — EOL, CVEs exist
  🟡 [MEDIUM]   HTTP without HTTPS           Port 80 open, no 443 redirect
  🟢 [LOW]      Server Banner Disclosed      Apache/2.4.7 visible in headers
  ℹ  [INFO]     Target resolved              45.33.32.156
```

---

## ⚠️ Legal Notice

> **Only scan targets you own or have explicit written permission to test.**  
> PyKnock prompts for consent before every scan. The authors accept no
> responsibility for misuse of this tool.

---

## 🏗️ Architecture Notes (for interviews)

- **Autonomous agent loop** — Claude acts as the reasoning engine, not just a formatter
- **Stateful context** — full scan state passed every API call; no hallucinated history
- **Tool registry pattern** — adding a new tool is a one-function change
- **Graceful degradation** — works with just `nmap` + `curl` if other tools absent
- **Structured AI output** — Claude forced to respond in JSON; robust fallback parsing
- **Zero hardcoded scan paths** — AI decides every next step based on actual findings

---

*Built with Python 3.10+, Anthropic Claude, Rich*
