# LiquidSystem — Network Intelligence Platform

A full-stack network security and privacy audit platform for a self-hosted home lab. Pulls data from Pi-hole, Prometheus, OPNsense/Suricata, and fail2ban, runs an AI-powered analysis via Claude, and presents everything through a live web dashboard with interactive chat.

---

## Features

### DNS Audit
- **Traffic Review** — total queries, block/cache rates, top allowed and blocked domains, top clients by volume, query type breakdown
- **DNS Bypass Detection** — flags devices querying DoH/DoT provider hostnames (`dns.google`, `cloudflare-dns.com`, etc.), PTR lookups to public resolvers, and clients with suspiciously low query counts (possible hardcoded DNS)
- **Blocklist Recommendations** — scans up to 15,000 allowed queries and surfaces known tracking, telemetry, ad network, data broker, fingerprinting, and smart TV / IoT phone-home domains that should be blocked

### Device Intelligence
- **Device Fingerprinting** — identifies 15+ device types (Apple, Windows, Android, Samsung/LG/Roku TVs, Alexa, Fire TV, Nintendo Switch, PlayStation, Sonos, Raspberry Pi, printers, routers, and more) via DNS signature matching
- **Privacy Risk Scoring** — classifies each device as high / medium / low / minimal risk with a confidence percentage
- **Manual Overrides** — label devices by hand in `devices.json`; override auto-detection for anything Pi-hole can't fingerprint

### Multi-Source Monitoring
- **Prometheus Metrics** — CPU, RAM, disk, and network I/O for up to 11 hosts (Proxmox, Jellyfin, Immich, Nextcloud, Traefik, etc.)
- **OPNsense Firewall** — recent block events and top blocked source IPs
- **Suricata IDS** — alert stream with severity classification (high/medium/low)
- **fail2ban** — ban counts and active jail status across all Proxmox containers via SSH

### AI Assessment
- **Claude AI Analysis** — streaming assessment from Claude Sonnet that synthesizes all six data sources into an executive summary, prioritized action list, cross-source correlations, and top domains to block
- **Longitudinal Trends** — compresses up to 5 previous reports into context so Claude can identify trends over time

### Interactive Chat
- **Web Chat Tab** — ask Claude follow-up questions directly in the dashboard; Claude retains the full audit context for the session
- **Actionable Responses** — Claude generates exact Pi-hole commands, firewall rules, blocklists, and config snippets you can copy-paste; responses stream in token-by-token
- **Session Management** — start a new conversation at any time without losing the current report view

### Web Dashboard
- Live dark-themed SPA with three tabs: **DNS & Security**, **System Health**, **Chat**
- Manual **Run Now** button plus automatic scheduled daily runs (configurable hour)
- Report history selector — browse and compare past reports
- **Export & Delete** — download any report as a self-contained HTML file; automatically removes it from server storage to keep memory usage low
- Log cleaner modal — select containers and clear fail2ban bans + truncate logs in one click

### Notifications
- **ntfy integration** — push notifications to a self-hosted ntfy instance after each run; severity-based priority with executive summary in the notification body

---

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- Pi-hole v6 (with API password)
- Anthropic API key (for AI assessment and chat)
- Prometheus (optional — for system metrics)
- OPNsense with API access (optional — for firewall/IDS data)
- Proxmox with SSH key access (optional — for fail2ban data)

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/liquidcode7/pihole-audit
cd pihole-audit
uv sync
```

### 2. Configure `.env`

Create a `.env` file in the project root:

```env
# Pi-hole (required)
PIHOLE_URL=http://192.168.1.x
PIHOLE_APP_PASSWORD=your_app_password_here

# Anthropic (required for AI features)
ANTHROPIC_API_KEY=sk-ant-...

# Prometheus (optional)
PROMETHEUS_URL=http://192.168.1.x:9090

# OPNsense (optional)
OPNSENSE_URL=https://192.168.1.1
OPNSENSE_KEY=your_api_key
OPNSENSE_SECRET=your_api_secret

# Proxmox / fail2ban (optional)
PROXMOX_HOST=192.168.1.20
PROXMOX_SSH_USER=root

# ntfy notifications (optional)
NTFY_URL=http://your-ntfy-server
NTFY_TOPIC=liquidsystem
NTFY_ENABLED=true

# App settings
REPORTS_DIR=data/reports        # where JSON reports are stored
MAX_REPORTS=30                   # max reports to retain before pruning
SCHEDULE_HOUR=11                 # UTC hour for daily auto-run (11 = 6 AM EST)

# Bypass detection — IPs to exclude from low-query-count flagging
# (192.168.1.1 and 127.0.0.1 are always excluded)
# PIHOLE_BYPASS_IGNORE_IPS=10.0.0.1,172.16.0.1

# Optional: path to manual device overrides
# PIHOLE_DEVICES_JSON=devices.json
```

### 3. (Optional) Manual device labels

Edit `devices.json` to override auto-detected device types:

```json
{
  "192.168.1.50": { "device_type": "Work Laptop", "privacy_risk": "low" },
  "192.168.1.75": { "device_type": "Samsung TV",  "privacy_risk": "high" }
}
```

### 4. Create a Pi-hole app password

Go to **Settings → API** in your Pi-hole web interface and generate an app password. Use that value for `PIHOLE_APP_PASSWORD` — do not use your main admin password.

---

## Running

### Web dashboard (recommended)

```bash
uv run uvicorn app:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` in your browser. Click **Run Now** to kick off the first analysis, or wait for the scheduled daily run.

### CLI mode

```bash
uv run python main.py
```

Produces a rich terminal report with color-coded tables, streams the AI assessment live, drops into an interactive chat session, and saves a self-contained HTML report to the current directory.

---

## Web Dashboard Overview

| Tab | What's Here |
|-----|-------------|
| **DNS & Security** | Traffic summary cards, top allowed/blocked domains, top clients, bypass findings, blocklist recommendations, device inventory, AI assessment |
| **System Health** | Host metric cards (CPU/RAM/disk/network), Suricata IDS alerts, firewall block events, fail2ban container status |
| **Chat** | Back-and-forth conversation with Claude, pre-loaded with the current report's audit context |

**Header controls:**
- **History dropdown** — switch between past reports
- **Run Now** — trigger an immediate analysis
- **Export & Delete** (per report) — downloads the report as a standalone HTML file and removes it from server storage

---

## Architecture

```
CLI (main.py) or Web API (app.py)
    └── Runner (runner.py)
        ├── Phase 1 — Pi-hole auth + concurrent fetches
        │   ├── traffic.py      DNS traffic stats
        │   ├── bypass.py       DNS bypass detection
        │   ├── recommender.py  Blocklist recommendations
        │   └── device_identifier.py  Device fingerprinting
        ├── Phase 2 — Independent sources (parallel, fault-isolated)
        │   ├── metrics.py      Prometheus system metrics
        │   ├── firewall.py     OPNsense + Suricata
        │   └── fail2ban.py     SSH → Proxmox containers
        └── Phase 3 — AI layer
            ├── assessment.py   Streaming Claude assessment
            └── conversation.py CLI interactive chat
                └── report.py   Jinja2 HTML renderer
                    notifier.py ntfy push notification
```

---

## Project Structure

```
pihole-audit/
├── app.py                # FastAPI web application + REST API
├── main.py               # CLI entry point
├── runner.py             # Orchestrates the full analysis pipeline
├── client.py             # Pi-hole v6 session manager
├── traffic.py            # DNS traffic review
├── bypass.py             # DNS bypass detection
├── recommender.py        # Blocklist recommendations
├── device_identifier.py  # Device fingerprinting + risk scoring
├── metrics.py            # Prometheus metrics collector
├── firewall.py           # OPNsense + Suricata integration
├── fail2ban.py           # fail2ban status via SSH
├── assessment.py         # Claude AI assessment
├── conversation.py       # CLI interactive chat
├── report.py             # Jinja2 HTML report renderer
├── notifier.py           # ntfy push notifications
├── log_cleaner.py        # fail2ban log + ban cleaner
├── devices.json          # Manual device label overrides
├── static/
│   └── index.html        # Web dashboard SPA
└── templates/
    └── report.html       # Self-contained HTML report template
```

---

## Notes

- All Pi-hole API calls are **read-only**. The tool never modifies Pi-hole configuration.
- Pi-hole v6 has a limited number of API session "seats" — the client uses a context manager to guarantee logout even on crash.
- The recommender scans up to 15,000 raw queries per run; the bypass detector scans up to 5,000.
- OPNsense TLS verification is disabled for LAN use (self-signed cert). Do not expose the API to untrusted networks.
- Chat sessions are held in memory and lost on server restart — they are not persisted to disk.
- The export feature renders a fully self-contained HTML file (no external dependencies) suitable for archiving or sharing.
