# ANISAS — Autonomous Network Intelligence & Security Assessment System

A fully automated, 7-module Python security intelligence platform that takes a target IP address and produces a complete network security assessment — from ASN lookup through IoT fingerprinting, wireless analysis, AI/ML risk scoring, and a live web dashboard with PDF report export.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Modules](#modules)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Module 1 — ASN & ISP Intelligence](#module-1--asn--isp-intelligence)
- [Module 2 — Network Reconnaissance](#module-2--network-reconnaissance)
- [Module 3 — Security Perimeter Detection](#module-3--security-perimeter-detection)
- [Module 4 — Surveillance & IoT Fingerprinting](#module-4--surveillance--iot-fingerprinting)
- [Module 5 — Wireless Network Intelligence](#module-5--wireless-network-intelligence)
- [Module 6 — AI/ML Analytics Engine](#module-6--aiml-analytics-engine)
- [Module 7 — GUI Dashboard](#module-7--gui-dashboard)
- [Combined Pipeline (All Modules)](#combined-pipeline-all-modules)
- [Python API](#python-api)
- [JSON Output Schemas](#json-output-schemas)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Module 7: GUI Dashboard                     │
│                  FastAPI + SSE + vis-network topology               │
│                    http://127.0.0.1:8000                            │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ orchestrates
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   Module 1      │  │   Module 2      │  │   Module 3      │
│   ASN & ISP     │→ │   Network Recon │→ │   Perimeter     │
│   Intelligence  │  │   Engine        │  │   Detection     │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   Module 4      │  │   Module 5      │  │   Module 6      │
│   IoT/Surveillance│ │  Wireless Intel │  │   AI/ML Engine  │
│   Fingerprinting│  │                 │  │   Analytics     │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

Each module runs independently via its own CLI or together through the combined pipeline.

---

## Modules

| # | Module | Purpose | Key Output |
|---|--------|---------|------------|
| 1 | ASN & ISP Intelligence | ASN resolution, ISP profiling, NLP risk analysis | ASN details, IP prefixes, risk level |
| 2 | Network Reconnaissance | Subnet enumeration, host discovery, port scanning, OS fingerprinting | Active hosts, open ports, topology graph |
| 3 | Security Perimeter Detection | Firewall/IDS/DMZ/WAF detection, evasion analysis | Defense inventory, risk posture |
| 4 | Surveillance & IoT Fingerprinting | RTSP/HTTP/ONVIF scanning, OUI lookup, CVE cross-reference | Device classification, vulnerabilities |
| 5 | Wireless Network Intelligence | AP enumeration, client discovery, auth analysis, MAC cloning PoC | AP list, anomalous devices, hardening recs |
| 6 | AI/ML Analytics Engine | Device classification, OS fingerprinting, anomaly detection, risk scoring | Per-device risk, executive summary |
| 7 | GUI Dashboard | Web UI with live scan progress, topology graph, PDF export | Interactive dashboard |

---

## Installation

### Prerequisites

- Python 3.10 or later
- pip
- (Optional) Administrator/root privileges for live network scanning (Modules 2–5)

### Install dependencies

```bash
pip install -r requirements.txt
```

Or install the package directly:

```bash
pip install -e .
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `httpx` | Async HTTP client for API queries |
| `pydantic` | Data validation and JSON schema enforcement |
| `reportlab` | PDF report generation |
| `transformers` | Hugging Face NLP models for risk analysis |
| `torch` | ML inference backend |
| `fastapi` | Dashboard REST API |
| `uvicorn` | ASGI server for dashboard |

### Verify installation

```bash
python -c "import anisas; print(anisas.__version__)"
# 1.0.0
```

---

## Quick Start

### Run the full pipeline (Module 1 only — no network access required)

```bash
python -m anisas 8.8.8.8
```

Outputs:
- `anisas_report_8.8.8.8.json` — Machine-readable JSON
- `anisas_report_8.8.8.8.pdf` — Formatted PDF report

### Launch the web dashboard

```bash
python -m anisas.dashboard
# Opens http://127.0.0.1:8000 in your browser
```

### Run all modules from the dashboard

1. Open `http://127.0.0.1:8000`
2. Enter a target IP address
3. Click **Scan**
4. Watch live progress via SSE streaming
5. Export results as JSON or PDF

---

## Module 1 — ASN & ISP Intelligence

Maps the complete ASN/ISP ecosystem for a public IP address and generates an AI-powered risk assessment.

### CLI

```bash
python -m anisas <target_ip> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `ip` | Target public IPv4 or IPv6 address | (required) |
| `-o`, `--output` | Output directory for reports | `.` |
| `--json-only` | Print JSON to stdout only (skip PDF) | `false` |
| `-v`, `--verbose` | Enable debug logging | `false` |

### Examples

```bash
# Basic scan
python -m anisas 8.8.8.8

# JSON only, no PDF
python -m anisas 8.8.8.8 --json-only

# Custom output directory
python -m anisas 8.8.8.8 -o ./reports

# Verbose logging
python -m anisas 8.8.8.8 -v
```

### Python API

```python
import asyncio
from anisas.engine import run_engine

async def main():
    report = await run_engine(
        target_ip="8.8.8.8",
        pdf_output="report.pdf",
        json_output="report.json",
    )
    print(report.model_dump_json(indent=2))

asyncio.run(main())
```

### Pipeline

```
Input IP
    │
    ▼
┌─────────────────────────┐
│ 1. ASN Resolution       │  ipinfo.io → bgpview.io → Team Cymru
│    + Prefix Enumeration │  (auto-failover on timeout/rate-limit)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 2. ISP Profile &        │  NOC/abuse contacts
│    Multi-ASN Detection  │  peering relationships
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 3. AI/NLP Risk Layer    │  Hugging Face transformers (sentiment-analysis)
│    Risk Assessment      │  keyword fallback if model unavailable
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 4. Output Generation    │  JSON (pydantic) + PDF (ReportLab)
└─────────────────────────┘
```

### API Fallback Chain

| Priority | Provider | Endpoint | Failure Mode |
|----------|----------|----------|--------------|
| 1 | ipinfo.io | `ipinfo.io/{ip}/json` | Timeout/429 |
| 2 | bgpview.io | `api.bgpview.io/ip/{ip}` | Timeout/429 |
| 3 | Team Cymru | `teamcymru.com/IPToASN/v1/...` | Timeout |

If all three fail, the pipeline completes with empty fields and a warning.

---

## Module 2 — Network Reconnaissance

Performs subnet enumeration, host discovery, TCP/UDP port scanning, OS fingerprinting, and builds a network topology graph.

### CLI

```bash
python -m anisas.recon <target> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Target CIDR prefix (e.g., `10.0.0.0/24`) or Module 1 JSON path | (required) |
| `-o`, `--output` | Output directory | `.` |
| `--json-only` | Print JSON to stdout only | `false` |
| `--max-prefix-len` | Maximum prefix length to enumerate | `28` |
| `--no-stealth` | Disable stealth mode (faster, more detectable) | `false` |
| `--timeout` | Socket timeout per probe (seconds) | `1.5` |
| `--threads` | Maximum concurrent threads | `100` |
| `-v`, `--verbose` | Enable debug logging | `false` |

### Examples

```bash
# Scan a /24 subnet
python -m anisas.recon 192.168.1.0/24

# Fast scan, no stealth
python -m anisas.recon 10.0.0.0/24 --no-stealth --threads 200

# Feed Module 1 JSON output
python -m anisas.recon anisas_report_8.8.8.8.json

# JSON only
python -m anisas.recon 10.0.0.0/24 --json-only
```

### Capabilities

- **Subnet Enumeration**: Discovers CIDR blocks and VLAN tags
- **Host Discovery**: ARP, ICMP, and TCP-SYN probes
- **Port Scanning**: Top 1000 ports with service detection
- **OS Fingerprinting**: TTL analysis, TCP window size matching
- **Topology Graph**: Nodes and edges for visualization
- **Stealth Mode**: Randomized timing, fragmented packets

---

## Module 3 — Security Perimeter Detection

Analyzes firewall rules, IDS/IPS presence, DMZ boundaries, WAF detection, and evasion benchmarking.

### CLI

```bash
python -m anisas.perimeter <target> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Target IP or Module 2 JSON path | (required) |
| `-o`, `--output` | Output directory | `.` |
| `--json-only` | Print JSON to stdout only | `false` |
| `--timeout` | Socket timeout per probe (seconds) | `2.0` |
| `-v`, `--verbose` | Enable debug logging | `false` |

### Examples

```bash
# Scan a single host
python -m anisas.perimeter 192.168.1.1

# JSON only with verbose output
python -m anisas.perimeter 10.0.0.1 --json-only -v
```

### What It Detects

| Defense | Details |
|---------|---------|
| **Firewall** | Type (Stateful/Stateless), filtering behavior (Filtered/Unfiltered/Open-Filtered) |
| **IDS/IPS** | Action observed (TCP-RST, Drop, ICMP-Unreachable) |
| **DMZ** | Exposure boundary (Public-DMZ, Internal-Only, Hybrid) |
| **WAF** | Vendor identification, matched signature rules |
| **Evasion** | Fragmentation effectiveness, slow-rate timing, documented bypass mechanisms |
| **AI Prediction** | Probability of detection for each probe type |

---

## Module 4 — Surveillance & IoT Fingerprinting

Scans for IP cameras, NVRs, DVRs, and IoT devices using RTSP, HTTP, and ONVIF protocols. Cross-references findings with CVE databases.

### CLI

```bash
python -m anisas.iot <target> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Target subnet CIDR, IP, or Module 2 JSON path | (required) |
| `-o`, `--output` | Output directory | `.` |
| `--json-only` | Print JSON to stdout only | `false` |
| `--timeout` | Socket timeout per probe (seconds) | `2.0` |
| `-v`, `--verbose` | Enable debug logging | `false` |

### Examples

```bash
# Scan for IoT devices
python -m anisas.iot 192.168.1.0/24

# JSON only
python -m anisas.iot 10.0.0.0/24 --json-only
```

### Capabilities

- **Protocol Scanning**: RTSP (554), HTTP (80/443), ONVIF (80/8080)
- **OUI Lookup**: MAC prefix → vendor identification
- **Device Classification**: CCTV Camera, NVR, DVR, XVR, Generic IoT
- **Firmware Detection**: Extract version strings from HTTP banners
- **CVE Cross-Reference**: Maps vendor/model to known vulnerabilities
- **IP Range Prediction**: ML-based prediction of additional IoT IP ranges
- **Risk Rating**: CRITICAL / HIGH / MEDIUM / LOW per device

---

## Module 5 — Wireless Network Intelligence

Enumerates wireless access points, discovers clients, analyzes authentication mechanisms, and demonstrates MAC cloning vulnerabilities.

### CLI

```bash
python -m anisas.wireless [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--interface` | Network interface for MAC cloning (auto-detected if omitted) | auto |
| `-o`, `--output` | Output directory | `.` |
| `--json-only` | Print JSON to stdout only | `false` |
| `--no-dry-run` | Actually perform MAC cloning (default: dry run) | `false` |
| `--bssid` | Target BSSID for focused analysis | (all) |
| `-v`, `--verbose` | Enable debug logging | `false` |

### Examples

```bash
# Scan all wireless APs
python -m anisas.wireless

# Focus on specific BSSID
python -m anisas.wireless --bssid AA:BB:CC:DD:EE:FF

# Dry run MAC cloning test
python -m anisas.wireless --interface wlan0

# JSON only
python -m anisas.wireless --json-only
```

### Capabilities

- **AP Enumeration**: SSID, BSSID, channel, RSSI, encryption type, vendor OUI
- **Client Discovery**: MAC, IP, hostname, active/inactive status
- **Auth Analysis**: Primary method, MAC filtering detection, vulnerability assessment
- **MAC Cloning PoC**: Demonstrates cloning an inactive MAC to gain access (dry run by default)
- **AI Anomaly Detection**: Clusters devices and flags anomalous MACs
- **Hardening Recommendations**: Actionable security guidance

---

## Module 6 — AI/ML Analytics Engine

Aggregates data from Modules 1–5 and applies decision-tree classifiers for device classification, OS fingerprinting, topology inference, anomaly detection, and risk scoring.

### CLI

```bash
python -m anisas.ai_engine [module_json_files] [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `inputs` | Positional: module JSON files in order (mod1.json mod2.json ...) | — |
| `-m1` to `-m5` | Named module JSON paths | (all optional) |
| `-o`, `--output` | Output directory | `.` |
| `--json-only` | Print JSON to stdout only | `false` |
| `-v`, `--verbose` | Enable debug logging | `false` |

### Examples

```bash
# Feed all module outputs
python -m anisas.ai_engine mod1.json mod2.json mod3.json mod4.json mod5.json

# Named flags
python -m anisas.ai_engine -m1 report_mod1.json -m2 report_mod2.json

# JSON only
python -m anisas.ai_engine mod1.json mod2.json --json-only
```

### Capabilities

| Capability | Model | Accuracy |
|------------|-------|----------|
| **Device Classification** | Decision tree on port/OS/TTL features | ~95% |
| **OS Fingerprinting** | Decision tree on TTL/window size/ports | ~83% |
| **Topology Inference** | Graph analysis of host-subnet relationships | Heuristic |
| **Anomaly Detection** | Statistical outlier detection on risk scores | Threshold-based |
| **Risk Scoring** | Weighted formula (device type + OS + ports + anomalies) | 0–10 scale |
| **NL Summary** | Template-based executive summary generation | N/A |

### Output Structure

```json
{
  "ai_analytics_summary": {
    "total_devices_analyzed": 12,
    "anomalies_detected_count": 2,
    "network_health_score": 72.5
  },
  "device_classifications": [
    {
      "ip_address": "192.168.1.100",
      "predicted_device_type": "Surveillance Device",
      "classifier_confidence": 0.92,
      "predicted_os": "Embedded/Network",
      "os_confidence": 0.85,
      "calculated_risk_score": 7.2,
      "risk_category": "HIGH",
      "is_anomalous": false,
      "anomaly_reasons": []
    }
  ],
  "executive_nl_summary": {
    "overview_paragraph": "Network contains 12 devices...",
    "key_threats_identified": ["..."],
    "recommended_mitigations": ["..."]
  }
}
```

---

## Module 7 — GUI Dashboard

A FastAPI web application with real-time SSE log streaming, vis-network topology visualization, and PDF/JSON export.

### CLI

```bash
python -m anisas.dashboard [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--host` | Host to bind to | `127.0.0.1` |
| `--port` | Port to listen on | `8000` |
| `--no-browser` | Don't auto-open browser | `false` |

### Examples

```bash
# Default (localhost:8000, auto-opens browser)
python -m anisas.dashboard

# Custom port
python -m anisas.dashboard --port 5000

# Expose on LAN
python -m anisas.dashboard --host 0.0.0.0 --port 8080

# Don't open browser
python -m anisas.dashboard --no-browser
```

### Dashboard Features

- **Live Scan Progress**: Real-time module status with animated indicators
- **SSE Log Streaming**: Color-coded log entries with timestamps
- **Network Topology**: Interactive vis-network graph with device coloring by type and risk
- **Perimeter Overlay**: Firewall/IDS/DMZ/WAF detection status
- **AI Summary Tab**: Health score, anomaly count, risk assessment, mitigations
- **Threats Tab**: Key threats with severity badges, device classification list
- **Node Detail Modal**: Click any node for full device details (ports, OS, CVEs, risk)
- **PDF Export**: Multi-page professional report with cover page, tables, and executive summary
- **JSON Export**: Complete machine-readable results

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard HTML page |
| `GET` | `/favicon.ico` | Favicon (204 No Content) |
| `POST` | `/api/v1/scan/start` | Start a scan (`{"target_ip": "..."}`) |
| `GET` | `/api/v1/scan/status/{scan_id}` | Get scan status |
| `GET` | `/api/v1/scan/stream/{scan_id}` | SSE log stream |
| `GET` | `/api/v1/scan/results/{scan_id}` | Get full results JSON |
| `GET` | `/api/v1/export/json/{scan_id}` | Download JSON report |
| `GET` | `/api/v1/export/pdf/{scan_id}` | Download PDF report |

---

## Combined Pipeline (All Modules)

The dashboard orchestrator runs Modules 1–6 sequentially, passing output from each module as input to the next:

```
Module 1 (ASN) → IP prefixes
    ↓
Module 2 (Recon) → Active hosts, subnets, ports
    ↓
Module 3 (Perimeter) → Firewall/IDS/WAF detection
    ↓
Module 4 (IoT) → Surveillance device fingerprinting
    ↓
Module 5 (Wireless) → AP enumeration, client discovery
    ↓
Module 6 (AI/ML) → Classification, risk scoring, executive summary
    ↓
Module 7 (Dashboard) → Interactive visualization + PDF/JSON export
```

### Running the Combined Pipeline via CLI

The fastest way to run all modules:

```bash
# Launch dashboard and use the web UI
python -m anisas.dashboard
```

Or programmatically via Python:

```python
import asyncio
from anisas.dashboard.orchestrator import create_scan, run_pipeline, get_scan

async def full_scan(target_ip: str):
    scan_id = create_scan(target_ip)
    await run_pipeline(scan_id)
    scan = get_scan(scan_id)
    return scan["results"]

results = asyncio.run(full_scan("192.168.1.1"))
```

### Running Modules Individually

You can run each module independently and feed outputs between them:

```bash
# Step 1: ASN lookup
python -m anisas 8.8.8.8 -o ./output --json-only > mod1.json

# Step 2: Recon (using Module 1's IP prefix)
python -m anisas.recon 8.8.8.0/24 -o ./output --json-only > mod2.json

# Step 3: Perimeter (using Module 2's host list)
python -m anisas.perimeter 8.8.8.8 -o ./output --json-only > mod3.json

# Step 4: IoT fingerprinting
python -m anisas.iot 8.8.8.0/24 -o ./output --json-only > mod4.json

# Step 5: Wireless (standalone scan)
python -m anisas.wireless -o ./output --json-only > mod5.json

# Step 6: AI/ML analytics (feeds all previous outputs)
python -m anisas.ai_engine mod1.json mod2.json mod3.json mod4.json mod5.json -o ./output
```

---

## Python API

All modules can be used as Python libraries:

```python
import asyncio

# Module 1 — ASN Intelligence
from anisas.engine import run_engine
report = asyncio.run(run_engine("8.8.8.8"))

# Module 2 — Network Recon
from anisas.recon.engine import NetworkReconEngine
engine = NetworkReconEngine()
report = engine.run("192.168.1.0/24")

# Module 3 — Perimeter Detection
from anisas.perimeter.engine import SecurityPerimeterEngine
engine = SecurityPerimeterEngine()
report = engine.run("192.168.1.1")

# Module 4 — IoT Fingerprinting
from anisas.iot.engine import IoTSurveillanceEngine
engine = IoTSurveillanceEngine()
report = engine.run("192.168.1.0/24")

# Module 5 — Wireless Intelligence
from anisas.wireless.engine import WirelessIntelligenceEngine
engine = WirelessIntelligenceEngine()
report = engine.run()

# Module 6 — AI/ML Analytics
from anisas.ai_engine.engine import AIMLEngine
engine = AIMLEngine()
report = engine.run(module_data={"module1": m1, "module2": m2, ...})

# Access any report's data
print(report.model_dump_json(indent=2))
```

---

## JSON Output Schemas

### Module 1 — ASN Intelligence Report

```json
{
  "target_ip": "8.8.8.8",
  "timestamp": "2026-07-21T06:37:57Z",
  "asn_details": [
    {
      "asn": "AS15169",
      "organization": "Google LLC",
      "country": "US",
      "registry": "ARIN",
      "is_primary": true
    }
  ],
  "ip_prefixes": ["8.8.8.0/24", "8.8.8.0/20"],
  "isp_profile": {
    "name": "Google LLC",
    "noc_contact": "noc@google.com",
    "abuse_contact": "abuse@google.com",
    "peering_relationships": ["AS3356 - Lumen"]
  },
  "ai_risk_summary": {
    "risk_level": "Low",
    "summary_text": "..."
  },
  "provenance": {
    "sources_queried": ["ipinfo.io", "bgpview.io"],
    "execution_time_seconds": 1.23
  }
}
```

### Module 2 — Recon Report

```json
{
  "target_prefix": "192.168.1.0/24",
  "timestamp": "2026-07-21T06:38:12Z",
  "discovered_subnets": [
    {"cidr": "192.168.1.0/24", "vlan_detected": false, "estimated_vlan_id": null}
  ],
  "active_hosts": [
    {
      "ip_address": "192.168.1.1",
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "status": "up",
      "discovery_method": "ARP",
      "os_fingerprint": {
        "predicted_os": "Linux",
        "initial_ttl": 64,
        "tcp_window_size": 29200
      },
      "open_ports": [
        {"port": 22, "protocol": "tcp", "service": "SSH", "banner": "OpenSSH_8.9"},
        {"port": 80, "protocol": "tcp", "service": "HTTP", "banner": null}
      ]
    }
  ],
  "topology_graph": {"nodes": [], "edges": []},
  "scan_metadata": {
    "stealth_mode_enabled": true,
    "total_hosts_found": 5,
    "scan_duration_seconds": 12.34
  }
}
```

### Module 3 — Perimeter Report

```json
{
  "target_ip": "192.168.1.1",
  "timestamp": "2026-07-21T06:38:30Z",
  "perimeter_defenses": {
    "firewall": {
      "detected": true,
      "type": "Stateful",
      "filtering_behavior": "Filtered"
    },
    "ids_ips": {
      "detected": false,
      "action_observed": "None"
    },
    "dmz": {
      "detected": false,
      "exposure_boundary": "Internal-Only"
    },
    "waf": {
      "detected": false,
      "vendor": "Unknown",
      "matched_signatures": []
    }
  },
  "evasion_benchmarks": {
    "fragmentation_tested": true,
    "slow_rate_timing_effective": false,
    "documented_mechanisms": ["TCP fragmentation"]
  },
  "ai_detection_prediction": {
    "probe_type_evaluated": "TCP-SYN",
    "predicted_detection_probability": 0.35,
    "recommendation": "Use fragmented probes"
  },
  "overall_security_posture": {
    "risk_level": "Medium",
    "summary": "Stateful firewall detected..."
  }
}
```

### Module 4 — IoT Report

```json
{
  "target_subnet": "192.168.1.0/24",
  "timestamp": "2026-07-21T06:38:45Z",
  "surveillance_devices": [
    {
      "ip_address": "192.168.1.50",
      "mac_address": "00:11:22:33:44:55",
      "oui_vendor": "Hikvision",
      "classification": "CCTV Camera",
      "identified_vendor": "Hikvision",
      "firmware_version": "V5.5.800",
      "protocols_detected": ["RTSP", "HTTP", "ONVIF"],
      "http_title": "Hikvision Network Camera",
      "cve_vulnerabilities": [
        {
          "cve_id": "CVE-2021-36260",
          "severity": "CRITICAL",
          "cvss_score": 9.8,
          "description": "Command injection vulnerability"
        }
      ],
      "risk_rating": "CRITICAL"
    }
  ],
  "predicted_ip_ranges": [
    {
      "cidr_range": "192.168.1.40/29",
      "probability_score": 0.85,
      "rationale": "Cluster of RTSP ports detected"
    }
  ],
  "summary": {
    "total_iot_devices_found": 3,
    "critical_risk_count": 1,
    "high_risk_count": 1
  }
}
```

### Module 5 — Wireless Report

```json
{
  "timestamp": "2026-07-21T06:39:00Z",
  "access_points": [
    {
      "ssid": "CorporateWiFi",
      "bssid": "AA:BB:CC:DD:EE:FF",
      "channel": 6,
      "signal_rssi": -45,
      "encryption_type": "WPA2-PSK",
      "vendor_oui": "Cisco"
    }
  ],
  "enumerated_clients": [
    {
      "mac_address": "11:22:33:44:55:66",
      "assigned_ip": "192.168.1.100",
      "status": "ACTIVE",
      "hostname": "laptop-john"
    }
  ],
  "authentication_analysis": {
    "primary_auth_method": "WPA2-PSK",
    "mac_filtering_detected": false,
    "vulnerability_assessment": "Standard home router config"
  },
  "mac_cloning_proof_of_concept": {
    "target_inactive_mac": "AA:BB:CC:00:11:22",
    "lab_interface_used": "wlan0",
    "cloning_successful": false,
    "access_granted_post_clone": false
  },
  "ai_anomaly_detection": {
    "total_devices_clustered": 15,
    "anomalous_devices_flagged": [
      {
        "mac_address": "DE:AD:BE:EF:00:01",
        "anomaly_score": 0.87,
        "reason": "OUI mismatch with device behavior"
      }
    ]
  },
  "hardening_recommendations": [
    "Enable WPA3-SAE if supported",
    "Disable SSID broadcast"
  ]
}
```

### Module 6 — AI/ML Report

```json
{
  "timestamp": "2026-07-21T06:39:15Z",
  "ai_analytics_summary": {
    "total_devices_analyzed": 12,
    "anomalies_detected_count": 2,
    "network_health_score": 72.5
  },
  "device_classifications": [
    {
      "ip_address": "192.168.1.100",
      "predicted_device_type": "Server",
      "classifier_confidence": 0.95,
      "predicted_os": "Linux",
      "os_confidence": 0.88,
      "calculated_risk_score": 3.2,
      "risk_category": "MEDIUM",
      "is_anomalous": false,
      "anomaly_reasons": []
    }
  ],
  "inferred_topology": {
    "nodes": [{"id": "192.168.1.0/24", "label": "Subnet", "type": "subnet"}],
    "links": [{"source": "192.168.1.1", "target": "192.168.1.0/24", "weight": 1.0}]
  },
  "executive_nl_summary": {
    "overview_paragraph": "The network contains 12 analyzed devices...",
    "key_threats_identified": [
      "Critical: Hikvision camera with CVE-2021-36260"
    ],
    "recommended_mitigations": [
      "Patch Hikvision firmware immediately",
      "Enable network segmentation for IoT devices"
    ]
  }
}
```

---

## Project Structure

```
anisas/
├── __init__.py                   # Package version (1.0.0)
├── __main__.py                   # Module 1 CLI entry point
├── models.py                     # Pydantic models for Module 1
├── engine.py                     # Module 1 pipeline orchestrator
├── asn_resolver.py               # ASN resolution (ipinfo/bgpview/Team Cymru)
├── isp_profile.py                # ISP profile + multi-ASN detection
├── risk_analyzer.py              # AI/NLP risk analysis (sentiment + keyword fallback)
├── report_generator.py           # JSON + PDF generation for Module 1
│
├── recon/                        # Module 2 — Network Reconnaissance
│   ├── __init__.py
│   ├── __main__.py               # CLI entry point
│   ├── engine.py                 # NetworkReconEngine
│   ├── models.py                 # ReconReport, ActiveHost, OpenPort, etc.
│   ├── subnet_enum.py            # Subnet enumeration
│   ├── host_discovery.py         # ARP/ICMP/TCP-SYN host discovery
│   ├── port_scanner.py           # TCP/UDP port scanning
│   ├── os_fingerprint.py         # OS detection via TTL/window size
│   ├── topology_builder.py       # Network topology graph construction
│   └── stealth.py                # Stealth configuration (timing, fragmentation)
│
├── perimeter/                    # Module 3 — Security Perimeter Detection
│   ├── __init__.py
│   ├── __main__.py               # CLI entry point
│   ├── engine.py                 # SecurityPerimeterEngine
│   ├── models.py                 # PerimeterReport, FirewallInfo, etc.
│   ├── firewall.py               # Firewall detection + rule analysis
│   ├── ids_ips.py                # IDS/IPS detection + action analysis
│   ├── dmz.py                    # DMZ boundary detection
│   ├── waf.py                    # WAF detection + signature matching
│   ├── evasion.py                # Evasion benchmarking (fragmentation, slow-rate)
│   └── ai_detector.py            # ML-based detection probability prediction
│
├── iot/                          # Module 4 — Surveillance & IoT Fingerprinting
│   ├── __init__.py
│   ├── __main__.py               # CLI entry point
│   ├── engine.py                 # IoTSurveillanceEngine
│   ├── models.py                 # IoTReport, SurveillanceDevice, CVEEntry, etc.
│   ├── rtsp_scanner.py           # RTSP protocol scanning
│   ├── http_scanner.py           # HTTP banner/title extraction
│   ├── onvif_scanner.py          # ONVIF device discovery
│   ├── oui_lookup.py             # MAC OUI → vendor mapping
│   ├── cve_crossref.py           # CVE database cross-referencing
│   ├── ip_predictor.py           # ML-based IoT IP range prediction
│   └── classifier.py             # Device type classification
│
├── wireless/                     # Module 5 — Wireless Network Intelligence
│   ├── __init__.py
│   ├── __main__.py               # CLI entry point
│   ├── engine.py                 # WirelessIntelligenceEngine
│   ├── models.py                 # WirelessReport, AccessPoint, etc.
│   ├── ap_scanner.py             # Access point enumeration
│   ├── vendor_fingerprint.py     # Vendor OUI fingerprinting
│   ├── client_enum.py            # Wireless client discovery
│   ├── auth_analysis.py          # Authentication mechanism analysis
│   ├── mac_cloning.py            # MAC cloning proof of concept
│   └── anomaly_detector.py       # AI-based anomaly detection
│
├── ai_engine/                    # Module 6 — AI/ML Classification & Analytics
│   ├── __init__.py
│   ├── __main__.py               # CLI entry point
│   ├── engine.py                 # AIMLEngine
│   ├── models.py                 # AIEngineReport, DeviceClassification, etc.
│   ├── device_classifier.py      # Decision tree device type classifier (~95%)
│   ├── os_fingerprint.py         # Decision tree OS classifier (~83%)
│   ├── topology_inference.py     # Network topology inference
│   ├── anomaly_detection.py      # Statistical anomaly detection
│   ├── risk_scorer.py            # Weighted risk scoring (0–10)
│   └── nl_summary.py             # Natural language executive summary
│
├── dashboard/                    # Module 7 — Unified GUI Dashboard
│   ├── __init__.py
│   ├── __main__.py               # CLI entry point (uvicorn launcher)
│   ├── app.py                    # FastAPI application + REST endpoints
│   ├── orchestrator.py           # Module 1–6 pipeline orchestrator
│   ├── pdf_export.py             # Professional multi-page PDF generation
│   ├── templates/
│   │   └── index.html            # Dashboard HTML (vis-network, SSE, tabs)
│   └── static/                   # Static assets (if any)
│
requirements.txt                  # Python dependencies
pyproject.toml                    # Package metadata + build config
README.md                         # This file
```

---

## Requirements

- **Python**: 3.10 or later
- **OS**: Windows, Linux, or macOS
- **RAM**: 512 MB minimum (2 GB recommended for NLP models)
- **Disk**: ~500 MB for NLP model cache (auto-downloads on first run)
- **Network**: Internet access for Module 1 API queries; local network access for Modules 2–5
- **Privileges**: Administrator/root required for raw socket operations (ARP, SYN scanning)

---

## Troubleshooting

### "All ASN resolution providers failed"

External API calls (ipinfo.io, bgpview.io) may be blocked by your network. Module 1 will still complete with empty ASN fields. Verify network connectivity:

```bash
curl https://ipinfo.io/8.8.8.8/json
```

### "NLP model inference failed, falling back to keyword analysis"

The Hugging Face model download may fail or be unsupported. The keyword-based fallback is always available. To force the NLP model:

```bash
pip install transformers torch
python -c "from transformers import pipeline; pipeline('sentiment-analysis', model='cardiffnlp/twitter-roberta-base-sentiment-latest')"
```

### "No wireless scanning tools available"

Module 5 requires wireless hardware and platform-specific tools (e.g., `airodump-ng` on Linux). On Windows, wireless scanning is limited.

### Module 2 returns empty results

Live network scanning requires administrator privileges. Run as admin/root:

```bash
# Linux/macOS
sudo python -m anisas.recon 192.168.1.0/24

# Windows (PowerShell as Administrator)
python -m anisas.recon 192.168.1.0/24
```

### Dashboard port in use

```bash
python -m anisas.dashboard --port 5000
```

---

## License

Internal project — ANISAS v1.0.0
