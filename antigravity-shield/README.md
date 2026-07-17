# AntiGravity Shield

**Real-time AI Anti-Forensic Detection and Mitigation Framework**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

AntiGravity Shield is a research-grade detection and evidence-preservation framework for autonomous AI-driven anti-forensic operations. It addresses the **TOCTOU Time Gap vulnerability** inherent in periodic File Integrity Monitoring (FIM) systems such as Wazuh and Splunk.

### The Problem

Enterprise SIEM platforms use periodic polling to check file integrity (e.g., every 12 hours or 5 seconds). An autonomous AI agent can execute a complete anti-forensic operation — timestomping, secure wiping, and log sanitisation — in **under 400 milliseconds**, completing the entire attack chain between polling cycles and leaving zero traces for the SIEM to detect.

This was empirically demonstrated in the author's prior research published at **AI-SS 2026** (Orji et al., 2026).

### The Solution

AntiGravity Shield replaces periodic polling with **kernel-event-driven monitoring** (Linux `inotify`) and augments detection with:

1. **Real-Time File Monitor** — Sub-millisecond detection of every file system event
2. **Behavioral Pattern Detector** — Identifies automated attack signatures (operation bursts, wiper sequences, ephemeral files)
3. **Timestamp Validator** — Detects timestomping via ctime/mtime divergence analysis
4. **Canary Deployer** — Honeypot files that trigger zero-false-positive alerts when accessed
5. **Log Protector** — SHA-256 hash-chained immutable audit logging
6. **Wazuh Integration** — Sends alerts to Wazuh SIEM via API or local socket

## Installation

### From Source

```bash
cd antigravity-shield
pip install -e .
```

### System Installation (with systemd)

```bash
# Install the package
pip install -e .

# Create system directories
sudo mkdir -p /etc/antigravity /var/lib/antigravity /var/log/antigravity /var/run/antigravity

# Copy configuration
sudo cp config/default.yaml /etc/antigravity/config.yaml

# Install systemd service
sudo cp systemd/antigravity.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable antigravity
sudo systemctl start antigravity
```

## Usage

### CLI Commands

```bash
# Start monitoring (foreground)
antigravity start --watch /home --watch /tmp

# Start as background daemon
antigravity start --daemonize --config /etc/antigravity/config.yaml

# Check status
antigravity status

# Stop the shield
antigravity stop

# View configuration
antigravity config

# View latest report
antigravity report --latest

# Run the dissertation experiment. The offensive agent is supplied separately.
agshield test --agent-path /path/to/agent_package \
  --stealth-trials 30 --noisy-trials 3 --human-trials 1 --fp-duration 10
```

### Python API

```python
from agshield import Config, DetectionEngine

# Load configuration
config = Config("/etc/antigravity/config.yaml")

# Create and start the engine
engine = DetectionEngine(config)
engine.start(deploy_canaries=True, canary_count=3)

# Block until interrupted (Ctrl+C)
engine.wait()

# Or stop programmatically
engine.stop()
```

### Wazuh Integration

Enable Wazuh integration in your config:

```yaml
wazuh_integration:
  enabled: true
  api_url: "https://localhost:55000"
  api_user: ""
  api_password: ""
  socket_path: "/var/ossec/queue/sockets/queue"
  alert_prefix: "antigravity"
```

AntiGravity Shield will send structured alerts to Wazuh with MITRE ATT&CK technique tags, enabling correlation with other security events in your SIEM.

Set credentials outside source control:

```bash
export AGSHIELD_WAZUH_USER="wazuh-wui"
export AGSHIELD_WAZUH_PASSWORD="your-secret"
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AntiGravity Shield                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Real-Time   │  │  Behavioral  │  │  Timestamp   │  │
│  │   Monitor    │──│  Detector    │  │  Validator   │  │
│  │  (inotify)   │  │  (patterns)  │  │  (anomaly)   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                  │          │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────┴───────┐  │
│  │   Canary     │  │    Log       │  │    Rule      │  │
│  │  Deployer    │  │  Protector   │  │   Engine     │  │
│  │  (honeypot)  │  │  (hash-chain)│  │  (config)    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Wazuh Integration                    │  │
│  │  (API + Socket + Custom Log Output)               │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Detection Capabilities

| Attack Technique | Detection Method | MITRE ATT&CK |
|---|---|---|
| Timestomping | ctime/mtime divergence analysis | T1070.006 |
| Secure Wiping | Modify→Rename→Delete sequence | T1485 |
| Log Truncation | Size monitoring + hash chain | T1070.002 |
| Mass Deletion | Rapid deletion threshold | T1070.004 |
| Evidence Staging | Canary file interaction | T1583 |
| Automated Execution | Operation burst detection | T1059 |

## Experimental Evaluation

Pilot testing has demonstrated the following behavior. These values are not a substitute for the dissertation's required 30-trial primary experiment:

| Metric | Result |
|---|---|
| **Detection Completeness** | 100% |
| **Average Detection Latency** | <100ms |
| **False Positive Rate** | 0/second |
| **Log Integrity** | ✅ VERIFIED (hash chain intact) |

The experiment command additionally produces:

- Trial-level CSV data
- JSON results with mean, median, standard deviation, minimum, and maximum
- A two-sided Mann-Whitney U test of Shield completeness against the historical Wazuh control
- Rank-biserial correlation effect size
- Detection-latency box plot, completeness bar chart, and agent-vs-human timing chart
- A separate controlled canary-effectiveness test

The historical control is explicitly labelled and detection latency is not fabricated when Wazuh produces no alert.

## Configuration

See `config/default.yaml` for all available options. Key settings:

- `general.watch_paths` — Directories to monitor
- `behavioral_detector.burst_threshold_ops` — Operations per second to trigger alert
- `timestamp_validator.retro_date_threshold_days` — Flag old timestamps
- `canary_deployer.default_count` — Honeypot files per directory
- `wazuh_integration.enabled` — Send alerts to Wazuh SIEM

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src/agshield

# Lint
ruff check src/agshield
```

## Academic Reference

This tool was developed as part of the research:

> Orji, E.C., Adenihun, A., Ojuolape-Oria, I., Ofeimun, O., Adeboye, O. and Akinseye, S. (2026) 'Exploring Agentic AI in Anti-Forensics: Simulation of Evasion Tactics in Digital Investigations', in *Proceedings of the 1st International Workshop on AI Safety and Security (AI-SS 2026)*, held in conjunction with the 21st European Dependable Computing Conference (EDCC 2026). Canterbury, UK, 7 April. IEEE CPS.

## License

MIT License — see LICENSE file for details.

## Author

**Emmanuel Chukwudinma Orji**  
MSc Cyber Security, University of Salford
