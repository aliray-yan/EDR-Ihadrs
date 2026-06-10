# 🛡️ IHADRS — Intelligent Host-Based Attack Detection and Response System

A lightweight, standalone EDR (Endpoint Detection and Response) system for individual users and small teams. Written in Python, with a PyQt6 desktop dashboard and an HTML web dashboard.

## Features

- **30 MITRE ATT&CK–mapped detection rules** covering ransomware, credential dumping, C2 communication, defense evasion, persistence, and more
- **3-stage detection pipeline**: YAML rule engine → behavioral sliding-window detection → cross-event correlation engine
- **Isolation Forest ML** baseline classifier with 28-dimensional process feature vectors
- **Automated response**: process suspension/kill, IP blocking, file quarantine, forensic collection
- **Dual dashboard**: PyQt6 desktop app and standalone HTML/JS web dashboard
- **REST API**: full programmatic access to events, threats, stats, and response actions

## Quick Start

```bash
pip install ihadrs
ihadrs start          # Start the daemon
ihadrs ui             # Open the PyQt6 dashboard
# Or open http://127.0.0.1:8765 in your browser for the web dashboard
```

## Windows Clickable Install

To use IHADRS like a normal Windows app, double-click:

```text
Install IHADRS.cmd
```

The installer creates:

- Desktop shortcut: `IHADRS EDR`
- Start Menu folder: `IHADRS EDR`
- Start shortcut, dashboard shortcut, and stop shortcut

After that, launch IHADRS from the Desktop or Start Menu. Windows will ask for
Administrator approval on launch because endpoint monitoring needs system-level
access. The launcher starts IHADRS in the background, opens
`http://127.0.0.1:8765/`, and writes launcher/runtime logs under `logs/`.

To remove the shortcuts, double-click:

```text
Uninstall IHADRS Shortcuts.cmd
```

## SecureOps SOC Export

IHADRS can push Windows detections into SecureOps with the EDR ingest API.
Open the web dashboard settings drawer and configure:

- SecureOps API base URL, for example `http://127.0.0.1:8000/api/v1`
- EDR ingest key from SecureOps Settings/API Configuration
- Enable SOC export
- Test SOC Connection

Saved ingest keys are protected with Windows DPAPI and are never written to
plaintext config files. The outbound queue keeps unsent alerts locally and
retries network/5xx failures with 10s, 30s, 2m, 5m, and 15m backoff while
preserving the same stable `alert_id` for SecureOps idempotency.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         IHADRS Daemon                          │
│                                                                 │
│  Monitors          Detection Pipeline         Response          │
│  ──────────        ──────────────────         ────────          │
│  Process  ──┐      Rule Engine (YAML)         AutoResponder     │
│  Network  ──┤      Behavioral Detector   ───► Recommender       │
│  File     ──┼──►   Correlation Engine         Notifier          │
│  Registry ──┤      ML Classifier (IF)                          │
│  Service  ──┤      Explainer                                    │
│  Auth     ──┘                                                   │
│               │               │                                 │
│               ▼               ▼                                 │
│           EventBus        ThreatEvents                          │
│           (priority       (IHADRS_DETECTION_TRIGGERED)          │
│            heap queue)                                          │
│                                                                 │
│  Storage: SQLite (WAL mode) + LRU/TTL cache                    │
│  API: FastAPI + uvicorn on :8765                               │
└─────────────────────────────────────────────────────────────────┘
```

## Detection Rules

| Rule ID | Name | Severity | MITRE |
|---|---|---|---|
| R001 | Encoded PowerShell Execution | HIGH | T1059.001 |
| R002 | Office App Spawning Shell | CRITICAL | T1566.001 |
| R003 | Mass File Encryption | CRITICAL | T1486 |
| R004 | Shadow Copy Deletion | HIGH | T1490 |
| R005 | Credential Dumping (Mimikatz) | CRITICAL | T1003 |
| R012 | Registry Run Key Persistence | HIGH | T1547.001 |
| R018 | Windows Defender Disabled | HIGH | T1562.001 |
| R023 | Hosts File Modification | MEDIUM | T1565.001 |
| ... | (30 rules total) | | |

## Configuration

Edit `config/settings.yaml` to configure:
- Monitor poll intervals
- Detection thresholds (ransomware rename count, brute force failures)
- Response mode (manual / semi_auto / full_auto)
- API authentication token
- Alerting channels

## API

```bash
# Get system status
curl -H "X-IHADRS-Token: your-token" http://127.0.0.1:8765/api/v1/status

# Get recent threats
curl -H "X-IHADRS-Token: your-token" http://127.0.0.1:8765/api/v1/threats?limit=10

# Mark false positive
curl -X POST -H "X-IHADRS-Token: your-token" \
  -d '{"reason":"Legitimate admin tool"}' \
  http://127.0.0.1:8765/api/v1/threats/{threat_id}/fp
```

## Requirements

- Python 3.11+
- psutil, watchdog, scikit-learn, fastapi, uvicorn, pydantic
- PyQt6 (optional, for desktop dashboard)

## Test Suite

```bash
pytest tests/ -m "not slow"     # 394 tests, ~20s
pytest tests/ --asyncio-mode=auto  # Full suite including slow ML tests
```

## License

MIT — see LICENSE file.
