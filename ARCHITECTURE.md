# IHADRS Architecture

## Module Map

```
src/ihadrs/
├── constants.py          52 EventTypes, 15 AttackCategories, all enums
├── exceptions.py         40+ typed exception hierarchy
├── app.py                Application orchestrator (startup/shutdown)
├── __main__.py           Click CLI entry point
│
├── core/
│   ├── config.py         Pydantic v2 IHADRSConfig singleton + hot-reload
│   ├── event_bus.py      Priority heap bus (≥1000 eps), TokenBucket rate limiter
│   ├── resource_manager.py CPU/RAM/disk budget enforcement
│   └── scheduler.py      ThreadTimer-based recurring job scheduler
│
├── models/
│   ├── events.py         8 event dataclasses + factories
│   └── threats.py        ThreatEvent, ThreatEvidence, ProcessContext, RemediationStep
│
├── monitors/
│   ├── base.py           Abstract BaseMonitor (lifecycle, dedup, health check)
│   ├── process_monitor.py psutil poll-diff, PID baseline, privilege detection
│   ├── network_monitor.py psutil connections, C2 beaconing analysis
│   ├── file_monitor.py   watchdog OS-native watchers, ransomware threshold
│   ├── registry_monitor.py winreg persistence key polling (Windows only)
│   ├── service_monitor.py psutil win_service_iter poll-diff (Windows only)
│   └── auth_monitor.py   Windows Security Event Log / Linux auth.log parser
│
├── detection/
│   ├── rule_engine.py    YAML rule loading, 17 operators, ALL/ANY/THRESHOLD
│   ├── behavioral.py     SlidingWindowTracker, ransomware/brute-force/spawn-burst
│   ├── correlation.py    Cross-event chain detection, 5 attack patterns
│   └── engine.py         3-stage pipeline orchestrator, dedup, ThreatEvent builder
│
├── classification/
│   ├── ml_classifier.py  28-dim ProcessFeatures, Isolation Forest, explainability
│   ├── rule_classifier.py MITRE→category mapping, severity adjustment, FP scoring
│   ├── heuristic.py      Fast risk scorer (no training required)
│   └── explainer.py      User-friendly + technical explanations + prevention tips
│
├── response/
│   ├── auto_responder.py Action dispatch (suspend/kill/block_ip/quarantine/forensics)
│   └── recommender.py    Playbook-driven remediation step generation
│
├── alerting/
│   └── notifier.py       Rate-limited multi-channel notification dispatcher
│
├── api/
│   └── server.py         FastAPI: all /api/v1/* endpoints, Starlette middleware auth
│
├── web/
│   ├── server.py         Static file server for HTML dashboard
│   ├── templates/
│   │   └── dashboard.html Single-page dashboard (no build step, no dependencies)
│   └── static/
│       ├── css/dashboard.css  Dark theme, responsive
│       └── js/dashboard.js   Polling engine, all tab logic, chart rendering
│
├── ui/
│   ├── app.py            PyQt6 entry point + dark theme stylesheet
│   ├── main_window.py    MainWindow + APIWorker QThread + IHADRSStatusBar
│   └── tabs/
│       ├── monitor_tab.py   Live process list, resource bars, event feed
│       ├── alerts_tab.py    Threat feed, detail panel, FP marking, response buttons
│       ├── analysis_tab.py  Severity bars, category breakdown, MITRE table
│       ├── logs_tab.py      Raw event log with search and export
│       └── settings_tab.py  API config, response mode, notification preferences
│
├── intelligence/
│   └── mitre.py          MITRE ATT&CK technique/tactic name resolver
│
└── storage/
    ├── event_store.py    Async SQLite (WAL mode), migrations, retention pruning
    └── cache.py          LRU+TTL cache registry
```

## Event Flow

```
Monitor polls OS  →  BusEvent(PROCESS_CREATED)
                          │
                    EventBus (priority heap)
                          │
                    DetectionEngine.process_event()
                       ├── RuleEvaluator.evaluate()          → matched_rules
                       ├── BehavioralDetector.process_event() → behavioral_matches
                       └── CorrelationEngine.process_event()  → correlation_matches
                          │
                    ThreatEvent constructed + deduplicated
                          │
                    BusEvent(IHADRS_DETECTION_TRIGGERED)
                       ├── Notifier.handle_event()  → desktop notification
                       └── AutoResponder.respond()  → automated actions
```

## Detection Pipeline Details

### Stage 1: Rule Engine
- Loads 30 YAML rules from `config/rules.yaml`
- Each rule defines monitor type, field conditions, and MITRE mapping
- 17 operators: equals, contains, contains_any, regex, in, gte, lte, etc.
- ALL (AND) and ANY (OR) condition modes
- O(R×C) per event, <1ms for 30 rules

### Stage 2: Behavioral Detector
- Sliding time windows per entity (PID, source IP)
- Ransomware: ≥N file renames with crypto extensions in T seconds
- Brute Force: ≥N auth failures from same IP in T seconds
- Spawn Burst: ≥N shells spawned by same parent in T seconds
- Cooldown suppresses duplicate alerts per pattern

### Stage 3: Correlation Engine
- Rolling window of recent events (configurable, default 300s)
- 5 multi-stage attack patterns:
  - Office Macro → Shell → Network
  - Downloaded File → Execution
  - Auth Failures → Success (credential stuffing)
  - Process → Registry Run Key
  - Process → Service Installation

## API Authentication

- Header: `X-IHADRS-Token: <token>` or `Authorization: Bearer <token>`
- Implemented as Starlette BaseHTTPMiddleware (not FastAPI Depends)
  - Reason: Pydantic v2 forward-ref resolution breaks nested Depends
- Rate limiting: per-client-IP token bucket (default 100 req/60s)
- All `/api/v1/*` routes protected; `/healthz` is public