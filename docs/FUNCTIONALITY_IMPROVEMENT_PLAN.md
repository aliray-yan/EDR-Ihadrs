# IHADRS Functionality Improvement Plan

This plan is ordered for practical implementation. Phase 1 focuses on the
highest-value user-facing functionality, then later phases deepen the EDR into a
more complete endpoint and SOC workflow.

## Phase 1 - Operator Workflow

Goal: make the dashboard useful during a real alert review session.

- Add alert lifecycle states: new, acknowledged, investigating, remediated, false positive.
- Add alert notes and analyst comments stored locally with timestamps.
- Add bulk actions for selected alerts: acknowledge, export, mark false positive.
- Add a synthetic "Send Test Alert" button for validating UI, queue, and SecureOps ingest.
- Add SOC queue controls: retry now, pause export, resume export, clear permanent payload errors.
- Add a visible "EDR running/stopped" launcher state and graceful stop signal in the UI.

## Phase 2 - Detection Quality

Goal: reduce false positives and make detections easier to trust.

- Add allowlists for trusted process paths, publishers, hashes, users, and command-line patterns.
- Add per-rule tuning: enabled/disabled, severity override, confidence threshold, cooldown.
- Add rule test mode that runs sample events through the rule engine before enabling a rule.
- Improve stable detection IDs by including rule ID, event timestamp bucket, host ID, and process identifiers.
- Add richer IOC extraction for command lines, URLs, domains, IPs, hashes, registry paths, and file paths.

## Phase 3 - Windows Telemetry Coverage

Goal: collect better Windows-native evidence for stronger detections.

- Add Windows Event Log collector for Security, PowerShell, Defender, and Sysmon channels.
- Add Windows service and scheduled task monitors.
- Add registry persistence monitoring for Run keys, services, IFEO, shell open commands, and Winlogon keys.
- Add USB/removable media telemetry.
- Add local endpoint inventory: OS build, hostname, users, interfaces, installed security tools.

## Phase 4 - Incident Response

Goal: move from detection to controlled response.

- Add manual response buttons for kill process, suspend process, quarantine file, and block IP.
- Add approval workflow for high-risk actions.
- Add response audit log with actor, action, target, timestamp, and result.
- Add rollback metadata where possible, especially for firewall rules and quarantine actions.
- Add a "collect evidence package" action for alert timelines, process details, file hashes, and logs.

## Phase 5 - Packaging And Service Mode

Goal: make IHADRS behave like a proper Windows application.

- Package as a signed executable with PyInstaller or Briefcase.
- Add Windows Service mode for always-on protection.
- Add a tray controller for start, stop, dashboard, and status.
- Add a real installer with Start Menu entries, uninstall support, and dependency checks.
- Store runtime data under ProgramData/IHADRS instead of the project folder for installed mode.

## Phase 6 - SecureOps Integration Hardening

Goal: make SOC export production-ready.

- Add a queue viewer with batch ID, retry count, next retry time, and permanent error reason.
- Add payload validation before enqueue to catch schema errors locally.
- Add a "test alert to SecureOps" action using a deterministic alert ID.
- Add HTTPS enforcement for production mode and clearer warnings for HTTP lab mode.
- Add ingest key rotation flow and masked key status.
- Add source/device metadata consistency checks so SecureOps can correlate alerts by endpoint.

## Phase 7 - Reliability And Tests

Goal: make changes safer and easier to maintain.

- Add unit tests for rule tuning, allowlists, lifecycle state, and queue controls.
- Add API tests for alert lifecycle and SecureOps settings endpoints.
- Add a synthetic telemetry fixture suite for common Windows attack behaviors.
- Add dashboard smoke tests for render, filtering, settings, and SOC test connection.
- Add startup diagnostics that explain missing admin rights, missing dependencies, port conflicts, and bad config.
