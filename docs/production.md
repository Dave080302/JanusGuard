# Using JanusGuard in Production and Mobile Environments

This document describes considerations and patterns for integrating JanusGuard
beyond its current role as a local, interactive scanner. The features described
here are **not yet implemented** — this is a forward-looking design guide.

---

## 1. CI/CD Pipeline Integration

JanusGuard already produces machine-readable JSON output and meaningful exit
codes, making it straightforward to embed in any CI/CD system.

**Pattern:** gate every release build on a JanusGuard scan.

```yaml
# GitHub Actions example
- name: Scan APK with JanusGuard
  run: |
    janusguard app/build/outputs/apk/release/app-release.apk \
      --format json --stdout | tee reports/release.report.json
    exit ${PIPESTATUS[0]}   # propagate JanusGuard exit code
```

Exit codes map directly to risk levels (`MEDIUM → 10`, `HIGH → 20`,
`CRITICAL → 30`), so the pipeline breaks automatically if a signed APK
regresses to v1-only or a Janus-style structural anomaly appears.

---

## 2. Mobile Device Management (MDM) Integration

Enterprises that distribute internal APKs through MDM platforms (Jamf, VMware
Workspace ONE, Microsoft Intune) can run JanusGuard as a pre-publish step.
The JSON report can be forwarded to the MDM API as metadata, allowing
administrators to see the signing scheme and risk level for every pushed
version in the MDM console without installing the APK on a real device.

---

## 3. App Store / Distribution Server Hook

Distribution servers (internal app catalogues, Aptoide enterprise, Firebase
App Distribution) can invoke JanusGuard as an upload hook. Any APK that
produces `HIGH` or `CRITICAL` is quarantined pending human review; anything
`MEDIUM` triggers an automated warning email; `LOW` and `OK` are published
automatically.

---

## 4. SIEM / Security Alerting

The JSON report structure is straightforward to ingest into a SIEM (Splunk,
Elastic Security, Sentinel). Each `Finding` object maps to a structured event
with `code`, `level`, `title`, and `detail` fields. A `STRUCT-JANUS-PATTERN`
finding at `CRITICAL` can trigger a high-priority alert and automatically open
a ticket in the incident tracking system.

---

## 5. Watch / Daemon Mode

**Planned feature — not yet implemented.**

In a production environment, new APKs land continuously — from build servers,
from third-party vendor uploads, from MDM sync jobs. Manually invoking
JanusGuard for each file is impractical. A watch/daemon mode would address this.

### Concept

A long-running JanusGuard process monitors one or more directories for new
`.apk` files. When a file appears (or is modified), it is automatically
analyzed and a report is emitted.

```bash
# Proposed CLI (not yet implemented)
janusguard watch /incoming/apks/ \
  --format json \
  --output-dir /var/reports/janusguard/ \
  --on-critical "notify-team.sh {apk} {report}" \
  --on-high    "log-to-siem.sh {report}"
```

### Implementation outline

- **File system event source.** On Linux, `inotify` via Python's
  `watchdog` library (optional dependency, guarded behind `pip install
  janusguard[watch]`). On macOS, `FSEvents`. On Windows, `ReadDirectoryChangesW`.
  For maximum portability with no extra dependency, a polling fallback
  using `os.stat` on a configurable interval (e.g. every 5 s) suffices.

- **Debounce.** APK files are often written in chunks; the watcher must wait
  until the file size is stable for at least one polling interval before
  analyzing, to avoid reading a partially-written archive.

- **Concurrency.** In high-throughput environments (e.g. a busy build farm),
  multiple APKs may arrive simultaneously. A thread-pool executor with a
  configurable worker count would analyze them in parallel without
  overloading the machine.

- **Hook commands.** The `--on-critical` / `--on-high` / `--on-medium` flags
  accept a shell command template. JanusGuard substitutes `{apk}` with the
  file path and `{report}` with the JSON report path before invoking the
  command in a subprocess. This makes it trivially composable with existing
  notification scripts (PagerDuty, Slack webhooks, email relays).

- **Persistence / deduplication.** A small SQLite database (or a flat JSON
  log) records which `(path, sha256)` pairs have already been analyzed, so
  a restart does not re-scan files that have not changed.

- **Systemd / Windows Service integration.** The daemon can be wrapped in a
  systemd unit file (Linux) or a Windows Service (via `pywin32` or NSSM) so
  it starts automatically and restarts on failure.

### Security considerations for daemon mode

- The daemon must **never execute** any APK it watches — the same constraints
  as the interactive mode apply.
- Directory permissions on the watch path should be tightly scoped; the daemon
  process should run as a dedicated low-privilege service account.
- Hook commands should be audited carefully: an attacker who can place a
  crafted APK in the watched directory could potentially influence the hook
  command output (though not the command itself, which is fixed at startup).
- Reports written to `--output-dir` should not be world-readable if they
  contain sensitive internal APK metadata.

---

## 6. Scaling Considerations

For organisations scanning hundreds of APKs per day:

- **Horizontal scaling.** JanusGuard is stateless and CPU-bound; multiple
  instances can run in parallel behind a simple queue (Redis, RabbitMQ, or
  even a watched S3 bucket with Lambda triggers).
- **Result caching.** Because analysis is deterministic given the same bytes,
  the SHA-256 hash can serve as a cache key. A result store (Redis, DynamoDB)
  avoids re-analyzing identical uploads.
- **Containerisation.** The standard-library-only design means the Docker
  image is just `python:3.12-slim` plus the package — well under 50 MB.
