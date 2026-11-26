# Hecate Background Services & Daemon Architecture

This guide advises developers and operators on the background system services available in Hecate, their security roles, and how to set them up.

---

## 1. Do You Need Background Services?

Hecate supports two primary operating modes:

* **Interactive Development (No Services Needed):**
  If you are developing rules, testing CLI commands (`hecate-agent`, `hecate-runner run`), running unit tests, or exploring hunts locally, you do **not** need systemd services. Use a standard virtual environment with `uv` as described in [`docs/ONBOARDING.md`](ONBOARDING.md).

* **Autonomous Node (Background Services Required):**
  If you want 24/7 continuous cyber threat intelligence (CTI) intake, automated hypothesis generation, scheduled SIEM sweeps, continuous Purple Team replay verification, or Slack alerting, you should deploy the systemd background services.

---

## 2. Service Catalog

| Service Unit | Tier | Purpose | Dedicated User | Env File |
| :--- | :---: | :--- | :--- | :--- |
| **`hecate-runner-daemon`** | **Required** | Continuous CTI intake (GitHub PoCs, MISP, RSS), hypothesis generation, automated hunt execution, and continuous Purple Team verification. | `hecate-reader` | `/etc/hecate/reader.env` |
| **`hecate-runner-maintenance`** | **Recommended** | Queue draining, cooldown management, automated artifact retention, and scheduled downstream publishing (MISP/GitHub/Splunk). | `hecate-writer` | `/etc/hecate/writer.env` |
| **`hecate-slack-bot`** | **Optional** | Real-time intake & BAS alerts, draft approval notifications, and interactive Slack slash commands. *(Skip if not using Slack).* | `hecate-slack` | `/etc/hecate/slack.env` |
| **`hecate-bas-broker`** | **Optional** | Unix domain socket proxy (`/run/hecate-bas/broker.sock`) for containerized adversary emulation (Atomic Red Team / CALDERA). *(Skip if only executing SIEM query verification).* | `root` / `docker` | *None (supervises socket ACL)* |

---

## 3. Quickstart: Setting Up Services

We provide a streamlined setup script that auto-detects your repository paths, builds the isolated runtime, sets up dedicated non-login system accounts, and installs the hardened systemd units:

```bash
# From the Hecate-Runner root directory:
./scripts/setup-services.sh
```

### Script Options
```bash
./scripts/setup-services.sh \
  --core /path/to/Hecate-Core \
  --workspace /path/to/Hecate-Public \
  --env-dir /etc/hecate \
  --docker-socket /var/run/docker.sock \
  --check    # Dry-run validation only
```

---

## 4. Role Isolation & Environment Files

For security, background services run under unprivileged, non-login system accounts with dedicated credential files in `/etc/hecate/` (permissions `0640`, owner `root:hecate-<role>`):

* **`reader.env` (`hecate-reader`):**
  Read-only permissions. Contains CTI API keys, LLM/model endpoint tokens, and `SPLUNK_READ_TOKEN`.
  > [!CAUTION]
  > Never put publishing keys (`SPLUNK_WRITE_TOKEN`, GitHub App private keys, or Slack app tokens) into `reader.env`.

* **`writer.env` (`hecate-writer`):**
  Publishing and maintenance permissions. Contains `SPLUNK_WRITE_TOKEN`, `SPLUNK_READ_TOKEN` (for SIEM audits), GitHub App private key paths, and MISP export keys.
  - Enable autonomous SIEM drift reconciliation: `HECATE_RUNNER_SIEM_DRIFT_AUTO_RECONCILE=true`.

* **`slack.env` (`hecate-slack`):**
  Slack integration tokens (`SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`) and pinned channel IDs:
  - `SLACK_CHANNEL_HUNTS_EXEC=C0CC5R9S4EP` (Executive hunts & verified true-positives)
  - `SLACK_CHANNEL_THREAT_HUNTING=C0CCA3NLN0N` (Operational hunting & sweep findings)
  - `SLACK_CHANNEL_OPS_METRICS=C0CC6PG0GAH` (Consolidated 24h operational pulse)
  - (Optional domain digests: `DETECTION_ENGINEERING`, `THREAT_INTEL`, `EXPLOITS`, `SANDBOX`, `APT`, `CLOUD`, `C2`)

Starter templates are located in [`deploy/service-env/`](../deploy/service-env/).

---

## 5. Operations Cheatsheet

### Check Status
```bash
systemctl status hecate-runner-daemon.service hecate-runner-maintenance.service hecate-slack-bot.service hecate-bas-broker.service
```

### View Live Logs
```bash
# Daemon orchestrator logs
journalctl -u hecate-runner-daemon.service -f

# Maintenance / publisher / SIEM drift logs
journalctl -u hecate-runner-maintenance.service -f

# Interactive Slack bot logs
journalctl -u hecate-slack-bot.service -f
```

### Updating Runtime After Code Changes
Production services run against an immutable, standalone runtime in `/opt/hecate/runtime`. When code changes are pulled into `Hecate-Core` or `Hecate-Runner`, do **not** use `pip install`. Use the atomic runtime updater with the bundled interpreter:

```bash
# 1. Build a new runtime stage as an ordinary unprivileged user:
scripts/prepare-service-runtime.sh ../Hecate-Core /tmp/hecate-runtime-stage

# 2. Hot-swap the runtime transactionally with automatic rollback support:
sudo /opt/hecate/runtime/venv/bin/python scripts/update-service-runtime.py --runtime-stage /tmp/hecate-runtime-stage

# 3. Clean up the stage directory:
rm -rf /tmp/hecate-runtime-stage
```
Snapshots of prior runtimes are saved in `/var/backups/hecate-service-isolation/`.

---

## 6. Troubleshooting & Operational Guardrails

* **Interpreter Invocation (`pydantic_core` error):**
  Always invoke the bundled runtime interpreter directly (`/opt/hecate/runtime/venv/bin/python`), rather than system `python3` or passing `sys.path`. The system Python may lack compiled native wheels.

* **Workspace Permissions (`PermissionError` on .env or logs):**
  The shared workspace directory and files must be accessible by the `hecate-data` group.
  Ensure workspace files maintain mode `0660` (or `2770` for directories) owned by `<operator>:hecate-data`.
  Run file operations inside the workspace via `sg hecate-data -c "..."`.

* **SIEM Query Synchronization & Drift:**
  To check whether live deployed queries in your SIEM match local git definitions:
  ```bash
  hecate-runner audit-siem --platform splunk
  # To force immediate reconciliation:
  hecate-runner reconcile-queries --all --platform splunk
  ```

### Update models with a runtime release

The isolated runtime updater can change the cloud model and extraction routing in
the same drained update. For example, pass `--complex-model anthropic/claude-sonnet-4-6`
and `--source-extraction-tier complex` alongside `--runtime-stage /path/to/prepared-stage`.
The local backend and other capability routes are preserved. Private configuration
backups are retained with the runtime recovery snapshot. Failed startup or routing
checks restore both the previous runtime and the previous environment files.
Model-routing canaries are offline; they do not send API requests.

`HECATE_LLM_CAPABILITY_TIERS` is a JSON object, for example
`{"source_extraction":"complex"}`. Runner forwards it to isolated API workers.
These overrides retain the existing restrictions on moving critical work to the
simple tier. Invalid mappings fail explicitly.
