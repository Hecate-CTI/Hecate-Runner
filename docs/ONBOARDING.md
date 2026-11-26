# Runner onboarding

Core provides the engine, Runner coordinates workflows, and the selected workspace
supplies knowledge and stores results. Choose catalog browsing, existing-hunt
execution or model-assisted generation after installation.

## Install once into a shared environment

Use Python 3.11.5+, Git, uv and Bash on Linux/macOS or WSL:

```bash
mkdir hecate-dev
cd hecate-dev
git clone https://github.com/Hecate-Org/Hecate-Core.git
git clone https://github.com/Hecate-Org/Hecate-Runner.git
git clone https://github.com/Hecate-Org/Hecate-Public.git
uv venv .venv
source .venv/bin/activate
uv pip install -e './Hecate-Core[all,dev]' -e './Hecate-Runner[dev]'
export HECATE_WORKSPACE="$PWD/Hecate-Public"
export HECATE_BIN="$PWD/.venv/bin/hecate-agent"
cd Hecate-Public
hecate-runner demo
hecate-agent hunt list
```

The demo uses temporary fixtures and needs no model, SIEM, Slack or BAS connection.
The organization `.github` repository is optional to clone. For a locked Runner
installation, see [dependency security](DEPENDENCY_SECURITY.md).

For subsequent Bash shells, save this as `hecate-dev/env.sh`:

```bash
# Source this file; executing it cannot update the parent shell.
HECATE_DEV_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$HECATE_DEV_ROOT/.venv/bin/activate"
export HECATE_WORKSPACE="$HECATE_DEV_ROOT/Hecate-Public"
export HECATE_BIN="$HECATE_DEV_ROOT/.venv/bin/hecate-agent"
```

Run `source /absolute/path/to/hecate-dev/env.sh` in a new shell. For enterprise
use, change the workspace export to your private workspace. Keep the same package
interpreter; `uv run --directory` may select a different project's environment.

## Workspace and secrets

Export an absolute `HECATE_WORKSPACE` before launching either application. Both
read its `.env`; existing environment values win and a cwd `.env` is an override.
No symlink is created automatically. Copy `.env.example` only when `.env` does not
exist, protect credentials with owner-only permissions, and do not source dotenv
files as shell scripts. Restart long-running processes after configuration changes.

Seed a private workspace with reviewed Public content. Complete
`knowledge/environment.md` with verified telemetry and adapt
`knowledge/hunting-knowledge.md` to local practice. Keep logs, `.hecate/`, private
findings and evidence there; bundled reference data does not establish coverage.

## Choose a workflow

### Offline evaluation

Run `hecate-runner demo` for the isolated fixture workflow or `hecate-agent hunt list`
to browse the selected catalog. `hecate-runner doctor` checks configuration and
can report missing optional capabilities; it is not a live execution test.

### Existing-hunt execution

Keep `HECATE_RUNNER_QUERY_PROVIDER=mock` for practice. For live queries, configure
a supported backend's endpoint and credentials. Keep
`HECATE_AUTO_HUNT_APPROVAL_REQUIRED=true` and use actual hunt and sweep IDs:

```bash
hecate-agent context --hunt H-0001 --format json
hecate-agent hunt update H-0001 --status active
hecate-runner sweep stage --hunt-id H-0001 --days 1
hecate-runner sweep pending
hecate-runner sweep approve "<SWEEP-ID>"
```

Approval uses the count-first gate and configured fetch limits. Continuous
scheduling uses `sweep daemon` and `HECATE_AUTO_HUNT_*`. It does not need CTI polling
or new hunts; optional analysis, pivots and tuning may use models.

### Model-assisted generation

Configure `HECATE_LLM_PROVIDER`, `HECATE_LLM_MODEL` and the relevant endpoint/key.
Web search has separate configuration; see [.env.example](../.env.example).

```bash
hecate-runner draft --file /path/to/intelligence.txt --dry-run
hecate-runner draft --file /path/to/intelligence.txt
```

`--url` supplies the primary report and `--title` the research topic. For queued
intake, select `HECATE_RUNNER_CTI_PROVIDER=file`, place a `.txt` item in
`<workspace>/cti_queue/`, and run `hecate-runner run`. Use `sources` commands for
supported feeds; `daemon` processes configured intake continuously under quotas.

## Setting up background services (Autonomous Node)

For production deployments, 24/7 continuous threat intelligence intake, scheduled hunt sweeps, continuous Purple Team replay verification, SIEM drift reconciliation, and Slack operations, Hecate runs as hardened background systemd services.

### Core service architecture

| Service Unit | Status | Purpose | Dedicated Account | Config File |
| :--- | :---: | :--- | :--- | :--- |
| **`hecate-runner-daemon`** | **Required** | Perpetual CTI intake, hypothesis drafting, active hunt sweeps, and continuous Purple Team verification | `hecate-reader` | `/etc/hecate/reader.env` |
| **`hecate-runner-maintenance`** | **Required** | SIEM query drift auditing/auto-reconciliation, GitHub PR & MISP outbox publishing, queue maintenance | `hecate-writer` | `/etc/hecate/writer.env` |
| **`hecate-slack-bot`** | **Recommended** | Interactive Socket Mode bot, slash commands (`/hecate status`, `/hecate hunt`), and multi-channel alerting | `hecate-slack` | `/etc/hecate/slack.env` |
| **`hecate-bas-broker`** | **Optional** | Unix domain socket broker (`/run/hecate-bas/broker.sock`) for sandboxed Docker adversary emulation | `root` / `docker` | *Supervised socket ACL* |

### Step 1: Initial automated setup

From the `Hecate-Runner` repository root, run the guided setup script:

```bash
# 1. Validate inputs and paths without installing:
./scripts/setup-services.sh --check

# 2. Run the guided installer with administrative privileges:
sudo ./scripts/setup-services.sh \
  --core ../Hecate-Core \
  --workspace ../Hecate-Public \
  --env-dir /etc/hecate
```

The installer:
1. Provisions dedicated non-login system accounts (`hecate-reader`, `hecate-writer`, `hecate-slack`) and group `hecate-data`.
2. Compiles and locks the isolated runtime under `/opt/hecate/releases/<timestamp>-runtime` and creates the active symlink `/opt/hecate/runtime`.
3. Seeds role-separated credential files in `/etc/hecate/` with permissions `0640`.
4. Hardens and enables the systemd unit files with `NoNewPrivileges=yes`, `ProtectSystem=strict`, and private namespaces.

### Step 2: Configure role environment files

Populate the required credentials in `/etc/hecate/` (permissions must be `0640` owned by `root:hecate-<role>`):

* **`/etc/hecate/reader.env` (`hecate-reader`):**
  Read-only ingestion keys. Contains `SPLUNK_READ_TOKEN`, `SPLUNK_HOST`, CTI feed API keys (e.g. `OTX_API_KEY`), and LLM configuration (`HECATE_LLM_PROVIDER`, `HECATE_LLM_MODEL`).
  > [!CAUTION]
  > Never put publishing keys (`SPLUNK_WRITE_TOKEN`, GitHub App private keys, or Slack app tokens) into `reader.env`.

* **`/etc/hecate/writer.env` (`hecate-writer`):**
  Publishing and maintenance keys. Contains `SPLUNK_WRITE_TOKEN`, `SPLUNK_READ_TOKEN` (for SIEM audits), `HECATE_RUNNER_SIEM_DRIFT_AUTO_RECONCILE=true`, GitHub App credentials (`HECATE_RUNNER_GITHUB_APP_PRIVATE_KEY_PATH`), and MISP publishing keys.

* **`/etc/hecate/slack.env` (`hecate-slack`):**
  Slack integration tokens (`SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`) and pinned channel IDs:
  - `SLACK_CHANNEL_HUNTS_EXEC`: Executive findings and PR notifications (e.g., `C0CC5R9S4EP`).
  - `SLACK_CHANNEL_THREAT_HUNTING`: Operational hunting and sweep findings feed (e.g., `C0CCA3NLN0N`).
  - `SLACK_CHANNEL_OPS_METRICS`: Daily consolidated operations pulse (e.g., `C0CC6PG0GAH`).

Starter templates are available in [`deploy/service-env/`](../deploy/service-env/).

### Step 3: Verify service health

Verify that all daemons have started cleanly:

```bash
# Check status across all units:
systemctl status hecate-runner-daemon.service hecate-runner-maintenance.service hecate-slack-bot.service hecate-bas-broker.service

# Follow live orchestrator logs:
journalctl -u hecate-runner-daemon.service -f

# Follow maintenance and SIEM drift reconciliation logs:
journalctl -u hecate-runner-maintenance.service -f

# Verify environment and dependency health:
hecate-runner doctor
```

### Step 4: Updating services after code changes

Production background services execute from the standalone isolated runtime at `/opt/hecate/runtime`. When code changes are committed or pulled into `Hecate-Core` or `Hecate-Runner`, do **not** run `pip install` directly. Instead, build and apply an atomic runtime update:

```bash
# 1. Build a new runtime stage as your normal unprivileged user:
scripts/prepare-service-runtime.sh ../Hecate-Core /tmp/hecate-runtime-stage

# 2. Apply the update atomically as root using the runtime's virtual environment:
sudo /opt/hecate/runtime/venv/bin/python scripts/update-service-runtime.py --runtime-stage /tmp/hecate-runtime-stage

# 3. Clean up the temporary staging directory:
rm -rf /tmp/hecate-runtime-stage
```

The update script gracefully drains running workers, swaps `/opt/hecate/runtime` atomically, runs runtime contract verification, and restarts the services. Automatic rollback snapshots are preserved in `/var/backups/hecate-service-isolation/`.

For detailed architecture and systemd hardening details, see [Background Services](SERVICES.md) and [Service Isolation](SERVICE_ISOLATION.md).

## Validation, publishing and services

| Guide | Use it for |
| --- | --- |
| [BAS automation](BAS_AUTOMATION.md) | Pinned Linux procedures, sensors, cleanup and evidence limits; `bas-check` executes lab procedures |
| [Community releases](COMMUNITY_RELEASES.md) | Exact public-snapshot review, redistribution and separate release approval |
| [Background services](SERVICES.md) | Dedicated service accounts/units and `scripts/setup-services.sh` |
| [Operating recipes](HOW_TO.md) | Commands and troubleshooting for feeds, execution, publication and monitoring |

`hecate-agent monitor` reads the selected workspace. Reopen it after code updates;
running processes do not reload edited source automatically.

## Contribute and verify

From each source repository with the shared venv active:

```bash
python -m pytest tests/ -q
ruff check .
```

Default tests isolate operator dotenv files and reject unmocked external calls.
Live checks require `-m network` and test-specific configuration. Keep those guards
in place. Core guide edits also require `python scripts/sync_docs.py --check`.
