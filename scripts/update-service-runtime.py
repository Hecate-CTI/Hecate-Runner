#!/usr/bin/env python3
"""Replace an installed isolated runtime without rerunning the account migration."""

from __future__ import annotations

import argparse
import fcntl
import grp
import importlib.util
import json
import os
import shlex
import stat
import subprocess
import time
from contextlib import suppress
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "isolated_installer", Path(__file__).with_name("install-isolated-services.py")
)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)

ENV_ROOT = Path("/etc/hecate")
BACKUP_ROOT = Path("/var/backups/hecate-service-isolation")


def managed_prefix() -> Path:
    prefix = Path("/opt/hecate")
    if prefix.is_symlink() or prefix.stat().st_uid != 0 or prefix.stat().st_mode & 0o022:
        raise ValueError("Runtime prefix must be protected and administrator-owned")
    return prefix


def installed_environment(role: str) -> dict[str, str]:
    path = ENV_ROOT / f"{role}.env"
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != grp.getgrnam(f"hecate-{role}").gr_gid
        or stat.S_IMODE(info.st_mode) != 0o640
    ):
        raise ValueError(f"Unexpected ownership or permissions for {role}.env")
    result = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = shlex.split(line)
        if len(tokens) != 1 or "=" not in tokens[0]:
            raise ValueError(f"Invalid installed configuration for {role}")
        name, value = tokens[0].split("=", 1)
        result[name] = value
    return result


def select_runtime(current: Path, target: Path) -> None:
    temporary = current.with_name(f".runtime-update-{os.getpid()}")
    temporary.symlink_to(target)
    try:
        os.replace(temporary, current)
    finally:
        temporary.unlink(missing_ok=True)


def check_service_canaries(unit: str, role: str, current: Path) -> None:
    """Offline checks in the running role's mount namespace; no model calls."""
    pid = installer.command(
        "/usr/bin/systemctl", "show", unit, "--property=MainPID", "--value"
    ).stdout.strip()
    if not pid.isdigit() or int(pid) <= 1:
        raise ValueError(f"No live process for {unit}")
    # Carry only nonsecret configuration from the actual process, including
    # shared reference settings supplied by systemd drop-ins.
    allowed = {"HOME", "HECATE_WORKSPACE", "HECATE_STIX_CACHE"}
    env = {}
    for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
        key, separator, value = item.partition(b"=")
        if separator and key.decode() in allowed:
            env[key.decode()] = value.decode()
    if not {"HOME", "HECATE_WORKSPACE"} <= env.keys():
        raise ValueError(f"Missing runtime environment for {unit}")
    env.update(PATH="/usr/bin:/bin", HECATE_SERVICE_ISOLATED="1", PYTHON_DOTENV_DISABLED="1")
    code = """
import os
import subprocess
import sys
from pathlib import Path
from hecate_runner.hecate_client import HecateClient, HecateError
from hecate_runner.subprocess_utils import run_process_group

cache = os.environ.get("HECATE_STIX_CACHE")
if cache:
    from hecate_agent.api import lookup_technique
    for tid, name in {"T1059.001": "PowerShell", "T1059.002": "AppleScript", "T1059.007": "JavaScript"}.items():
        assert lookup_technique(tid).get("name") == name
    for path in (Path(cache), Path(cache) / "enterprise-attack.json", Path(cache) / "enterprise-attack.sqlite3"):
        assert os.access(path, os.R_OK) and not os.access(path, os.W_OK)
client = HecateClient(Path(sys.executable), Path(os.environ["HECATE_WORKSPACE"]))
try:
    client._run_stage("readiness-probe", {}, 10)
except HecateError as exc:
    assert str(exc) == "readiness-probe API call failed in isolated worker"
else:
    raise RuntimeError("Worker accepted an unsupported operation")
try:
    run_process_group([sys.executable, "-I", "-c", "import time; time.sleep(30)"], timeout=0.1)
except subprocess.TimeoutExpired:
    pass
else:
    raise RuntimeError("Process deadline failed")
"""
    installer.command(
        "/usr/bin/nsenter",
        "--target",
        pid,
        "--mount",
        "--",
        "/usr/sbin/runuser",
        "-u",
        f"hecate-{role}",
        "--",
        str(current / "venv/bin/python"),
        "-I",
        "-c",
        code,
        env=env,
        cwd=current,
    )


def model_environment_changes(
    values: dict[str, str], model: str | None, source_tier: str | None
) -> dict[str, str]:
    """Nonsecret overrides; keep the configured local backend and other routing."""
    changes: dict[str, str] = {}
    if model:
        if not model.startswith("anthropic/claude-") or any(char.isspace() for char in model):
            raise ValueError("Expected an explicit Anthropic model ID")
        changes.update(HECATE_LLM_COMPLEX_PROVIDER="litellm", HECATE_LLM_COMPLEX_MODEL=model)
        if values.get("HECATE_LLM_MODEL", "").startswith("anthropic/"):
            changes["HECATE_LLM_MODEL"] = model
    if source_tier:
        if source_tier not in {"simple", "complex"}:
            raise ValueError("Source extraction tier must be simple or complex")
        mapping = json.loads(values.get("HECATE_LLM_CAPABILITY_TIERS", "{}"))
        if not isinstance(mapping, dict):
            raise ValueError("Installed capability routing must be an object")
        mapping["source_extraction"] = source_tier
        changes["HECATE_LLM_CAPABILITY_TIERS"] = json.dumps(mapping, sort_keys=True)
    return changes


def replace_environment_values(raw: str, changes: dict[str, str]) -> str:
    """Preserve credentials/comments verbatim; replace only requested assignments."""
    pending = dict(changes)
    result = []
    for line in raw.splitlines():
        stripped = line.strip()
        key = stripped.partition("=")[0] if not stripped.startswith("#") else ""
        if key in changes:
            if key not in pending:
                raise ValueError("Duplicate installed model environment assignment")
            result.append(key + "=" + json.dumps(pending.pop(key)))
        else:
            result.append(line)
    result.extend(key + "=" + json.dumps(value) for key, value in pending.items())
    return "\n".join(result) + "\n"


def write_environment(path: Path, raw: str) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
        raise ValueError("Refusing unsafe installed environment file")
    temporary = path.with_name(f".{path.name}.model-update-{os.getpid()}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def check_service_models(
    unit: str, role: str, current: Path, model: str | None, source_tier: str | None
) -> None:
    pid = installer.command(
        "/usr/bin/systemctl", "show", unit, "--property=MainPID", "--value"
    ).stdout.strip()
    if not pid.isdigit() or int(pid) <= 1:
        raise ValueError("Service model check requires a running worker")
    allowed = {
        "HOME",
        "HECATE_WORKSPACE",
        "HECATE_LLM_PROVIDER",
        "HECATE_LLM_MODEL",
        "HECATE_LLM_SIMPLE_PROVIDER",
        "HECATE_LLM_SIMPLE_MODEL",
        "HECATE_LLM_SIMPLE_BASE_URL",
        "HECATE_LLM_COMPLEX_PROVIDER",
        "HECATE_LLM_COMPLEX_MODEL",
        "HECATE_LLM_COMPLEX_BASE_URL",
        "HECATE_LLM_CAPABILITY_TIERS",
    }
    env = {}
    for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
        key, separator, value = item.partition(b"=")
        if separator and key.decode() in allowed:
            env[key.decode()] = value.decode()
    env.update(PATH="/usr/bin:/bin", HECATE_SERVICE_ISOLATED="1", PYTHON_DOTENV_DISABLED="1")
    code = """
import sys
from hecate_agent.core.llm_router import create_router
router = create_router()
if sys.argv[1]:
    assert router._providers['complex'].model == sys.argv[1]
if sys.argv[2]:
    assert router.resolve_tier(capability='source_extraction') == sys.argv[2]
assert router.resolve_tier(capability='sigma_draft') == 'complex'
assert router.resolve_tier(capability='sigma_review') == 'complex'
print('Offline model routing check passed')
"""
    installer.command(
        "/usr/bin/nsenter",
        "--target",
        pid,
        "--mount",
        "--",
        "/usr/sbin/runuser",
        "-u",
        f"hecate-{role}",
        "--",
        str(current / "venv/bin/python"),
        "-I",
        "-c",
        code,
        model or "",
        source_tier or "",
        env=env,
        cwd=current,
    )


def update(
    stage: Path, *, complex_model: str | None = None, source_extraction_tier: str | None = None
) -> None:
    if os.geteuid() != 0:
        raise PermissionError("Runtime replacement requires sudo")
    os.umask(0o007)
    prefix = managed_prefix()
    current = prefix / "runtime"
    if not current.is_symlink():
        raise ValueError("An isolated runtime must already be installed")
    previous = current.resolve()
    if not previous.is_relative_to(prefix / "releases"):
        raise ValueError("Current runtime is not a managed release")
    stage = stage.resolve()
    if not (stage / "venv/bin/python").is_file():
        raise ValueError("Prepared runtime is missing")
    # Run the candidate's installed packages, not the checkout invoking this
    # updater. Missing protections stop the update before backups or draining.
    installer.command(
        str(stage / "venv/bin/python"),
        "-I",
        "-m",
        "hecate_runner.runtime_contract",
        cwd=stage,
        env={
            "PATH": "/usr/bin:/bin",
            "HECATE_SERVICE_ISOLATED": "1",
            "PYTHON_DOTENV_DISABLED": "1",
        },
    )
    envs = {role: installed_environment(role) for role in installer.ROLES}
    updates = {
        role: model_environment_changes(values, complex_model, source_extraction_tier)
        for role, values in envs.items()
    }
    originals = {
        role: (ENV_ROOT / f"{role}.env").read_text() for role in installer.ROLES if updates[role]
    }
    proposed = {
        role: replace_environment_values(originals[role], updates[role]) for role in originals
    }
    for unit, role in zip(installer.UNITS, (*installer.ROLES, "bas"), strict=True):
        installer.command("/usr/bin/systemctl", "is-active", unit)
        user = installer.command(
            "/usr/bin/systemctl", "show", unit, "--property=User", "--value"
        ).stdout.strip()
        if user != f"hecate-{role}":
            raise ValueError("Expected isolated service identities before a runtime update")
    stamp = time.strftime("%Y%m%dT%H%M%S")
    backup = BACKUP_ROOT / f"runtime-{stamp}"
    backup.mkdir(mode=0o700)
    (backup / "previous-runtime.json").write_text(json.dumps({"runtime": str(previous)}))
    for role, raw in originals.items():
        private = backup / f"{role}.env"
        private.write_text(raw)
        private.chmod(0o600)

    release = prefix / "releases" / f"{stamp}-runtime"
    phase = "runtime preparation"
    stopped = False
    try:
        installer.prepare_runtime(stage, release)
        for role in installer.ROLES:
            phase = f"{role} configuration preflight"
            installer.check_role_runtime(
                role, release, Path("/var/lib/hecate/workspace"), {**envs[role], **updates[role]}
            )
        phase = "stopping isolated services"
        stopped = True
        installer.stop_existing_units(*installer.UNITS)
        phase = "model configuration update"
        for role, raw in proposed.items():
            write_environment(ENV_ROOT / f"{role}.env", raw)
        select_runtime(current, release)
        phase = "starting updated services"
        installer.command("/usr/bin/systemctl", "start", "hecate-bas-broker", *installer.UNITS[:-1])
        time.sleep(3)
        for unit in installer.UNITS:
            installer.command("/usr/bin/systemctl", "is-active", unit)
        phase = "service-account worker and reference canaries"
        for unit, role in zip(installer.UNITS[:-1], installer.ROLES, strict=True):
            check_service_canaries(unit, role, current)
            if complex_model or source_extraction_tier:
                check_service_models(unit, role, current, complex_model, source_extraction_tier)
        phase = "publication outbox access verification"
        pid = installer.command(
            "/usr/bin/systemctl",
            "show",
            "hecate-runner-maintenance",
            "--property=MainPID",
            "--value",
        ).stdout.strip()
        if not pid.isdigit() or pid == "0":
            raise ValueError("Writer service has no live process")
        # Check only local SQLite access in the writer's real mount namespace.
        # This does not invoke a publisher client or send any remote request.
        code = (
            "import os; os.umask(0o007); "
            "from hecate_runner.config import Settings; "
            "from hecate_runner.github_publisher import outbox_for; "
            "from hecate_runner.misp_publisher import _connect; "
            "settings=Settings(); outbox_for(settings).summary(); "
            "context=_connect(settings); db=context.__enter__(); "
            "db.execute('SELECT count(*) FROM exports').fetchone(); "
            "context.__exit__(None,None,None)"
        )
        env = {
            **envs["writer"],
            **updates["writer"],
            "HOME": "/var/lib/hecate/homes/writer",
            "PATH": f"{current}/venv/bin:/usr/bin:/bin",
            "HECATE_SERVICE_ISOLATED": "1",
            "HECATE_STRICT_CREDENTIAL_ROLES": "1",
            "PYTHON_DOTENV_DISABLED": "1",
            "HECATE_WORKSPACE": "/var/lib/hecate/workspace",
        }
        installer.command(
            "/usr/bin/nsenter",
            "--target",
            pid,
            "--mount",
            "--",
            "/usr/sbin/runuser",
            "-u",
            "hecate-writer",
            "--",
            str(current / "venv/bin/python"),
            "-I",
            "-c",
            code,
            env=env,
            cwd=current,
        )
        print(
            "Updated isolated runtime active; role worker/reference canaries and outbox access verified."
        )
        print(f"Private recovery snapshot: {backup}")
    except Exception as failure:
        with suppress(OSError):
            installer.record_failure(backup, phase, failure)
        if stopped:
            with suppress(Exception):
                installer.stop_existing_units(*installer.UNITS)
            for role, raw in originals.items():
                write_environment(ENV_ROOT / f"{role}.env", raw)
            select_runtime(current, previous)
            installer.command(
                "/usr/bin/systemctl",
                "start",
                "hecate-bas-broker",
                *installer.UNITS[:-1],
                check=False,
            )
        raise RuntimeError(
            f"Runtime update failed during {phase}; prior runtime restoration attempted. "
            f"Private diagnostics: {backup}/failure.json"
        ) from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-stage", type=Path, required=True)
    parser.add_argument(
        "--complex-model",
        help="Replace the complex-tier Anthropic model while preserving the local backend",
    )
    parser.add_argument("--source-extraction-tier", choices=("simple", "complex"))
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise PermissionError("Runtime replacement requires sudo")
        fd = os.open(
            "/run/lock/hecate-runtime-update.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            update(
                args.runtime_stage,
                complex_model=args.complex_model,
                source_extraction_tier=args.source_extraction_tier,
            )
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
