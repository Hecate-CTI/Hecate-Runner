"""Runtime replacement keeps a recoverable selection and requires root."""

import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "runtime_updater", Path(__file__).resolve().parents[1] / "scripts/update-service-runtime.py"
)
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)


def test_runtime_selection_is_atomic_and_can_restore_the_previous_release(tmp_path):
    previous = tmp_path / "old"
    candidate = tmp_path / "new"
    previous.mkdir()
    candidate.mkdir()
    current = tmp_path / "runtime"
    current.symlink_to(previous)
    updater.select_runtime(current, candidate)
    assert current.resolve() == candidate
    updater.select_runtime(current, previous)
    assert current.resolve() == previous
    assert not list(tmp_path.glob(".runtime-update-*"))


def test_failed_swap_preserves_the_running_selection(tmp_path, monkeypatch):
    previous = tmp_path / "old"
    previous.mkdir()
    current = tmp_path / "runtime"
    current.symlink_to(previous)

    def fail_replace(*args):
        raise OSError("fixture swap failure")

    monkeypatch.setattr(updater.os, "replace", fail_replace)
    with pytest.raises(OSError):
        updater.select_runtime(current, tmp_path / "new")
    assert current.resolve() == previous
    assert not list(tmp_path.glob(".runtime-update-*"))


def test_unprivileged_updates_stop_before_host_mutations(tmp_path, monkeypatch):
    monkeypatch.setattr(updater.os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError, match="sudo"):
        updater.update(tmp_path)


def test_canaries_use_actual_shared_reference_setting_without_credentials(tmp_path, monkeypatch):
    import subprocess

    calls = []

    def command(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="123\n")

    original = Path.read_bytes
    credential_name = "_".join(("OPENAI", "API", "KEY"))

    def environ(path):
        if path == Path("/proc/123/environ"):
            values = {
                "HOME": "/private/reader",
                "HECATE_WORKSPACE": "/workspace",
                "HECATE_STIX_CACHE": "/reference/attack",
                credential_name: "must-not-copy",
            }
            return b"\0".join(f"{key}={value}".encode() for key, value in values.items())
        return original(path)

    monkeypatch.setattr(updater.installer, "command", command)
    monkeypatch.setattr(Path, "read_bytes", environ)
    updater.check_service_canaries("hecate-runner-daemon", "reader", tmp_path)
    args, options = calls[-1]
    assert args[:4] == ("/usr/bin/nsenter", "--target", "123", "--mount")
    assert "hecate-reader" in args
    assert options["env"]["HECATE_STIX_CACHE"] == "/reference/attack"
    assert credential_name not in options["env"]
    assert "must-not-copy" not in repr(calls)


def test_canaries_reject_missing_live_service_before_entering_namespace(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setattr(
        updater.installer,
        "command",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="0\n"),
    )
    with pytest.raises(ValueError, match="No live process"):
        updater.check_service_canaries("hecate-runner-daemon", "reader", tmp_path)


def test_model_change_preserves_local_backend_and_other_capability_routes():
    import json

    before = {
        "HECATE_LLM_MODEL": "anthropic/claude-sonnet-4-5-20250929",
        "HECATE_LLM_SIMPLE_MODEL": "qwen3.6:35b-a3b-q4_K_M",
        "HECATE_LLM_CAPABILITY_TIERS": '{"research_summarize":"simple"}',
    }
    changes = updater.model_environment_changes(before, "anthropic/claude-sonnet-5-5", "complex")
    assert changes["HECATE_LLM_COMPLEX_MODEL"] == "anthropic/claude-sonnet-5-5"
    assert changes["HECATE_LLM_MODEL"] == "anthropic/claude-sonnet-5-5"
    assert "HECATE_LLM_SIMPLE_MODEL" not in changes
    assert json.loads(changes["HECATE_LLM_CAPABILITY_TIERS"]) == {
        "research_summarize": "simple",
        "source_extraction": "complex",
    }


def test_environment_rewrite_keeps_unrelated_assignments_verbatim():
    import json
    import shlex

    raw = '# retained comment\nANTHROPIC_API_KEY="private-fixture-value"\nHECATE_LLM_COMPLEX_MODEL="old"\n'
    changes = {
        "HECATE_LLM_COMPLEX_MODEL": "anthropic/claude-sonnet-5-5",
        "HECATE_LLM_CAPABILITY_TIERS": json.dumps({"source_extraction": "complex"}),
    }
    updated = updater.replace_environment_values(raw, changes)
    assert '# retained comment\nANTHROPIC_API_KEY="private-fixture-value"\n' in updated
    values = dict(
        shlex.split(line)[0].split("=", 1)
        for line in updated.splitlines()
        if line and not line.startswith("#")
    )
    assert json.loads(values["HECATE_LLM_CAPABILITY_TIERS"]) == {"source_extraction": "complex"}
    assert values["HECATE_LLM_COMPLEX_MODEL"] == changes["HECATE_LLM_COMPLEX_MODEL"]


def test_atomic_environment_update_preserves_permissions_and_rejects_links(tmp_path):
    import os
    import stat

    path = tmp_path / "reader.env"
    path.write_text("MODEL=old\n")
    path.chmod(0o640)
    updater.write_environment(path, "MODEL=new\n")
    assert path.read_text() == "MODEL=new\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    os.link(path, tmp_path / "alias")
    with pytest.raises(ValueError, match="unsafe"):
        updater.write_environment(path, "MODEL=bad\n")
    assert path.read_text() == "MODEL=new\n"


@pytest.mark.parametrize("fail_models", [False, True])
def test_coordinated_model_rollout_restores_config_and_runtime_on_failure(
    tmp_path, monkeypatch, fail_models
):
    import subprocess

    prefix = tmp_path / "opt"
    previous = prefix / "releases/old"
    previous.mkdir(parents=True)
    current = prefix / "runtime"
    current.symlink_to(previous)
    stage = tmp_path / "stage"
    (stage / "venv/bin").mkdir(parents=True)
    (stage / "venv/bin/python").touch()
    env_root = tmp_path / "etc"
    env_root.mkdir()
    backup_root = tmp_path / "backups"
    backup_root.mkdir()
    originals = {
        role: 'HECATE_LLM_COMPLEX_MODEL="old"\nANTHROPIC_API_KEY="private-fixture"\n'
        for role in updater.installer.ROLES
    }
    for role, raw in originals.items():
        (env_root / f"{role}.env").write_text(raw)
    monkeypatch.setattr(updater, "ENV_ROOT", env_root)
    monkeypatch.setattr(updater, "BACKUP_ROOT", backup_root)
    monkeypatch.setattr(updater, "managed_prefix", lambda: prefix)
    monkeypatch.setattr(updater.os, "geteuid", lambda: 0)
    monkeypatch.setattr(updater.os, "umask", lambda *_: 0)
    monkeypatch.setattr(
        updater, "installed_environment", lambda role: {"HECATE_LLM_COMPLEX_MODEL": "old"}
    )
    monkeypatch.setattr(updater, "write_environment", lambda path, raw: path.write_text(raw))
    monkeypatch.setattr(
        updater.installer, "prepare_runtime", lambda stage, release: release.mkdir()
    )
    preflights = []
    monkeypatch.setattr(
        updater.installer,
        "check_role_runtime",
        lambda role, release, workspace, values: preflights.append(values),
    )
    stops = []
    monkeypatch.setattr(
        updater.installer, "stop_existing_units", lambda *units: stops.append(units)
    )
    monkeypatch.setattr(updater, "check_service_canaries", lambda *args: None)

    def models(*args):
        if fail_models:
            raise RuntimeError("fixture routing mismatch")

    monkeypatch.setattr(updater, "check_service_models", models)
    monkeypatch.setattr(updater.time, "sleep", lambda *_: None)

    def command(*args, **kwargs):
        output = "123\n"
        if "--property=User" in args:
            unit = args[2]
            output = {
                "hecate-runner-daemon": "hecate-reader",
                "hecate-runner-maintenance": "hecate-writer",
                "hecate-slack-bot": "hecate-slack",
                "hecate-bas-broker": "hecate-bas",
            }[unit] + "\n"
        return subprocess.CompletedProcess(args, 0, stdout=output)

    monkeypatch.setattr(updater.installer, "command", command)
    if fail_models:
        with pytest.raises(RuntimeError, match="restoration attempted"):
            updater.update(
                stage, complex_model="anthropic/claude-sonnet-5-5", source_extraction_tier="complex"
            )
        assert current.resolve() == previous
        for role, raw in originals.items():
            assert (env_root / f"{role}.env").read_text() == raw
        assert len(stops) == 2
    else:
        updater.update(
            stage, complex_model="anthropic/claude-sonnet-5-5", source_extraction_tier="complex"
        )
        assert current.resolve() != previous
        for role in originals:
            assert (
                'HECATE_LLM_COMPLEX_MODEL="anthropic/claude-sonnet-5-5"'
                in (env_root / f"{role}.env").read_text()
            )
        assert len(stops) == 1
    assert all(
        values["HECATE_LLM_COMPLEX_MODEL"] == "anthropic/claude-sonnet-5-5" for values in preflights
    )
    for role, raw in originals.items():
        assert next(backup_root.glob(f"*/{role}.env")).read_text() == raw
