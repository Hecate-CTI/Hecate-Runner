"""Bounded BAS stress with private lease state and fake remote interfaces."""

import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from hecate_runner.bas.base import SafetyViolationError
from hecate_runner.bas.lifecycle import LabLease, reset_lab
from hecate_runner.bas.sensor import parse_exec_trace


def new_lease(root):
    return LabLease(root / "lease", root / "quarantine", root / "lock")


def test_parallel_attempts_never_enter_an_already_held_lab(tmp_path):
    lease = new_lease(tmp_path)
    blocked = []
    mutex = threading.Lock()

    def attempt(index):
        with (
            pytest.raises(SafetyViolationError, match="holds the active lab lease"),
            new_lease(tmp_path).acquire(f"H-{index:04d}"),
        ):
            raise AssertionError("Concurrent worker entered the held lease")
        with mutex:
            blocked.append(index)

    with lease.acquire("H-OWNER", timeout_sec=30), ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(attempt, range(64)))
    assert len(blocked) == 64
    assert not lease.is_quarantined()
    assert not lease.lease_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="Live Linux BAS uses flock")
def test_cross_process_attempts_are_refused_under_the_same_lease(tmp_path):
    lease = new_lease(tmp_path)
    code = """
import sys
from pathlib import Path
from hecate_runner.bas.lifecycle import LabLease
from hecate_runner.bas.base import SafetyViolationError
root=Path(sys.argv[1])
try:
    with LabLease(root/'lease',root/'quarantine',root/'lock').acquire('H-CHILD',timeout_sec=2):
        raise AssertionError('Child entered a held lease')
except SafetyViolationError:
    raise SystemExit(7)
"""
    with lease.acquire("H-PARENT", timeout_sec=30):
        for _ in range(4):
            result = subprocess.run(
                [sys.executable, "-I", "-c", code, str(tmp_path)], capture_output=True, timeout=10
            )
            assert result.returncode == 7
    assert not lease.is_quarantined()


def test_repeated_failure_reset_and_recovery_releases_watchdogs(tmp_path, monkeypatch):
    def fake_docker(args, **kwargs):
        output = "COMMAND\n/usr/bin/strace -f\n/usr/local/bin/sandcat\n" if args[0] == "top" else ""
        return subprocess.CompletedProcess(args, 0, output, "")

    monkeypatch.setattr("hecate_runner.bas.lifecycle.run_docker", fake_docker)
    lease = new_lease(tmp_path)
    threads = threading.active_count()
    for index in range(10):
        with (
            pytest.raises(RuntimeError, match="injected"),
            lease.acquire(f"H-{index:04d}", timeout_sec=10),
        ):
            raise RuntimeError("injected adapter failure")
        assert lease.is_quarantined()
        with pytest.raises(SafetyViolationError, match="quarantined"), lease.acquire("H-BLOCKED"):
            raise AssertionError("Quarantine bypassed")
        record = reset_lab("fixture-agent", workspace=tmp_path, lease=lease)
        assert record["status"] == "clean"
        with lease.acquire("H-RECOVERED", timeout_sec=10):
            pass
        assert not lease.lease_path.exists()
    assert threading.active_count() == threads
    assert len((tmp_path / ".hecate/bas/resets.jsonl").read_text().splitlines()) == 10


def test_trace_noise_cannot_create_false_positive_execution():
    noise = []
    for index in range(1000):
        noise.append(f'{index} 90.000 execve("/usr/bin/whoami", ["whoami"], 0x0) = 0')
        noise.append(f'{index} 101.000 execve("/usr/bin/whoami", ["whoami"], 0x0) = -1 ENOENT')
    noise.append('2000 102.000 execve("/usr/bin/whoami", ["whoami"], 0x0) = 0')
    events = parse_exec_trace(
        "\n".join(noise), start=100, end=105, host="fixture", command="whoami"
    )
    assert len(events) == 1
    assert events[0]["ProcessId"] == 2000
