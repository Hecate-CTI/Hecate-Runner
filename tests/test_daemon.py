"""Tests for `hecate-runner daemon` command."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from hecate_runner import cli
from hecate_runner.cli import app
from hecate_runner.orchestrator import RunResult

runner = CliRunner()


@pytest.fixture
def cli_env(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr("hecate_runner.integration_checks.start_health_refresh", lambda _: None)
    monkeypatch.setenv("HECATE_WORKSPACE", str(workspace))
    monkeypatch.setenv("HECATE_RUNNER_MAX_DRAFTS_PER_DAY", "10")
    monkeypatch.setenv("HECATE_RUNNER_DAEMON_INTERVAL_SEC", "1")
    return workspace


class TestDaemonCommand:
    def test_daemon_max_cycles_runs_and_exits_zero(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_count = 0

        class FakeOrch:
            def run_once(self, dry_run: bool = False) -> RunResult:
                nonlocal call_count
                call_count += 1
                return RunResult(
                    outcome="drafted",
                    detail="draft created",
                    hunt_id=f"H-000{call_count}",
                    research_id=f"R-000{call_count}",
                    draft_path=Path(f"/tmp/H-000{call_count}.md"),
                )

        monkeypatch.setattr(
            cli, "build_default_orchestrator", lambda s, ignore_quota=False: FakeOrch()
        )

        result = runner.invoke(app, ["daemon", "--max-cycles", "2", "--interval", "1"])
        assert result.exit_code == 0
        assert call_count == 2
        assert "Reached max cycles (2). Exiting daemon." in result.output
        assert "Hecate daemon shut down gracefully after 2 cycles." in result.output

    def test_daemon_handles_empty_queue(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_count = 0

        class FakeOrch:
            def run_once(self, dry_run: bool = False) -> RunResult:
                nonlocal call_count
                call_count += 1
                return RunResult(outcome="empty", detail="Queue empty")

        monkeypatch.setattr(
            cli, "build_default_orchestrator", lambda s, ignore_quota=False: FakeOrch()
        )

        result = runner.invoke(app, ["daemon", "--max-cycles", "1", "--interval", "1"])
        assert result.exit_code == 0
        assert call_count == 1
        assert "Outcome: empty" in result.output

    def test_daemon_spacing_cooldown_sleeps_appropriate_duration(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        slept_durations: list[float] = []

        class FakeOrch:
            def run_once(self, dry_run: bool = False) -> RunResult:
                return RunResult(
                    outcome="spacing_cooldown",
                    detail="1.9h/6.0h",
                    cooldown_remaining_sec=14760.0,
                )

        monkeypatch.setattr(
            cli, "build_default_orchestrator", lambda s, ignore_quota=False: FakeOrch()
        )
        monkeypatch.setattr(
            "threading.Event.wait",
            lambda self, timeout=None: (
                slept_durations.append(timeout) if timeout is not None else None
            ),
        )

        result = runner.invoke(app, ["daemon", "--max-cycles", "2", "--interval", "60"])
        assert result.exit_code == 0
        assert "Outcome: spacing_cooldown" in result.output
        assert slept_durations == [900.0]

    def test_daemon_fatal_exception_exits_one(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class CrashingOrch:
            def run_once(self, dry_run: bool = False) -> RunResult:
                raise RuntimeError("Disk corrupted")

        monkeypatch.setattr(
            cli, "build_default_orchestrator", lambda s, ignore_quota=False: CrashingOrch()
        )

        result = runner.invoke(app, ["daemon", "--max-cycles", "1"])
        assert result.exit_code == 1
        assert "Fatal daemon exception: Disk corrupted" in result.output

    def test_daemon_max_cycles_zero_runs_nothing(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_count = 0

        class FakeOrch:
            def run_once(self, dry_run: bool = False) -> RunResult:
                nonlocal call_count
                call_count += 1
                return RunResult(outcome="empty")

        monkeypatch.setattr(
            cli, "build_default_orchestrator", lambda s, ignore_quota=False: FakeOrch()
        )

        result = runner.invoke(app, ["daemon", "--max-cycles", "0", "--interval", "1"])
        assert result.exit_code == 0
        assert call_count == 0
        assert "after 0 cycles" in result.output

    def test_daemon_rejects_negative_interval(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            cli,
            "build_default_orchestrator",
            lambda s, ignore_quota=False: (_ for _ in ()).throw(AssertionError("should not build")),
        )
        result = runner.invoke(app, ["daemon", "--max-cycles", "1", "--interval", "-1"])
        assert result.exit_code == 1
        assert "Invalid --interval" in result.output

    def test_daemon_sweep_job_bounded_by_locks(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from hecate_runner.commands.daemon import _execute_sweep_job
        from hecate_runner.config import Settings
        from hecate_runner.work_locks import acquire_work_lock

        settings = Settings(
            hecate_workspace=cli_env,
            auto_hunt_execution_enabled=True,
        )

        ran_sweeps = False

        class MockScheduler:
            def __init__(self, *args, **kwargs):
                pass

            def run_scheduled_sweeps(self):
                nonlocal ran_sweeps
                ran_sweeps = True
                return []

        monkeypatch.setattr(
            "hecate_runner.execution.scheduler.HuntExecutionScheduler",
            MockScheduler,
        )

        # 1. Normal execution acquires lock and runs
        res = _execute_sweep_job(settings)
        assert ran_sweeps is True
        assert res == []

        # 2. When lock is held by another worker, tick is skipped nonblockingly
        lock_path = cli_env / ".hecate" / "sweeps.lock"
        held_lock = acquire_work_lock(lock_path)
        assert held_lock is not None
        try:
            ran_sweeps = False
            res_blocked = _execute_sweep_job(settings)
            assert res_blocked is None
            assert ran_sweeps is False
        finally:
            held_lock.close()

    def test_daemon_replay_job_bounded_by_locks(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from hecate_runner.commands.daemon import _execute_replay_job
        from hecate_runner.config import Settings
        from hecate_runner.work_locks import acquire_work_lock

        settings = Settings(
            hecate_workspace=cli_env,
            purple_team_continuous_replay_interval_sec=10,
        )

        ran_replay = False

        def mock_sweep(s):
            nonlocal ran_replay
            ran_replay = True
            return [{"hunt_id": "H-0001", "passed_rules": 1, "total_rules": 1}]

        monkeypatch.setattr(
            "hecate_runner.purple_team.run_continuous_replay_sweep",
            mock_sweep,
        )

        # 1. Normal execution acquires lock and runs
        res = _execute_replay_job(settings)
        assert ran_replay is True
        assert len(res) == 1

        # 2. When lock is held by another worker, tick is skipped nonblockingly
        lock_path = cli_env / ".hecate" / "replay.lock"
        held_lock = acquire_work_lock(lock_path)
        assert held_lock is not None
        try:
            ran_replay = False
            res_blocked = _execute_replay_job(settings)
            assert res_blocked is None
            assert ran_replay is False
        finally:
            held_lock.close()

    def test_daemon_sweep_worker_runs_independently_of_long_cycle(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        from hecate_runner.config import Settings

        sweep_count = 0

        def mock_sweep_job(settings, console=None):
            nonlocal sweep_count
            sweep_count += 1
            return []

        monkeypatch.setattr(
            "hecate_runner.commands.daemon._execute_sweep_job",
            mock_sweep_job,
        )

        class SlowOrch:
            def run_once(self, dry_run: bool = False) -> RunResult:
                time.sleep(0.5)
                return RunResult(outcome="drafted", hunt_id="H-0001")

        monkeypatch.setattr(cli, "build_default_orchestrator", lambda s, **kwargs: SlowOrch())

        mock_settings = Settings(
            hecate_workspace=cli_env,
            auto_hunt_execution_enabled=True,
        )
        object.__setattr__(mock_settings, "auto_hunt_sweep_interval_sec", 0.1)
        monkeypatch.setattr("hecate_runner.commands.daemon._get_settings", lambda: mock_settings)

        result = runner.invoke(app, ["daemon", "--max-cycles", "1", "--interval", "1"])
        assert result.exit_code == 0
        # Sweep worker executed on its 0.1s interval while the 0.5s slow cycle ran
        assert sweep_count >= 2
