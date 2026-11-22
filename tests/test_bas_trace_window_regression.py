"""Partial syscalls and PID reuse must not manufacture in-window evidence."""

import pytest

from hecate_runner.bas.sensor import LabSensorFusion, parse_exec_trace, parse_file_trace


@pytest.mark.parametrize("completion", [90.0, 106.0])
def test_resumed_exec_outside_window_or_before_start_is_not_evidence(completion):
    trace = (
        '20 101.000 execve("/usr/bin/whoami", ["whoami"], 0x0 <unfinished ...>\n'
        f"20 {completion:.3f} <... execve resumed>) = 0"
    )
    assert not parse_exec_trace(trace, start=100, end=105, host="fixture", command="whoami")


@pytest.mark.parametrize("completion", [90.0, 106.0])
def test_resumed_file_outside_window_or_before_start_is_not_evidence(completion):
    trace = (
        '20 101.000 openat(AT_FDCWD, "/tmp/probe", O_WRONLY|O_CREAT, 0666 <unfinished ...>\n'
        f"20 {completion:.3f} <... openat resumed> ) = 3"
    )
    assert not parse_file_trace(trace, start=100, end=105, host="fixture")


def test_file_event_cannot_inherit_a_future_process_with_reused_pid():
    events = [
        {"category": "file_event", "ProcessId": 20, "UtcTime": "2026-11-22T12:00:00+00:00"},
        {
            "category": "process_creation",
            "ProcessId": 20,
            "Image": "/usr/bin/whoami",
            "CommandLine": "whoami",
            "UtcTime": "2026-11-22T12:00:01+00:00",
        },
    ]
    fused = LabSensorFusion.correlate_lineage(events)
    assert "Image" not in fused[0]
    assert "CommandLine" not in fused[0]
