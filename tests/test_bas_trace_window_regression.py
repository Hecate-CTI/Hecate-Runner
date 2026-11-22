"""Partial syscalls and PID reuse must not manufacture in-window evidence."""

from datetime import UTC, datetime, timedelta

import pytest

from hecate_runner.bas.sensor import (
    LabSensorFusion,
    parse_exec_trace,
    parse_file_trace,
    parse_net_trace,
)
from hecate_runner.bas.verifier import DetectionVerifier


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


def test_execveat_syscall_traced_successfully():
    trace = '20 101.000 execveat(AT_FDCWD, "/usr/bin/whoami", ["whoami"], 0x0) = 0'
    events = parse_exec_trace(trace, start=100, end=105, host="fixture", command="whoami")
    assert len(events) == 1
    assert events[0]["Image"] == "/usr/bin/whoami"
    assert events[0]["CommandLine"] == "whoami"


def test_execveat_resumed_syscall_traced_successfully():
    trace = (
        '20 101.000 execveat(AT_FDCWD, "/usr/bin/whoami", ["whoami"], 0x0 <unfinished ...>\n'
        "20 102.000 <... execveat resumed> ) = 0"
    )
    events = parse_exec_trace(trace, start=100, end=105, host="fixture", command="whoami")
    assert len(events) == 1
    assert events[0]["Image"] == "/usr/bin/whoami"
    assert events[0]["ProcessId"] == 20


def test_net_resumed_connect_traced_successfully():
    trace = (
        '25 101.500 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) <unfinished ...>\n'
        "25 102.100 <... connect resumed> ) = 0"
    )
    events = parse_net_trace(trace, start=100, end=105, host="fixture")
    assert len(events) == 1
    assert events[0]["DestinationIp"] == "1.2.3.4"
    assert events[0]["DestinationPort"] == 443
    assert events[0]["ProcessId"] == 25


def test_net_resumed_connect_einprogress_traced_successfully():
    trace = (
        '25 101.500 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.1")}, 16) <unfinished ...>\n'
        "25 102.200 <... connect resumed> ) = -1 EINPROGRESS (Operation now in progress)"
    )
    events = parse_net_trace(trace, start=100, end=105, host="fixture")
    assert len(events) == 1
    assert events[0]["DestinationIp"] == "10.0.0.1"
    assert events[0]["DestinationPort"] == 80


def test_lineage_enriches_empty_or_none_fields():
    events = [
        {
            "category": "network_connection",
            "ProcessId": 33,
            "UtcTime": "2026-11-22T12:00:02+00:00",
            "Image": "",
            "CommandLine": None,
        },
        {
            "category": "process_creation",
            "ProcessId": 33,
            "Image": "/usr/bin/curl",
            "CommandLine": "curl http://evil.com",
            "UtcTime": "2026-11-22T12:00:01+00:00",
        },
    ]
    fused = LabSensorFusion.correlate_lineage(events)
    net_event = next(ev for ev in fused if ev["category"] == "network_connection")
    assert net_event["Image"] == "/usr/bin/curl"
    assert net_event["CommandLine"] == "curl http://evil.com"


def test_event_in_window_timestamp_handling():
    start = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)
    end = datetime(2026, 11, 22, 12, 10, 0, tzinfo=UTC)

    # 1. Fallback to UtcTime when timestamp_utc is None
    ev1 = {"timestamp_utc": None, "UtcTime": "2026-11-22T12:05:00Z"}
    assert DetectionVerifier._event_in_window(ev1, start, end)

    # 2. Fallback when timestamp_utc is malformed string
    ev2 = {"timestamp_utc": "invalid-stamp", "UtcTime": "2026-11-22T12:05:00+00:00"}
    assert DetectionVerifier._event_in_window(ev2, start, end)

    # 3. Numeric epoch in timestamp_utc (seconds)
    mid_epoch = (start + timedelta(minutes=5)).timestamp()
    ev3 = {"timestamp_utc": mid_epoch}
    assert DetectionVerifier._event_in_window(ev3, start, end)

    # 4. Numeric epoch in timestamp_utc (milliseconds)
    ev4 = {"timestamp_utc": int(mid_epoch * 1000)}
    assert DetectionVerifier._event_in_window(ev4, start, end)

    # 5. Out of window
    ev5 = {"timestamp_utc": None, "UtcTime": "2026-11-22T11:50:00Z"}
    assert not DetectionVerifier._event_in_window(ev5, start, end)
