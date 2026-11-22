"""Live BAS proof must belong to the declared execution window."""

from datetime import UTC, datetime, timedelta

import pytest

from hecate_runner.bas.approved import APPROVED_PROCEDURES
from hecate_runner.bas.base import DetonationResult
from hecate_runner.bas.verifier import DetectionVerifier, VerificationStatus

RULE = """title: Identity discovery
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: /whoami
  condition: selection
"""


@pytest.fixture
def execution():
    start = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
    end = start + timedelta(seconds=5)
    procedure = APPROVED_PROCEDURES["T1033"]
    return DetonationResult(
        True,
        "H-0001",
        "T1033",
        procedure.ability_id,
        "caldera",
        start.isoformat(),
        end.isoformat(),
        5,
        0,
        "",
        "",
        cleanup_success=True,
    )


def verify(execution, events):
    return DetectionVerifier().verify_detonation(
        execution, rule_yaml=RULE, raw_events=events, backend="lab_process"
    )


@pytest.mark.parametrize(
    "value",
    [
        "2000-01-01T00:00:00Z",
        "2030-01-01T00:00:00Z",
        "bad",
        "",
        None,
        "2026-11-22T12:00:01",
        float("nan"),
        float("inf"),
        True,
    ],
)
def test_stale_future_and_invalid_events_cannot_grant_live_proof(execution, value):
    result = verify(execution, [{"Image": "/usr/bin/whoami", "timestamp_utc": value}])
    assert not result.rule_triggered
    assert not result.telemetry_arrived
    assert result.matched_events_count == 0
    assert result.status == VerificationStatus.TELEMETRY_MISSING


@pytest.mark.parametrize(
    "field,value",
    [
        ("timestamp_utc", "2026-11-22T12:00:01Z"),
        ("UtcTime", "2026-11-22T13:00:01+01:00"),
        ("_time", datetime(2026, 11, 22, 12, 0, 1, tzinfo=UTC).timestamp()),
        ("_time", str(datetime(2026, 11, 22, 12, 0, 1, tzinfo=UTC).timestamp())),
    ],
)
def test_valid_current_sensor_timestamp_formats_are_accepted(execution, field, value):
    result = verify(execution, [{"Image": "/usr/bin/whoami", field: value}])
    assert result.status == VerificationStatus.VERIFIED_TRUE_POSITIVE
    assert result.matched_events_count == 1


def test_mixed_events_only_count_in_window_proof(execution):
    events = [
        {"Image": "/usr/bin/whoami", "timestamp_utc": "2000-01-01T00:00:00Z"},
        {"Image": "/usr/bin/whoami", "timestamp_utc": "2026-11-22T12:00:02Z"},
        {"Image": "/usr/bin/whoami"},
        None,
        "invalid",
    ]
    result = verify(execution, events)
    assert result.status == VerificationStatus.VERIFIED_TRUE_POSITIVE
    assert result.matched_events_count == 1
    assert len(result.sample_matched_events) == 1


@pytest.mark.parametrize(
    "start,end",
    [
        ("bad", "bad"),
        ("2026-11-22T12:00:10Z", "2026-11-22T12:00:00Z"),
        ("2026-11-22T12:00:00", "2026-11-22T12:00:05"),
    ],
)
def test_bad_execution_clock_never_creates_fallback_proof(execution, start, end):
    execution.start_time_utc = start
    execution.end_time_utc = end
    result = verify(
        execution, [{"Image": "/usr/bin/whoami", "timestamp_utc": "2026-11-22T12:00:01Z"}]
    )
    assert result.status == VerificationStatus.ERROR
    assert not result.rule_triggered


def test_missing_time_is_allowed_only_for_explicit_synthetic_logic_probe(execution):
    execution.provider = "mock"
    result = verify(execution, [{"Image": "/usr/bin/whoami"}])
    assert result.status == VerificationStatus.SIMULATION_MATCH
    assert result.verification_scope == "synthetic_sigma_logic"
