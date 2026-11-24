"""BAS publish credit is live-only; mock/skip must not look verified."""

from __future__ import annotations

from hecate_runner.bas.approved import confirms_technique, result_status
from hecate_runner.hunt_writer import DraftHuntRequest, render_draft
from hecate_runner.hecate_client import HypothesisResult
from datetime import UTC, datetime


def _hyp() -> HypothesisResult:
    return HypothesisResult(
        hypothesis="Adversaries dump LSASS.",
        justification="CTI",
        techniques=["T1003.001"],
        data_sources=["process_creation"],
        observables=["lsass"],
        false_positives=["diag"],
        actor="a",
        behavior="b",
        location="l",
        evidence="e",
        is_threat_report=True,
        is_indicator_only=False,
    )


def test_confirms_technique_rejects_mock_verified_label() -> None:
    assert (
        confirms_technique(
            {
                "status": "verified_true_positive",
                "provider": "mock",
                "fidelity_scope": "behavioral",
            }
        )
        is False
    )
    assert (
        result_status(
            {
                "status": "verified_true_positive",
                "provider": "mock",
                "fidelity_scope": "behavioral",
            }
        )
        == "simulation_match"
    )


def test_confirms_technique_rejects_simulation_and_fallback() -> None:
    assert confirms_technique({"status": "simulation_match", "provider": "caldera"}) is False
    assert (
        confirms_technique(
            {
                "status": "verified_true_positive",
                "provider": "caldera",
                "mock_fallback": True,
                "fidelity_scope": "behavioral",
            }
        )
        is False
    )


def test_confirms_technique_accepts_live_behavioral() -> None:
    assert (
        confirms_technique(
            {
                "status": "verified_true_positive",
                "provider": "caldera",
                "fidelity_scope": "behavioral",
            }
        )
        is True
    )


def test_render_skipped_bas_is_optional_not_required() -> None:
    hyp = _hyp()
    md = render_draft(
        DraftHuntRequest(
            hunt_id="H-0990",
            threat_intel="intel",
            hypothesis=hyp,
            generated_at=datetime(2026, 11, 24, tzinfo=UTC),
            platforms=["linux"],
            bas_verification={
                "status": "skipped",
                "provider": "caldera",
                "reason": "No approved lab platform for this hunt (Linux lab only).",
            },
        )
    )
    assert "Optional — skipped" in md
    assert "not required for publish" in md
    assert "bas_verified:" not in md.split("---", 2)[1]


def test_render_mock_bas_never_sets_bas_verified_true() -> None:
    hyp = _hyp()
    md = render_draft(
        DraftHuntRequest(
            hunt_id="H-0991",
            threat_intel="intel",
            hypothesis=hyp,
            generated_at=datetime(2026, 11, 24, tzinfo=UTC),
            platforms=["linux"],
            bas_verification={
                "status": "verified_true_positive",
                "provider": "mock",
                "fidelity_scope": "behavioral",
                "technique_id": "T1059.004",
                "telemetry_arrived": True,
                "rule_triggered": True,
                "matched_events_count": 1,
            },
        )
    )
    assert "bas_verified: false" in md
    assert "not live BAS credit" in md or "SYNTHETIC" in md
    assert "bas_live: false" in md
