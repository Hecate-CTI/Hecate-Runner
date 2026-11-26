"""Regression cases for unrelated samples, circular validation and unsafe widening."""

import hashlib
import json
from unittest.mock import patch

import pytest

from hecate_runner.config import Settings
from hecate_runner.continuous_replay import evaluate_hunt_replay, run_sweep
from hecate_runner.rule_tuner import RuleTuner

RULE = """title: Campaign DNS
logsource:
  product: macos
  category: dns_query
detection:
  selection:
    QueryName: campaign.invalid
  condition: selection
"""


def setup_case(tmp_path, positive=None, benign=None):
    query = tmp_path / "queries/H-0001/dns.yml"
    query.parent.mkdir(parents=True)
    query.write_text(RULE)
    path = tmp_path / ".hecate/replay_cases/H-0001.json"
    path.parent.mkdir(parents=True)
    rule_case = {
        "rule_sha256": hashlib.sha256(RULE.encode()).hexdigest(),
        "source_reference": "internal:independently-authored-case",
        "positive": positive if positive is not None else [{"QueryName": "campaign.invalid"}],
        "benign": benign if benign is not None else [{"QueryName": "example.com"}],
    }
    data = {"schema": 1, "hunt_id": "H-0001", "rules": {"dns.yml": rule_case}}
    path.write_text(json.dumps(data))
    return query, path, data


def test_missing_cases_are_unassessed_even_when_predicate_sanity_passes(tmp_path):
    _, path, _ = setup_case(tmp_path)
    path.unlink()
    result = evaluate_hunt_replay(tmp_path, "H-0001")
    assert result["passed_rules"] == result["failed_rules"] == 0
    assert result["not_assessed_rules"] == result["sanity_passed_rules"] == 1
    assert result["fidelity"] == "unavailable"
    assert result["sample_events_count"] == 0


def test_exact_source_cases_pass_but_never_claim_live_or_holdout_validation(tmp_path):
    setup_case(tmp_path)
    result = evaluate_hunt_replay(tmp_path, "H-0001")
    assert result["passed_rules"] == 1
    assert result["sample_events_count"] == 2
    assert not result["live_validated"]
    assert result["holdout_rules_scored"] == 0


def test_a_real_miss_is_not_rescued_by_rule_derived_sanity(tmp_path):
    setup_case(tmp_path, positive=[{"QueryName": "different-campaign.invalid"}])
    result = evaluate_hunt_replay(tmp_path, "H-0001")
    assert result["failed_rules"] == result["sanity_passed_rules"] == 1
    assert result["passed_rules"] == 0
    assert result["rule_results"][0]["fn"] == 1


def test_benign_match_fails_the_independent_check(tmp_path):
    setup_case(tmp_path, benign=[{"QueryName": "campaign.invalid", "context": "authorized"}])
    result = evaluate_hunt_replay(tmp_path, "H-0001")
    assert result["failed_rules"] == 1
    assert result["rule_results"][0]["fp"] == 1


@pytest.mark.parametrize(
    "mutation",
    ["empty-positive", "empty-benign", "platform", "overlap", "schema", "reference", "malformed"],
)
def test_invalid_or_mislabeled_cases_fail_closed(tmp_path, mutation):
    _, path, data = setup_case(tmp_path)
    case = data["rules"]["dns.yml"]
    if mutation == "empty-positive":
        case["positive"] = []
    elif mutation == "empty-benign":
        case["benign"] = []
    elif mutation == "platform":
        case["positive"][0]["product"] = "windows"
    elif mutation == "overlap":
        case["benign"] = case["positive"]
    elif mutation == "schema":
        data["schema"] = 2
    elif mutation == "reference":
        case["source_reference"] = ""
    path.write_text("[]" if mutation == "malformed" else json.dumps(data))
    result = evaluate_hunt_replay(tmp_path, "H-0001")
    assert result["error_rules"] == 1
    assert result["passed_rules"] == 0


def test_changed_rule_requires_case_review(tmp_path):
    query, _, _ = setup_case(tmp_path)
    query.write_text(RULE.replace("campaign.invalid", "other.invalid"))
    result = evaluate_hunt_replay(tmp_path, "H-0001")
    assert result["not_assessed_rules"] == 1
    assert result["failed_rules"] == 0


def test_rule_symlink_is_never_followed(tmp_path):
    query, _, _ = setup_case(tmp_path)
    query.unlink()
    query.symlink_to(tmp_path / "private.yml")
    result = evaluate_hunt_replay(tmp_path, "H-0001")
    assert result["error_rules"] == 1


def test_sweep_reports_full_counts_once_and_never_tunes(tmp_path):
    setup_case(tmp_path, positive=[{"QueryName": "different-campaign.invalid"}])
    settings = Settings(
        _env_file=None, hecate_workspace=tmp_path, slack_channel_purple_team="C-LAB"
    )
    with (
        patch("hecate_runner.notifications.notify_purple_team") as notify,
        patch.object(RuleTuner, "auto_tune_from_miss") as tune,
    ):
        first = run_sweep(settings)[0]
        second = run_sweep(settings)[0]
    tune.assert_not_called()
    notify.assert_called_once()
    assert notify.call_args.kwargs["telemetry_count"] == 2
    assert notify.call_args.kwargs["replay_status"] == "Independent Replay Failures"
    assert first == second
    assert first["tuning_suggestion"] is None
    assert "1 failed" in notify.call_args.kwargs["summary"]


@pytest.mark.parametrize(
    "event",
    [
        {"QueryName": "example.com"},
        {"QueryName": "sub.example.net"},
        {"QueryName": "campaign.invalid", "_hecate_synthetic": True},
        {"QueryName": "campaign.invalid", "synthetic": "true"},
    ],
)
def test_automatic_tuning_rejects_placeholder_and_synthetic_evidence(tmp_path, event):
    query, _, _ = setup_case(tmp_path)
    result = RuleTuner(tmp_path).auto_tune_from_miss("H-0001", [event], apply=True, rule_file=query)
    assert not result.ok
    assert query.read_text() == RULE


def test_tuning_evaluator_errors_never_return_a_valid_candidate(tmp_path):
    query, _, _ = setup_case(tmp_path)
    with patch(
        "hecate_agent.core.sigma_evaluator.SigmaEvaluator.evaluate_rule",
        side_effect=RuntimeError("evaluation failed"),
    ):
        result = RuleTuner(tmp_path).auto_tune_from_miss(
            "H-0001", [{"QueryName": "actual-domain.org"}], rule_file=query
        )
    assert not result.ok
    assert "evaluation failed" in result.error


def test_replay_cli_signals_missing_cases_instead_of_succeeding(tmp_path):
    from typer.testing import CliRunner

    from hecate_runner.cli import app

    _, path, _ = setup_case(tmp_path)
    path.unlink()
    result = CliRunner().invoke(app, ["replay-check", "H-0001", "--workspace", str(tmp_path)])
    assert result.exit_code == 2
    assert "not_assessed_rules" in result.output


def test_tuning_cannot_redirect_to_another_hunt(tmp_path):
    query, _, _ = setup_case(tmp_path)
    other = tmp_path / "queries/H-0002/other.yml"
    other.parent.mkdir()
    other.write_text(RULE)
    with pytest.raises(ValueError, match="selected hunt"):
        RuleTuner(tmp_path).auto_tune_from_miss(
            "H-0001", [{"QueryName": "actual-domain.org"}], rule_file=other
        )
    assert query.read_text() == other.read_text() == RULE


def test_safe_expansion_updates_only_the_explicit_rule(tmp_path):
    query, _, _ = setup_case(tmp_path)
    other = query.parent / "aaa.yml"
    other.write_text(RULE)
    result = RuleTuner(tmp_path).auto_tune_from_miss(
        "H-0001", [{"QueryName": "actual-campaign.org"}], apply=True, rule_file=query
    )
    assert result.ok
    assert "actual-campaign.org" in query.read_text()
    assert other.read_text() == RULE
    assert query.with_suffix(".spl").exists()


def test_candidate_must_cover_every_miss(tmp_path):
    query, _, _ = setup_case(tmp_path)
    result = RuleTuner(tmp_path).auto_tune_from_miss(
        "H-0001",
        [{"QueryName": "campaign-one.org"}, {"QueryName": "campaign-two.org"}],
        rule_file=query,
    )
    assert not result.ok
    assert "all misses" in result.error
    assert query.read_text() == RULE
