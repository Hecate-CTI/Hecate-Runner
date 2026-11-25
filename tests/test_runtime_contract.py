"""Release preflight must catch the regressions that escaped import checks."""

import pytest

from hecate_runner.runtime_contract import check_runtime_contract


def test_combined_runtime_contract_is_offline_and_leaves_no_env_override(monkeypatch):
    monkeypatch.setenv("HECATE_LLM_CAPABILITY_TIERS", '{"source_extraction":"simple"}')
    assert check_runtime_contract()["ok"] is True
    import os

    assert os.environ["HECATE_LLM_CAPABILITY_TIERS"] == '{"source_extraction":"simple"}'


def test_release_contract_detects_a_lost_core_review_gate(monkeypatch):
    monkeypatch.setattr(
        "hecate_agent.core.sigma_review_policy.review_block_reason", lambda doc: None
    )
    with pytest.raises(RuntimeError, match="does not block"):
        check_runtime_contract()


def test_release_contract_detects_wrong_platform_even_if_generation_succeeds(monkeypatch):
    from hecate_agent.agents.llm.sigma_generator import SigmaGeneratorAgent

    monkeypatch.setattr(
        SigmaGeneratorAgent,
        "_logsource_block",
        lambda *a, **k: {"category": "process_creation", "product": "linux"},
    )
    with pytest.raises(RuntimeError, match="relabels macOS"):
        check_runtime_contract()


def test_release_contract_detects_a_lost_runner_artifact_gate(monkeypatch):
    monkeypatch.setattr(
        "hecate_runner.sigma_review_gate.discard_rejected_rules",
        lambda rules, **kwargs: (rules, []),
    )
    with pytest.raises(RuntimeError, match="accepted blocked"):
        check_runtime_contract()


def test_release_contract_detects_patch_hash_regression(monkeypatch):
    monkeypatch.setattr(
        "hecate_agent.api.extract_indicators", lambda text: {"hashes": ["patch-id"]}
    )
    with pytest.raises(RuntimeError, match="patch revision"):
        check_runtime_contract()


def test_release_contract_detects_applicability_used_as_scope(monkeypatch):
    monkeypatch.setattr(
        "hecate_runner.orchestrator_ttp.resolve_ttps", lambda *args, **kwargs: ([], ["Linux"])
    )
    with pytest.raises(RuntimeError, match="applicability"):
        check_runtime_contract()
