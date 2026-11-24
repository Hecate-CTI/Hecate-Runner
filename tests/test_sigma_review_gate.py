"""Rejected rule files never reach replay, BAS, native deployment or lab queries."""

from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from hecate_runner.hecate_client import SigmaResult
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.sigma_review_gate import discard_rejected_rules


def rule(out_dir, title, verdict="reject"):
    doc = {
        "title": title,
        "logsource": {"product": "linux", "category": "network_connection"},
        "detection": {"selection": {"Image|endswith": r"\python.exe"}, "condition": "selection"},
        "hecate_review": {"verdict": verdict, "issues": ["Windows executable path on Linux"]},
    }
    path = out_dir / (title + ".yml")
    path.write_text(yaml.safe_dump(doc))
    path.with_suffix(".spl").write_text('search Image="*python.exe"')
    return {
        "title": title,
        "logsource_category": "network_connection",
        "rule_yaml": yaml.safe_dump(doc),
        "path": str(path),
    }


def test_returned_and_stale_rejected_files_are_archived_and_removed(tmp_path):
    out_dir = tmp_path / "queries" / "H-0040"
    out_dir.mkdir(parents=True)
    bad = rule(out_dir, "bad")
    rule(out_dir, "stale")
    good = rule(out_dir, "good", "keep")
    kept, rejected = discard_rejected_rules(
        [bad, good], workspace=tmp_path, out_dir=out_dir, hunt_id="H-0040"
    )
    assert kept == [good]
    assert {entry["title"] for entry in rejected} == {"bad", "stale"}
    assert {path.name for path in out_dir.iterdir()} == {"good.yml", "good.spl"}
    archives = list((tmp_path / ".hecate/rejected-rules/H-0040").glob("*.json"))
    assert len(archives) == 1
    assert archives[0].stat().st_mode & 0o777 == 0o600
    assert "Windows executable path on Linux" in archives[0].read_text()


@pytest.mark.parametrize("unsafe", ["outside", "symlink"])
def test_artifact_cleanup_cannot_escape_query_directory(tmp_path, unsafe):
    out_dir = tmp_path / "queries/H-0040"
    out_dir.mkdir(parents=True)
    bad = rule(out_dir, "bad")
    external = tmp_path / "external.yml"
    external.write_text("preserve")
    if unsafe == "outside":
        bad["path"] = str(external)
    else:
        Path(bad["path"]).unlink()
        Path(bad["path"]).symlink_to(external)
    with pytest.raises(ValueError):
        discard_rejected_rules([bad], workspace=tmp_path, out_dir=out_dir, hunt_id="H-0040")
    assert external.read_text() == "preserve"


@pytest.mark.parametrize("all_rejected", [False, True])
def test_rejected_proposals_are_excluded_from_all_pipeline_consumers(
    settings, workspace, mock_hecate, file_queue_with_cti, monkeypatch, all_rejected
):
    settings.purple_team_validation_enabled = True
    settings.bas_enabled = True
    settings.siem_deploy_enabled = True
    settings.lab_hit_probe_enabled = True
    generated = {}

    def generate(payload, out_dir, **kwargs):
        out_dir.mkdir(parents=True, exist_ok=True)
        candidates = [rule(out_dir, "bad")]
        if not all_rejected:
            candidates.append(rule(out_dir, "good", "keep"))
        generated["out_dir"] = out_dir
        return SigmaResult(success=True, rules=candidates)

    mock_hecate.sigma_generator.side_effect = generate
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)
    consumers = {
        name: Mock(return_value=[] if name == "_deploy_native_queries" else {})
        for name in (
            "_run_purple_team_validation",
            "_run_bas_validation",
            "_deploy_native_queries",
            "_probe_lab_hits",
        )
    }
    for name, consumer in consumers.items():
        monkeypatch.setattr(orch, name, consumer)
    result = orch.run_once()
    assert result.outcome == "draft_created"
    for name, consumer in consumers.items():
        if all_rejected:
            consumer.assert_not_called()
        else:
            consumer.assert_called_once()
            assert [entry["title"] for entry in consumer.call_args.args[0].sigma_rejections] == [
                "bad"
            ]
            if name != "_probe_lab_hits":
                rules_arg = consumer.call_args.args[1]
                assert [entry["title"] for entry in rules_arg] == ["good"]
    out_dir = generated["out_dir"]
    draft = result.draft_path.read_text()
    assert "Discarded Rule Proposals" in draft
    assert "Windows executable path on Linux" in draft
    assert not (out_dir / "bad.yml").exists()
    assert not (out_dir / "bad.spl").exists()


def test_routing_override_is_forwarded_to_isolated_workers(settings):
    import json

    settings.hecate_llm_capability_tiers = {"source_extraction": "complex"}
    assert json.loads(settings.env_for_hecate()["HECATE_LLM_CAPABILITY_TIERS"]) == {
        "source_extraction": "complex"
    }


def test_revision_required_proposal_is_held_back_with_its_native_query(tmp_path):
    out_dir = tmp_path / "queries/H-0040"
    out_dir.mkdir(parents=True)
    proposal = rule(out_dir, "unfinished", "revise")
    accepted, held = discard_rejected_rules(
        [proposal], workspace=tmp_path, out_dir=out_dir, hunt_id="H-0040"
    )
    assert not accepted
    assert held[0]["reason"].startswith("Revision required:")
    assert not list(out_dir.iterdir())
