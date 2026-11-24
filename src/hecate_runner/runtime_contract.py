"""Offline behavioral checks for the Core/Runner packages being released."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import yaml


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def check_runtime_contract() -> dict[str, object]:
    # Imports deliberately come from the installed candidate, including Core.
    # An older or mismatched package must fail before deployment stops services.
    from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent
    from hecate_agent.core.sigma_evaluator import SigmaEvaluator
    from hecate_agent.core.sigma_review_policy import review_block_reason

    from hecate_runner.config import Settings
    from hecate_runner.sigma_review_gate import discard_rejected_rules

    with tempfile.TemporaryDirectory(prefix="hecate-runtime-check-") as name:
        workspace = Path(name)
        out = workspace / "queries" / "release-check"
        out.mkdir(parents=True)
        proposals = []
        for verdict in ("reject", "revise", "keep"):
            doc = {
                "title": verdict,
                "hecate_review": {"verdict": verdict, "issues": ["release fixture"]},
            }
            if verdict != "keep":
                require(bool(review_block_reason(doc)), f"Core does not block {verdict} proposals")
            path = out / (verdict + ".yml")
            path.write_text(yaml.safe_dump(doc))
            path.with_suffix(".spl").write_text("release fixture")
            proposals.append(
                {"title": verdict, "rule_yaml": yaml.safe_dump(doc), "path": str(path)}
            )
        kept, rejected = discard_rejected_rules(
            proposals, workspace=workspace, out_dir=out, hunt_id="release-check"
        )
        require(
            [r["title"] for r in kept] == ["keep"] and len(rejected) == 2,
            "Runner accepted blocked proposals",
        )
        require(
            {p.name for p in out.iterdir()} == {"keep.yml", "keep.spl"},
            "Blocked executable artifacts survived",
        )

        command = "launchctl bootstrap gui/501 /Users/test/Library/LaunchAgents/com.apple.softwareupdated.plist"
        raw = {
            "title": "Release platform fixture",
            "logsource_category": "process_creation",
            "logsource_product": "linux",
            "detection": {
                "selection": {
                    "Image|endswith": "/launchctl",
                    "CommandLine|contains": "com.apple.softwareupdated.plist",
                },
                "condition": "selection",
            },
        }
        agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
        rule, error = agent._build_rule(
            raw,
            SigmaGenerationInput(
                hypothesis="Source-named macOS LaunchAgent",
                platforms=["macOS"],
                threat_intel=command,
            ),
        )
        require(rule is not None and error is None, "Platform fixture could not be rendered")
        if rule is None:
            raise RuntimeError("Platform fixture missing")
        document = yaml.safe_load(rule.rule_yaml)
        require(
            document["logsource"].get("product") == "macos",
            "Candidate relabels macOS as another OS",
        )
        evaluator = SigmaEvaluator(document, strict_logsource=True)
        event = {
            "category": "process_creation",
            "product": "macos",
            "Image": "/bin/launchctl",
            "CommandLine": command,
        }
        require(evaluator.matches(event), "Correctly scoped event does not match")
        require(
            not evaluator.matches({**event, "CommandLine": "launchctl list"}),
            "Benign platform control matched",
        )

        settings = Settings(
            _env_file=None,
            hecate_workspace=workspace,
            query_provider="splunk",
            bas_mode="caldera",
            bas_fallback_to_mock=False,
            allow_mock_backends=False,
            hecate_llm_capability_tiers={"source_extraction": "complex"},
        )
        routing = settings.env_for_hecate()["HECATE_LLM_CAPABILITY_TIERS"]
        require(
            json.loads(routing) == {"source_extraction": "complex"},
            "Worker capability routing was lost",
        )
        from hecate_agent.core.llm_router import resolve_capability_tiers

        previous = os.environ.get("HECATE_LLM_CAPABILITY_TIERS")
        try:
            os.environ["HECATE_LLM_CAPABILITY_TIERS"] = routing
            require(
                resolve_capability_tiers()["source_extraction"] == "complex",
                "Core ignores capability routing",
            )
        finally:
            if previous is None:
                os.environ.pop("HECATE_LLM_CAPABILITY_TIERS", None)
            else:
                os.environ["HECATE_LLM_CAPABILITY_TIERS"] = previous
    return {
        "ok": True,
        "review_gate": True,
        "artifact_gate": True,
        "platform_scope": True,
        "routing": True,
        "model_calls": 0,
    }


if __name__ == "__main__":
    print(json.dumps(check_runtime_contract(), sort_keys=True))
