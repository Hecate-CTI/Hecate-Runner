"""Independent synthetic cases for continuous replay; no automatic rule widening.

Case files are private workspace artifacts at .hecate/replay_cases/H-XXXX.json.
They bind source-reviewed positive and benign examples to exact rule bytes.
Predicate-derived samples are reported only as self-consistency sanity checks.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import yaml
from hecate_agent.core.sigma_evaluator import SigmaEvaluator

from hecate_runner.workspace_paths import (
    list_query_hunt_ids,
    normalize_hunt_id,
    query_directory,
    read_artifact,
    workspace_path,
    write_artifact,
)

log = logging.getLogger(__name__)


def _events(value: Any, product: str, category: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 1000:
        raise ValueError("Cases require 1-1000 positive and benign events each")
    if not all(isinstance(event, dict) and event for event in value):
        raise ValueError("Each case event must be a nonempty object")
    for event in value:
        if event.get("product", product) != product or event.get("category", category) != category:
            raise ValueError("Case event platform/category differs from its rule")
    return value


def evaluate_hunt_replay(workspace: Path, hunt_id: str) -> dict[str, Any]:
    """Read-only evaluation. Missing/stale cases are not assessed, never misses."""
    hunt_id = normalize_hunt_id(hunt_id)
    directory = query_directory(workspace, hunt_id)
    files = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    if not files:
        return {"ok": False, "hunt_id": hunt_id, "error": "No Sigma rules found"}
    case_path = workspace_path(workspace, ".hecate", "replay_cases", f"{hunt_id}.json")
    cases: dict[str, Any] = {}
    case_error = ""
    if case_path.exists():
        try:
            document = json.loads(read_artifact(case_path, workspace))
            if document.get("schema") != 1 or document.get("hunt_id") != hunt_id:
                raise ValueError("Unsupported replay case schema or hunt identity")
            cases = document["rules"]
            if not isinstance(cases, dict):
                raise ValueError("Replay rules must be an object keyed by filename")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            case_error = str(exc)
            cases = {}
    results: list[dict[str, Any]] = []
    for file in files:
        row: dict[str, Any] = {"rule_file": file.name, "status": "not_assessed", "sample_count": 0}
        try:
            raw = read_artifact(file, workspace)
            row["rule_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
            parsed = yaml.safe_load(raw)
            if not isinstance(parsed, dict):
                raise ValueError("Rule must be a YAML object")
            source = parsed.get("logsource") or {}
            product, category = str(source.get("product", "")), str(source.get("category", ""))
            row.update(product=product, category=category)
            # Rule-derived cases can catch a malformed predicate but cannot
            # establish independent recall or rescue an independent failure.
            from hecate_runner.bas.synthesizer import synthesize_events_from_rule

            try:
                sanity_positive, sanity_benign = synthesize_events_from_rule(raw)
                sanity = SigmaEvaluator.evaluate_rule(raw, [sanity_positive], sanity_benign)
                row["sanity_status"] = (
                    "passed" if sanity.is_perfect and not sanity.errors else "failed"
                )
            except Exception:
                row["sanity_status"] = "error"
            case = cases.get(file.name)
            if case_error:
                raise ValueError(case_error)
            if case is None:
                row["reason"] = "No independent source-reviewed cases for this rule"
            elif not isinstance(case, dict):
                raise ValueError("Rule case must be an object")
            elif case.get("rule_sha256") != row["rule_sha256"]:
                row["reason"] = "Rule changed since case review; refresh independent cases"
            else:
                reference = case.get("source_reference")
                if not isinstance(reference, str) or not reference.strip():
                    raise ValueError("Independent cases require a source reference")
                positive = _events(case.get("positive"), product, category)
                benign = _events(case.get("benign"), product, category)
                if any(event in benign for event in positive):
                    raise ValueError("Positive and benign cases overlap")
                score = SigmaEvaluator.evaluate_rule(raw, positive, benign)
                row.update(
                    sample_count=len(positive) + len(benign),
                    positive_count=len(positive),
                    benign_count=len(benign),
                    source_reference=reference,
                    tp=score.true_positives,
                    fp=score.false_positives,
                    fn=score.false_negatives,
                    tn=score.true_negatives,
                    errors=list(score.errors),
                    status="error" if score.errors else "passed" if score.is_perfect else "failed",
                )
        except Exception as exc:
            row.update(status="error", reason=str(exc))
        results.append(row)
    counts = {
        status: sum(r["status"] == status for r in results)
        for status in ("passed", "failed", "not_assessed", "error")
    }
    assessed = counts["passed"] + counts["failed"]
    return {
        "ok": True,
        "hunt_id": hunt_id,
        "total_rules": len(results),
        "passed_rules": counts["passed"],
        "failed_rules": counts["failed"],
        "not_assessed_rules": counts["not_assessed"],
        "error_rules": counts["error"],
        "assessed_rules": assessed,
        "fidelity": f"{100 * counts['passed'] / assessed:.0f}%" if assessed else "unavailable",
        "sample_events_count": sum(row["sample_count"] for row in results),
        "sample_count_scope": "positive and benign rule-event evaluations",
        "sanity_passed_rules": sum(r.get("sanity_status") == "passed" for r in results),
        "evaluation_scope": "source_reviewed_synthetic_cases",
        "live_validated": False,
        "holdout_rules_scored": 0,
        "holdout_rules_passed": 0,
        "holdout_rules_failed": 0,
        "holdout_rules_unavailable": len(results),
        "rule_results": results,
    }


def run_sweep(settings: Any) -> list[dict[str, Any]]:
    """Persist diagnostics and notify only on changed failures/errors. Never tune."""
    workspace = Path(settings.hecate_workspace)
    queries = workspace_path(workspace, "queries")
    # Retain safety checks on legacy suggestion paths; do not revive stale previews.
    workspace_path(workspace, ".hecate", "tuning_suggestions")
    outcomes: list[dict[str, Any]] = []
    for hunt_id in list_query_hunt_ids(queries):
        try:
            result = evaluate_hunt_replay(workspace, hunt_id)
            if not result.get("ok"):
                continue
            result["tuning_suggestion"] = None
            report_path = workspace_path(workspace, ".hecate", "replay_results", f"{hunt_id}.json")
            report_path.parent.mkdir(parents=True, exist_ok=True)
            serialized = json.dumps(result, indent=2, sort_keys=True)
            previous = read_artifact(report_path, workspace) if report_path.exists() else ""
            write_artifact(report_path, serialized, workspace)
            if (
                previous != serialized
                and (result["failed_rules"] or result["error_rules"])
                and getattr(settings, "slack_channel_purple_team", None)
            ):
                from hecate_runner.notifications import notify_purple_team

                notify_purple_team(
                    settings,
                    hunt_id=hunt_id,
                    technique="Continuous independent replay",
                    success=False,
                    telemetry_count=result["sample_events_count"],
                    replay_status="Independent Replay Failures"
                    if result["failed_rules"]
                    else "Replay Test Errors",
                    summary=(
                        f"{result['passed_rules']} passed, {result['failed_rules']} failed, "
                        f"{result['not_assessed_rules']} not assessed, {result['error_rules']} errors "
                        f"across {result['total_rules']} rules. "
                        "Samples count positive and benign rule-event evaluations. "
                        "Rules were retained; review the per-rule replay report. No automatic tuning."
                    ),
                )
            outcomes.append(result)
        except Exception as exc:
            log.warning("Continuous replay error for %s: %s", hunt_id, exc)
    return outcomes
