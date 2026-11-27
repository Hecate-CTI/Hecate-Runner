"""Keep rejected rule artifacts out of replay, SIEM deployment and query probes."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import yaml
from hecate_agent.core.sigma_review_policy import review_block_reason

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.workspace_paths import read_artifact, workspace_path

_NATIVE_SUFFIXES = (".spl", ".kql", ".eql", ".cql", ".s1ql", ".leql")


def discard_rejected_rules(
    rules: list[dict[str, Any]], *, workspace: Path, out_dir: Path, hunt_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Archive rejected proposals privately and remove their executable siblings.

    Inspect both returned metadata and files: older Core versions may already
    have written rejected YAML and native queries. Keep accepted proposals that
    share an artifact path, and never follow paths outside this query directory.
    """
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    discarded_paths: set[Path] = set()
    snapshots: list[dict[str, Any]] = []

    def parse(raw: str) -> dict[str, Any]:
        doc = yaml.safe_load(raw)
        return doc if isinstance(doc, dict) else {}

    def local(path: Any) -> Path | None:
        if not path:
            return None
        value = Path(str(path))
        if value.parent.resolve() != out_dir.resolve() or value.is_symlink():
            raise ValueError("Generated Sigma artifact is outside its query directory")
        return value

    for rule in rules:
        path = local(rule.get("path"))
        doc = parse(str(rule.get("rule_yaml") or ""))
        reason = review_block_reason(doc, filename=str(path.name if path else rule.get("title") or ""))
        if reason:
            title = str(rule.get("title") or doc.get("title") or "Untitled rule")
            rejected.append({"title": title, "reason": reason})
            snapshots.append(
                {"title": title, "reason": reason, "rule_yaml": rule.get("rule_yaml", "")}
            )
            if path:
                discarded_paths.add(path)
        else:
            accepted.append(rule)

    kept_paths = {path for rule in accepted if (path := local(rule.get("path"))) is not None}
    for path in sorted([*out_dir.glob("*.yml"), *out_dir.glob("*.yaml")]):
        if path in kept_paths:
            continue
        doc = parse(read_artifact(path, workspace))
        reason = review_block_reason(doc, filename=path.name)
        if reason:
            discarded_paths.add(path)
            title = str(doc.get("title") or path.stem)
            entry = {"title": title, "reason": reason}
            if entry not in rejected:
                rejected.append(entry)
                snapshots.append({**entry, "rule_yaml": yaml.safe_dump(doc, sort_keys=False)})

    if snapshots:
        archive = workspace_path(
            workspace, ".hecate", "rejected-rules", hunt_id, uuid.uuid4().hex + ".json"
        )
        # Persist diagnostic evidence before removing any generated artifacts.
        atomic_write_text(archive, json.dumps(snapshots, indent=2), mode=0o600)
    for path in discarded_paths - kept_paths:
        for artifact in (path, *(path.with_suffix(suffix) for suffix in _NATIVE_SUFFIXES)):
            if artifact.is_symlink():
                raise ValueError("Refusing symlinked rejected Sigma artifact")
            artifact.unlink(missing_ok=True)
    return accepted, rejected
