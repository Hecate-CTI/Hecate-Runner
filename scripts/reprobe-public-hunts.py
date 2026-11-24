#!/usr/bin/env python3
"""Re-probe Public hunts against live Splunk; strip mock BAS credit.

Updates lab_probe frontmatter + CHECK Events Analyzed when a real probe runs.
Does not invent KEEP findings. Run as a user that can write the workspace.

  cd Hecate-Runner
  sg hecate-data -c './.venv/bin/python scripts/reprobe-public-hunts.py'
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from hecate_runner.config import Settings
from hecate_runner.lab_hits import probe_lab_hits
from hecate_runner.lifecycle import parse_hunt_frontmatter
from hecate_runner.workspace_paths import write_artifact


def _upsert_fm(raw_yaml: str, updates: dict[str, object]) -> str:
    lines = raw_yaml.splitlines(keepends=True)
    keys = set(updates)
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        m = re.match(r"^([A-Za-z0-9_]+)\s*:", line)
        if m and m.group(1) in keys:
            key = m.group(1)
            val = updates[key]
            if isinstance(val, (dict, list)):
                rendered = json.dumps(val)
            elif isinstance(val, bool):
                rendered = "true" if val else "false"
            elif isinstance(val, (int, float)):
                rendered = str(val)
            else:
                rendered = json.dumps(str(val))
            out.append(f"{key}: {rendered}\n")
            seen.add(key)
        else:
            out.append(line)
    for key in keys - seen:
        val = updates[key]
        if isinstance(val, (dict, list)):
            rendered = json.dumps(val)
        elif isinstance(val, bool):
            rendered = "true" if val else "false"
        elif isinstance(val, (int, float)):
            rendered = str(val)
        else:
            rendered = json.dumps(str(val))
        out.append(f"{key}: {rendered}\n")
    return "".join(out)


def _patch_check(body: str, provider: str, window: int, hits: int, status: str, detail: str) -> str:
    quality = f"Lab probe `{status}`"
    if detail:
        quality = f"{quality} — {detail}"
    block = (
        "### Data Source Information\n\n"
        f"- **Index/Data Source:** `{provider}` (lab probe)\n"
        f"- **Time Range:** Past {window} day(s) (lab probe)\n"
        f"- **Events Analyzed:** {hits} (lab probe: `{status}`)\n"
        f"- **Data Quality:** {quality}\n"
    )
    if re.search(r"### Data Source Information\n", body):
        return re.sub(
            r"### Data Source Information\n[\s\S]*?(?=\n### |\n## )",
            block + "\n",
            body,
            count=1,
        )
    return body


def main() -> int:
    settings = Settings()
    workspace = Path(settings.hecate_workspace)
    hunts = sorted((workspace / "hunts").glob("**/H-*.md"))
    if not hunts:
        print(f"no hunts under {workspace / 'hunts'}", file=sys.stderr)
        return 1

    print(f"workspace={workspace} hunts={len(hunts)} provider={settings.query_provider}")
    for path in hunts:
        hunt_id = path.stem
        text = path.read_text(encoding="utf-8")
        fm, raw_yaml, body = parse_hunt_frontmatter(text)
        updates: dict[str, object] = {}

        # Strip mock BAS credit
        provider = str(fm.get("bas_provider") or "").strip().lower()
        bas_status = str(fm.get("bas_status") or "").strip().lower()
        if provider == "mock" or bas_status.startswith("simulation") or (fm.get("bas_verified") is True and provider == "mock"):
            updates["bas_verified"] = False
            updates["bas_live"] = False
            updates["bas_type"] = "synthesized_probe"
            if provider == "mock" and bas_status in {"verified_true_positive", "verified_behavioral"}:
                updates["bas_status"] = "simulation_match"

        qdir = workspace / "queries" / hunt_id
        if qdir.is_dir() and any(qdir.glob("*.spl")):
            report = probe_lab_hits(
                hunt_id,
                qdir,
                provider_name=settings.query_provider,
                hecate_bin=settings.hecate_bin_resolved,
                workspace=workspace,
                max_time_range_days=settings.max_query_time_range_days,
                max_limit=settings.max_query_limit,
                env_overrides=settings.query_provider_env(),
                window_days=getattr(settings, "lab_hit_probe_window_days", 1),
                max_auto_fetch=getattr(settings, "auto_hunt_max_fetch", 200),
            )
            updates.update(
                {
                    "lab_probe": report.status,
                    "lab_probe_provider": report.provider,
                    "lab_probe_window_days": report.window_days,
                    "lab_probe_hits": report.total_hits,
                    "lab_probe_queries": report.queries_run,
                    "lab_probe_detail": report.detail,
                    "lab_probe_results": [r.to_dict() for r in report.results],
                }
            )
            if report.status in {"hit", "miss", "overmatch"}:
                body = _patch_check(
                    body,
                    report.provider,
                    report.window_days,
                    report.total_hits,
                    report.status,
                    report.detail,
                )
            print(f"{hunt_id}: lab={report.status} hits={report.total_hits} q={report.queries_run}")
        else:
            print(f"{hunt_id}: no .spl queries — skipped probe")

        if not updates and body == parse_hunt_frontmatter(text)[2]:
            continue
        new_yaml = _upsert_fm(raw_yaml, updates) if updates else raw_yaml
        new_text = f"---\n{new_yaml}---\n{body.lstrip()}"
        write_artifact(path, new_text, workspace)
        if updates and "lab_probe" not in updates:
            print(f"{hunt_id}: updated frontmatter {sorted(updates)}")

    print("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
