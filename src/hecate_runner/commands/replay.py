"""Read-only independent synthetic case evaluation."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from hecate_runner.continuous_replay import evaluate_hunt_replay


def replay_check(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID to evaluate")],
    workspace: Annotated[Path, typer.Option(help="Selected private workspace")] = Path("."),
) -> None:
    """Evaluate reviewed synthetic cases offline; never tune, notify or execute."""
    try:
        report = evaluate_hunt_replay(workspace, hunt_id)
    except (ValueError, OSError) as exc:
        Console().print_json(data={"ok": False, "error": str(exc)})
        raise typer.Exit(1) from None
    Console().print_json(data=report)
    if not report.get("ok") or report.get("failed_rules") or report.get("error_rules"):
        raise typer.Exit(1)
    if report.get("not_assessed_rules"):
        raise typer.Exit(2)
