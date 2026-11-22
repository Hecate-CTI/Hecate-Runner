"""Authoritative Splunk fired-alert evidence, correlated to one BAS run."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote


@dataclass(frozen=True)
class AlertProof:
    name: str
    sid: str
    triggered_at: str
    latency_sec: float
    event: dict[str, Any]


def _search_text(query: str) -> str:
    query = query.strip()
    return query[7:].strip() if query.startswith("search ") else query


def find_fired_alert(
    client: Any,
    *,
    name: str,
    query: str,
    owner: str,
    app: str,
    run_id: str,
    hunt_id: str,
    started: datetime,
    ended: datetime,
    excluded_sid: str,
) -> AlertProof | None:
    """Require a server alert record and matching evidence in its own job.

    Search results, index names and client-provided alert-like event fields are
    never alert evidence. Failures propagate so callers can report unavailable
    verification rather than an alert miss.
    """
    namespace = f"/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
    escaped = quote(name, safe="")
    definition = client._request(
        "GET", f"{namespace}/saved/searches/{escaped}", params={"output_mode": "json"}
    )
    definitions = definition.get("entry", [])
    if len(definitions) != 1 or definitions[0].get("name") != name:
        return None
    remote_query = definitions[0].get("content", {}).get("search", "")
    if not isinstance(remote_query, str) or _search_text(remote_query) != _search_text(query):
        return None
    response = client._request(
        "GET", f"{namespace}/alerts/fired_alerts/{escaped}", params={"output_mode": "json"}
    )
    now = datetime.now(UTC).timestamp()
    for entry in response.get("entry", []):
        content = entry.get("content", {})
        sid = content.get("sid")
        if (
            content.get("savedsearch_name") != name
            or not isinstance(sid, str)
            or not sid
            or sid == excluded_sid
        ):
            continue
        try:
            triggered = float(content["trigger_time"])
        except (KeyError, TypeError, ValueError):
            continue
        if not math.isfinite(triggered) or not started.timestamp() - 10 <= triggered <= now + 30:
            continue
        # Bounded evidence read. Aggregations which drop the correlation marker
        # cannot establish that this firing belongs to this execution.
        for event in client.get_search_results(sid, count=100):
            row = dict(event)
            if isinstance(row.get("_raw"), str):
                try:
                    raw = json.loads(row["_raw"])
                    if isinstance(raw, dict):
                        row = {**raw, **row}
                except (TypeError, ValueError):
                    pass
            if row.get("hecate_bas_run_id") != run_id or row.get("hecate_hunt_id") != hunt_id:
                continue
            observed = None
            for candidate in ("timestamp_utc", "UtcTime", "_time", "event_time"):
                val = row.get(candidate)
                if val is None or val == "":
                    continue
                try:
                    if isinstance(val, (int, float)):
                        t_val = float(val)
                    else:
                        try:
                            t_val = float(val)
                        except (TypeError, ValueError):
                            t_val = datetime.fromisoformat(
                                str(val).replace("Z", "+00:00")
                            ).timestamp()
                    if math.isfinite(t_val):
                        observed = t_val
                        break
                except (TypeError, ValueError, OverflowError):
                    continue
            if observed is None:
                continue
            if (
                not math.isfinite(observed)
                or not started.timestamp() - 10 <= observed <= ended.timestamp() + 30
            ):
                continue
            return AlertProof(
                name=name,
                sid=sid,
                triggered_at=datetime.fromtimestamp(triggered, UTC).isoformat(),
                latency_sec=max(0.0, triggered - started.timestamp()),
                event=row,
            )
    return None
