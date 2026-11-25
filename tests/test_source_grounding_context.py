"""Held advisory drafts must not gain techniques or scope from website context."""

from unittest.mock import MagicMock

import pytest
from hecate_agent.core.source_evidence import SourceEvidence
from hecate_agent.core.technique_evidence import map_behaviours

from hecate_runner.config import Settings
from hecate_runner.cti import CTIItem
from hecate_runner.hecate_client import TechniqueMetadata
from hecate_runner.orchestrator import Orchestrator


@pytest.mark.parametrize(
    ("text", "technique", "name"),
    [
        (
            "* [Create account](https://portal.aws.amazon.com/billing/signup)\n"
            "OpenJDK Base64 decoder has an out-of-bounds write.",
            "T1136",
            "Create Account",
        ),
        (
            "Please note that customers may download only software that was procured from Cisco directly "
            "or through a Cisco authorized reseller or partner and for which the license is still valid.",
            "T1105",
            "Ingress Tool Transfer",
        ),
        (
            "BTM is a legitimate Apple subsystem that is used to track anything that installs itself to run "
            "automatically in the background (like launch agents, login items, or cron jobs).",
            "T1053.003",
            "Cron",
        ),
    ],
)
def test_site_context_cannot_survive_as_a_wording_or_model_pick(
    settings: Settings,
    mock_hecate: MagicMock,
    text: str,
    technique: str,
    name: str,
) -> None:
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=MagicMock())
    orch._source_evidence = SourceEvidence(url="https://example.com/report", text=text)
    item = CTIItem(content="Primary advisory", source="file")
    mock_hecate.lookup_technique.return_value = TechniqueMetadata(
        technique_id=technique,
        name=name,
        found=True,
    )
    texts = orch._evidence_texts(item, None)
    assert (
        orch._gate_on_observed_use([technique], [], map_behaviours(texts), texts, item=item) == []
    )
    assert technique not in {
        e["technique_id"] for e in orch._technique_evidence if e["status"] == "observed"
    }


def test_website_navigation_cannot_scope_an_endpoint_advisory_to_cloud(
    settings: Settings,
    mock_hecate: MagicMock,
) -> None:
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=MagicMock())
    orch._source_evidence = SourceEvidence(
        url="https://example.com/report",
        text="* Discover AWS\n* Products\nOpenJDK decoder vulnerability.",
    )
    item = CTIItem(content="OpenJDK decoder vulnerability", source="file")
    assert orch._specimen_platforms(item) == []


def test_narrow_attack_applicability_is_still_not_target_evidence(
    settings: Settings,
    mock_hecate: MagicMock,
) -> None:
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=MagicMock())
    mock_hecate.lookup_technique.return_value = TechniqueMetadata(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactics=["initial-access"],
        platforms=["Containers", "ESXi", "IaaS", "Linux", "macOS", "Network Devices", "Windows"],
        found=True,
    )
    facts = {}
    tactics, platforms = orch._resolve_ttps(
        ["T1190"],
        intel_text="Apache HTTP Server mod_http2 race condition.",
        facts=facts,
    )
    assert tactics == ["initial-access"]
    assert platforms == []
    assert "Linux" in facts["T1190"].platforms  # Reference applicability is retained separately.
