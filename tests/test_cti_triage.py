"""Triage rules: park commentary, never park intelligence.

The must-keep cases are the point. A model gate was measured on this task
first and parked "Cat's Got Your Files: Lynx Ransomware", "From Bing Search to
Ransomware: Bumblebee and AdaptixC2 Delivery" and the BengalSEO writeup that
became H-0616 -- so those titles are pinned here as regressions.
"""

from __future__ import annotations

import pytest

from hecate_runner.cti import CTIItem
from hecate_runner.cti_triage import source_quality_verdict, triage


def _item(title: str = "", tags: list[str] | None = None) -> CTIItem:
    return CTIItem(content="x", source="rss", title=title, metadata={"entry_tags": tags or []})


# --- Parked: publisher said so ---------------------------------------------


@pytest.mark.parametrize(
    "category",
    [
        "The Good, the Bad and the Ugly",
        "Threat Source newsletter",
        "Company",
        "Product Updates",
        "Tool Talk",
    ],
)
def test_a_commentary_category_is_parked(category: str) -> None:
    verdict = triage(_item("Some post", [category]))
    assert verdict.park is True
    assert category.lower() in verdict.reason


def test_categories_are_matched_case_insensitively() -> None:
    assert triage(_item("x", ["COMPANY"])).park is True


@pytest.mark.parametrize(
    "category", ["Malware", "Threat Research", "ransomware", "Insights", "Security Operations"]
)
def test_a_research_category_is_not_parked(category: str) -> None:
    """ "Insights" covers Red Canary's monthly intelligence summaries and
    "Security Operations" covers real research, so neither is denied."""
    assert triage(_item("Some post", [category])).park is False


# --- Parked: title shape, for feeds that publish no categories -------------


@pytest.mark.parametrize(
    "title",
    [
        "The Good, the Bad and the Ugly in Cybersecurity - Week 33 (2026)",
        "10 Hacker Summer Camp Standouts at Black Hat and DEF CON",
        "Black Hat 2026 recap: what we saw",
        "What is Managed EDR?",
        "How to choose a managed detection provider",
    ],
)
def test_a_commentary_title_is_parked_without_categories(title: str) -> None:
    assert triage(_item(title)).park is True


# --- Never parked -----------------------------------------------------------


@pytest.mark.parametrize(
    "title",
    [
        "Cat's Got Your Files: Lynx Ransomware",
        "From Bing Search to Ransomware: Bumblebee and AdaptixC2 Delivery",
        "BengalSEO Part 1: Anatomy of the Operation",
        "Apache ActiveMQ Exploit Leads to LockBit Ransomware",
        "Critical N-able N-central Vulnerability and Active Exploitation",
        "ClearFake WebDAV infection chain delivers Amatera stealer",
    ],
)
def test_real_intelligence_is_never_parked(title: str) -> None:
    assert triage(_item(title)).park is False


def test_a_conference_word_alone_does_not_park() -> None:
    """The pattern needs a recurring-recap shape, not just a topic word --
    otherwise a genuine advisory mentioning a conference would be held back."""
    assert triage(_item("What We Learned Hunting APT29 in Azure")).park is False
    assert triage(_item("Threat actors exploit a flaw disclosed at Black Hat")).park is False


def test_an_item_with_no_title_and_no_tags_is_not_parked() -> None:
    """Absence of signal is never a reason to hold something back."""
    assert triage(_item()).park is False


def test_non_rss_items_pass_through() -> None:
    """MISP and OTX carry no publisher categories; they must not be gated by
    the absence of them."""
    item = CTIItem(content="MISP Event: X\nSummary: prose", source="misp", title="", metadata={})
    assert triage(item).park is False


def test_sample_metadata_with_hash_is_routed_to_indicator_sweep() -> None:
    item = CTIItem(
        content="sample catalog record",
        source="malwarebazaar",
        metadata={
            "evidence_profile": "sample_metadata",
            "indicators": {"sha256": ["a" * 64]},
        },
    )

    verdict = source_quality_verdict(item)

    assert verdict is not None
    assert verdict.park is False


def test_sample_metadata_without_indicators_is_parked() -> None:
    item = CTIItem(
        content="sample catalog record",
        source="malwarebazaar",
        metadata={"evidence_profile": "sample_metadata", "indicators": {}},
    )

    verdict = source_quality_verdict(item)

    assert verdict is not None
    assert verdict.park is True
    assert "no routable indicators" in verdict.reason


def test_repository_archive_metadata_is_parked() -> None:
    item = CTIItem(
        content="repository archive record",
        source="vxunderground",
        metadata={"evidence_profile": "archive_metadata", "files": ["Windows/sample.7z"]},
    )

    verdict = source_quality_verdict(item)

    assert verdict is not None
    assert verdict.park is True
    assert "no extracted behavior" in verdict.reason


def test_anti_noise_parks_riot_benign_service(monkeypatch):
    from unittest.mock import patch

    from hecate_runner.cti_triage import anti_noise_verdict

    item = CTIItem(
        content="Suspicious traffic detected from 13.107.21.200",
        source="rss",
        metadata={"indicators": {"ipv4": ["13.107.21.200"]}},
    )

    with patch("hecate_agent.api.extract_greynoise_context") as mock_gn:
        mock_gn.return_value = {
            "noise": False,
            "riot": True,
            "classification": "benign",
            "actor": "Microsoft 365",
            "tags": [],
            "raw_status": 200,
        }
        verdict = anti_noise_verdict(item)
        assert verdict is not None
        assert verdict.park is True
        assert "verified benign enterprise infrastructure" in verdict.reason
        assert "Microsoft 365" in verdict.reason


def test_anti_noise_parks_benign_scanner(monkeypatch):
    from unittest.mock import patch

    from hecate_runner.cti_triage import anti_noise_verdict

    item = CTIItem(
        content="Probe from 65.49.20.70",
        source="misp",
        metadata={"ip": "65.49.20.70"},
    )

    with patch("hecate_agent.api.extract_greynoise_context") as mock_gn:
        mock_gn.return_value = {
            "noise": True,
            "riot": False,
            "classification": "benign",
            "actor": "ShadowServer.org",
            "tags": ["Ping Scanner"],
            "raw_status": 200,
        }
        verdict = anti_noise_verdict(item)
        assert verdict is not None
        assert verdict.park is True
        assert "known benign scanner" in verdict.reason
        assert "ShadowServer.org" in verdict.reason


def test_anti_noise_tags_mass_scanner_and_lets_through(monkeypatch):
    from unittest.mock import patch

    from hecate_runner.cti_triage import anti_noise_verdict

    item = CTIItem(
        content="Adversary listener at 198.51.100.5",
        source="abuse_ch",
        metadata={"indicators": {"ipv4": ["198.51.100.5"]}},
    )

    with patch("hecate_agent.api.extract_greynoise_context") as mock_gn:
        mock_gn.return_value = {
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "actor": "Mirai",
            "tags": ["Mirai", "Telnet Bruteforce"],
            "raw_status": 200,
        }
        verdict = anti_noise_verdict(item)
        assert verdict is None
        assert item.metadata["noise_classification"] == "mass_scanner"
        assert item.metadata["scanner_actor"] == "Mirai"
        assert "Telnet Bruteforce" in item.metadata["scanner_tags"]


def test_anti_noise_tags_targeted_infrastructure(monkeypatch):
    from unittest.mock import patch

    from hecate_runner.cti_triage import anti_noise_verdict

    item = CTIItem(
        content="Targeted C2 at 203.0.113.88",
        source="otx",
        metadata={"indicators": {"ipv4": ["203.0.113.88"]}},
    )

    with patch("hecate_agent.api.extract_greynoise_context") as mock_gn:
        mock_gn.return_value = {
            "noise": False,
            "riot": False,
            "classification": "unseen",
            "actor": "",
            "tags": [],
            "raw_status": 404,
        }
        verdict = anti_noise_verdict(item)
        assert verdict is None
        assert item.metadata["noise_classification"] == "targeted"


@pytest.mark.parametrize(
    "title",
    [
        "Wiz ASPM in the AI Era",
        "Whitepaper: Cloud Security Posture Management",
        "Top 10 Security Strategies for 2026",
        "Announcing our New Container Security Suite",
        "Buyer's Guide to Managed Detection and Response",
    ],
)
def test_marketing_and_whitepaper_without_observables_is_parked(title: str) -> None:
    item = CTIItem(
        content=f"Download our latest e-book and whitepaper on {title}. Schedule a demo today.",
        source="rss",
        title=title,
        metadata={"indicators": {}},
    )
    verdict = triage(item)
    assert verdict.park is True
    assert "commentary" in verdict.reason or "marketing" in verdict.reason


def test_technical_report_with_whitepaper_keyword_but_real_indicators_passes() -> None:
    item = CTIItem(
        content="Adversaries deployed a custom backdoor hash 0123456789abcdef0123456789abcdef",
        source="rss",
        title="Technical Analysis of APT41 Malware",
        metadata={"indicators": {"hash": ["0123456789abcdef0123456789abcdef"]}},
    )
    verdict = triage(item)
    assert verdict.park is False


_TOPIC_ESSAY = " ".join(
    ["Organizations should rethink how they staff a modern detection program"] * 8
)


def test_a_long_topic_essay_is_parked_before_research() -> None:
    item = CTIItem(
        content=_TOPIC_ESSAY,
        source="rss",
        title="Why detection engineering needs a new operating model",
        metadata={},
    )
    verdict = triage(item)
    assert verdict.park is True
    assert verdict.reason == "topic prose names no intrusion, exploit procedure, or indicator"


def test_the_same_essay_passes_when_it_names_a_procedure_or_an_intrusion() -> None:
    with_cve = CTIItem(
        content=_TOPIC_ESSAY + " CVE-2026-58115 is exploited by posting to /flows.",
        source="rss",
        title="Why detection engineering needs a new operating model",
        metadata={},
    )
    named = CTIItem(content=_TOPIC_ESSAY, source="rss", title="Lynx Ransomware", metadata={})
    with_command = CTIItem(
        content=_TOPIC_ESSAY + " The host ran powershell.exe -enc AAAA.",
        source="rss",
        title="Notes",
        metadata={},
    )
    assert triage(with_cve).park is False
    assert triage(named).park is False
    assert triage(with_command).park is False


def test_a_short_blurb_is_not_parked_for_lack_of_detail() -> None:
    assert triage(_item("Cat's Got Your Files: Lynx Ransomware")).park is False


# --- Legacy CVE and decommissioned platform gating -------------------------


def test_legacy_cve_prior_to_min_year_is_parked() -> None:
    item = CTIItem(
        content="Exploit procedure for CVE-2005-2428 affects Lotus Domino WebMail via GET /names.nsf.",
        source="nuclei",
        title="Nuclei template: CVE-2005-2428 - Lotus Domino R5 and R6 WebMail",
        metadata={"cve_id": "CVE-2005-2428"},
    )
    verdict = triage(item, min_cve_year=2021)
    assert verdict.park is True
    assert "targets legacy CVEs" in verdict.reason
    assert "2021" in verdict.reason


def test_modern_cve_passes_year_gate() -> None:
    item = CTIItem(
        content="Exploit procedure for CVE-2024-3400 command injection in PAN-OS GlobalProtect.",
        source="cisa_kev",
        title="PAN-OS GlobalProtect RCE",
        metadata={"cve_id": "CVE-2024-3400"},
    )
    verdict = triage(item, min_cve_year=2021)
    assert verdict.park is False


def test_mixed_cve_with_at_least_one_modern_passes_gate() -> None:
    item = CTIItem(
        content="Attack chain chains CVE-2019-1234 with CVE-2026-9082 against Drupal Core.",
        source="rss",
        title="Multi-stage Drupal compromise",
        metadata={"indicators": {"cve": ["CVE-2019-1234", "CVE-2026-9082"]}},
    )
    verdict = triage(item, min_cve_year=2021)
    assert verdict.park is False


def test_behavioral_cti_without_cve_is_not_parked_by_year_gate() -> None:
    item = CTIItem(
        content="Adversaries employ ClickFix social engineering targeting macOS using Mach-O payloads.",
        source="rss",
        title="ClickFix Campaign Delivers AMOS Infostealer",
        metadata={},
    )
    verdict = triage(item, min_cve_year=2021)
    assert verdict.park is False


def test_legacy_cve_gate_respects_custom_threshold() -> None:
    item = CTIItem(
        content="Exploit procedure for CVE-2005-2428 affects Lotus Domino WebMail.",
        source="nuclei",
        title="Nuclei template: CVE-2005-2428",
        metadata={"cve_id": "CVE-2005-2428"},
    )
    # When min_cve_year is set before 2005, it passes the year gate
    verdict = triage(item, min_cve_year=2000)
    # May still park on legacy software if Domino is mentioned without modern context
    assert "targets legacy CVEs" not in verdict.reason


def test_legacy_decommissioned_software_is_parked() -> None:
    item = CTIItem(
        content="Vulnerability discovered in Lotus Domino R5 mail routing daemon allows information leakage.",
        source="rss",
        title="Vulnerability in Lotus Domino Server",
        metadata={},
    )
    verdict = triage(item, min_cve_year=0)
    assert verdict.park is True
    assert "targets decommissioned legacy enterprise software" in verdict.reason


def test_legacy_software_with_modern_cloud_context_passes_platform_gate() -> None:
    item = CTIItem(
        content="Adversaries targeting Linux container environments migrate payloads to attack legacy services.",
        source="rss",
        title="Container threat group leverages multiple exploits",
        metadata={},
    )
    verdict = triage(item, min_cve_year=0)
    assert verdict.park is False
