"""Keep explicit network indicators while excluding software version numbers."""

import pytest

from hecate_runner.correlation import ThreatEntityExtractor

ADDRESS = "45.33.32.156"
VERSION = "17.0.21.1"


@pytest.mark.parametrize(
    "text",
    [
        f"The malware contacted C2 server {ADDRESS}.",
        f"The implant sent data to receiver {ADDRESS}.",
        f"The malware used curl to contact {ADDRESS}.",
        f"The implant used python to reach {ADDRESS}.",
        f"The actor used git to contact {ADDRESS}.",
        f"Command: curl {ADDRESS}",
        f"The implant connected to nginx {ADDRESS}.",
        f"The actor reached the web server with apache {ADDRESS}.",
        f"Software version | C2 IP\n{VERSION} | {ADDRESS}",
        f"IP address | Software version\n{ADDRESS} | {VERSION}",
        f"Affected version {VERSION}.\n| Indicator | Role |\n| {ADDRESS} | C2 |",
        f"| Software version | C2 IP |\n| {VERSION} | {ADDRESS} |",
        f"| IP address | Software version |\n| {ADDRESS} | {VERSION} |",
        f"Fixed version {VERSION}. The C2 address was [{ADDRESS}](https://incident.example/analysis).",
    ],
)
@pytest.mark.parametrize("metadata", [None, {"indicators": {"ipv4": [ADDRESS]}}])
def test_real_ip_survives_nearby_version_or_tool_context(text, metadata):
    found = ThreatEntityExtractor.extract_network_iocs(text, metadata)
    assert ADDRESS in found
    assert VERSION not in found


@pytest.mark.parametrize(
    "text",
    [
        f"Fixed in: {VERSION}, 21.0.13.1 and 25.0.5.1.",
        f"Affected software version [{VERSION}](https://vendor.example/advisory).",
        "| Product | Baseline | Patch Version |\n| JDK 17 | 17.0.1.0 | 17.0.21.1 |\n| JDK 21 | 21.0.1.0 | 21.0.13.1 |",
        "Fixed in:\n- 17.0.21.1\n- 21.0.13.1\n- 25.0.5.1",
    ],
)
def test_version_lists_links_and_table_columns_remain_excluded(text):
    found = ThreatEntityExtractor.extract_network_iocs(text)
    assert not found.intersection({VERSION, "21.0.13.1", "25.0.5.1", "17.0.1.0", "21.0.1.0"})


def test_metadata_ip_is_not_confused_with_substring_of_another_version():
    found = ThreatEntityExtractor.extract_network_iocs(
        "Affected version 145.33.32.156.", {"indicators": {"ipv4": [ADDRESS]}}
    )
    assert ADDRESS in found
    assert "145.33.32.156" not in found


def test_same_value_in_version_and_network_context_retains_the_network_evidence():
    text = f"Component version {ADDRESS}.\nC2 server {ADDRESS}."
    assert ADDRESS in ThreatEntityExtractor.extract_network_iocs(
        text, {"indicators": {"ipv4": [ADDRESS]}}
    )


def test_curl_version_output_is_still_not_network_evidence():
    assert VERSION not in ThreatEntityExtractor.extract_network_iocs(f"curl version {VERSION}")


@pytest.mark.parametrize("outer_pipes", [False, True])
def test_long_mixed_table_retains_its_header_and_every_network_address(outer_pipes):
    addresses = {f"45.33.32.{index}" for index in range(10, 110)}
    rows = ["Software version | C2 IP", "--- | ---"]
    rows += [f"{VERSION} | 45.33.32.{10 + index % 100}" for index in range(1000)]
    if outer_pipes:
        rows = [f"| {line} |" for line in rows]
    text = "\n".join(rows)
    found = ThreatEntityExtractor.extract_network_iocs(
        text, {"indicators": {"ipv4": sorted(addresses | {VERSION})}}
    )
    assert addresses <= found
    assert VERSION not in found


@pytest.mark.parametrize("version_label", ["Source version", "Source build", "Destination version"])
@pytest.mark.parametrize("network_label", ["Source", "Destination", "Source IP", "C2 IP"])
@pytest.mark.parametrize("network_first", [False, True])
def test_direction_words_in_version_headers_do_not_override_column_type(
    version_label, network_label, network_first
):
    columns = [(version_label, VERSION), (network_label, ADDRESS)]
    if network_first:
        columns.reverse()
    text = " | ".join(label for label, _ in columns) + "\n"
    text += " | ".join(value for _, value in columns)
    found = ThreatEntityExtractor.extract_network_iocs(text)
    assert ADDRESS in found
    assert VERSION not in found
