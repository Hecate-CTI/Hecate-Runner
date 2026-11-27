import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from hecate_runner.cti.cisa_kev import CisaKevProvider


@pytest.fixture
def provider(tmp_path):
    return CisaKevProvider(workspace=tmp_path)


def test_read_cursor_no_file(provider):
    dt = provider._read_cursor()
    # should be roughly 7 days ago
    now = datetime.now(UTC)
    assert (now - dt).days in (6, 7)


def test_read_cursor_with_file(provider):
    date_str = "2026-09-08T00:00:00+00:00"
    provider.cursor_file.parent.mkdir(parents=True, exist_ok=True)
    provider.cursor_file.write_text(json.dumps({"last_date_added": date_str}))
    dt = provider._read_cursor()
    assert dt.isoformat() == date_str


def test_write_cursor(provider):
    dt = datetime(2026, 9, 8, tzinfo=UTC)
    provider._write_cursor(dt)
    assert json.loads(provider.cursor_file.read_text())["last_date_added"] == dt.isoformat()


@patch("httpx.get")
def test_fetch_catalog_success(mock_get, provider):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {"cveID": "CVE-2", "dateAdded": "2026-09-02"},
            {"cveID": "CVE-1", "dateAdded": "2026-09-01"},
        ]
    }
    mock_get.return_value = mock_response

    vulns = provider._fetch_catalog()
    assert len(vulns) == 2
    # Should be sorted ascending
    assert vulns[0]["cveID"] == "CVE-1"
    assert vulns[1]["cveID"] == "CVE-2"


@patch("httpx.get")
def test_next_item_yields_new(mock_get, provider):
    # Set cursor to 2026-09-01
    provider._write_cursor(datetime(2026, 9, 1, tzinfo=UTC))

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cveID": "CVE-1",
                "dateAdded": "2026-09-01",
                "vendorProject": "A",
                "product": "B",
                "vulnerabilityName": "C",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2",
                "dateAdded": "2026-09-02",
                "vendorProject": "D",
                "product": "E",
                "vulnerabilityName": "F",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ]
    }
    mock_get.return_value = mock_response

    item = provider.next_item()
    assert item is not None
    assert item.identifier == "CVE-2"
    assert "Tags: ransomware-campaign-use" not in item.content

    # Next item should be None because we haven't acknowledged
    # Wait, next_item() re-reads catalog from cache, then checks cursor. Since cursor hasn't moved, it yields CVE-2 again.
    item2 = provider.next_item()
    assert item2.identifier == "CVE-2"


def test_acknowledge(provider):
    from hecate_runner.cti.base import CTIItem

    dt = datetime(2026, 9, 9, tzinfo=UTC)
    item = CTIItem(content="x", received_at=dt)
    provider.acknowledge(item)
    assert provider._read_cursor() == dt


@patch("httpx.get")
def test_cisa_kev_skips_legacy_cve_prior_to_min_year(mock_get, tmp_path):
    legacy_provider = CisaKevProvider(workspace=tmp_path, min_cve_year=2021)
    legacy_provider._write_cursor(datetime(2026, 9, 1, tzinfo=UTC))

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2005-2428",
                "dateAdded": "2026-09-02",
                "vendorProject": "IBM",
                "product": "Lotus Domino",
                "vulnerabilityName": "Lotus Domino WebMail Info Disclosure",
            },
            {
                "cveID": "CVE-2024-3400",
                "dateAdded": "2026-09-03",
                "vendorProject": "Palo Alto",
                "product": "PAN-OS",
                "vulnerabilityName": "Command Injection",
            },
        ]
    }
    mock_get.return_value = mock_response

    item = legacy_provider.next_item()
    # Should have skipped CVE-2005-2428 and yielded CVE-2024-3400
    assert item is not None
    assert item.identifier == "CVE-2024-3400"
    # Cursor should have advanced past CVE-2005-2428
    assert legacy_provider._read_cursor() >= datetime(2026, 9, 2, tzinfo=UTC)
