"""Production Settings must refuse mock SIEM/BAS backends."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from hecate_runner.config import Settings


def test_settings_refuse_mock_query_provider_without_allow(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HECATE_RUNNER_ALLOW_MOCK", "false")
    monkeypatch.setenv("HECATE_RUNNER_QUERY_PROVIDER", "mock")
    monkeypatch.setenv("HECATE_BAS_MODE", "caldera")
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    with pytest.raises(ValidationError, match="QUERY_PROVIDER=mock is forbidden"):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_settings_refuse_mock_bas_mode_without_allow(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HECATE_RUNNER_ALLOW_MOCK", "false")
    monkeypatch.setenv("HECATE_RUNNER_QUERY_PROVIDER", "splunk")
    monkeypatch.setenv("HECATE_BAS_MODE", "mock")
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    with pytest.raises(ValidationError, match="BAS_MODE=mock is forbidden"):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_settings_refuse_bas_fallback_to_mock_without_allow(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HECATE_RUNNER_ALLOW_MOCK", "false")
    monkeypatch.setenv("HECATE_RUNNER_QUERY_PROVIDER", "splunk")
    monkeypatch.setenv("HECATE_BAS_MODE", "caldera")
    monkeypatch.setenv("HECATE_BAS_FALLBACK_TO_MOCK", "true")
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    with pytest.raises(ValidationError, match="FALLBACK_TO_MOCK=true is forbidden"):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_settings_allow_mock_when_explicitly_enabled(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HECATE_RUNNER_ALLOW_MOCK", "true")
    monkeypatch.setenv("HECATE_RUNNER_QUERY_PROVIDER", "mock")
    monkeypatch.setenv("HECATE_BAS_MODE", "mock")
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.allow_mock_backends is True
    assert settings.query_provider == "mock"
    assert settings.bas_mode == "mock"
