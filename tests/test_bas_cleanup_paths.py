"""Cleanup uses the broker's canonical path policy even without the broker."""

import subprocess

import pytest

from hecate_runner.bas.lifecycle import clean_container_tmpfs


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/hecate-exec.trace",
        "//tmp/hecate-exec.trace",
        "///tmp/hecate-exec.trace",
        "/tmp//hecate-exec.trace",
        "/tmp/./hecate-exec.trace",
        "/tmp/hecate-exec.trace/",
        "/tmp//",
        "/tmp/.",
        "/tmp/../etc/shadow",
        "/etc/passwd",
        "/tmp/bad\x00name",
    ],
)
def test_cleanup_refuses_protected_aliases_and_noncanonical_paths(monkeypatch, path):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("hecate_runner.bas.lifecycle.run_docker", run)
    assert clean_container_tmpfs("fixture-agent", [path]) == []
    assert not calls


def test_cleanup_allows_canonical_benign_double_dot_filename(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("hecate_runner.bas.lifecycle.run_docker", run)
    assert clean_container_tmpfs("fixture-agent", ["/tmp/report..tmp"]) == ["/tmp/report..tmp"]
    assert calls == [["exec", "fixture-agent", "rm", "-rf", "/tmp/report..tmp"]]


@pytest.mark.parametrize(
    "path",
    [
        "//tmp/hecate-exec.trace",
        "/tmp//hecate-exec.trace",
        "/tmp/./hecate-exec.trace",
        "/tmp/hecate-exec.trace/",
        "/tmp/..",
        "/tmp",
    ],
)
def test_broker_uses_the_same_protected_path_policy(path):
    from hecate_runner.bas.docker_broker import Policy

    assert not Policy.tmp_path(path)
