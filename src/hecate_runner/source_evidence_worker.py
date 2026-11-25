"""Private worker for the source evidence stage's shared, hard deadline."""

from __future__ import annotations

import contextlib
import errno
import ipaddress
import json
import logging
import os
import socket
import sys
from dataclasses import asdict
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

_ORIG_CONNECT = socket.socket.connect
_ORIG_CONNECT_EX = socket.socket.connect_ex
_ORIG_GETADDRINFO = socket.getaddrinfo

_EGRESS_FILTER_INSTALLED = False

BLOCKED_WORKER_ENV_PREFIXES = (
    "SLACK_",
    "SPLUNK_",
    "CALDERA_",
    "MISP_",
    "AWS_",
    "GITHUB_",
)


def sanitize_worker_process_env() -> None:
    """Purge sensitive integration tokens from os.environ."""
    for key in list(os.environ.keys()):
        upper = key.upper()
        if any(upper.startswith(bad) for bad in BLOCKED_WORKER_ENV_PREFIXES):
            del os.environ[key]


def _get_allowed_endpoints() -> set[tuple[str, int]]:
    """Collect (host, port) endpoints explicitly configured for LLM providers."""
    allowed: set[tuple[str, int]] = set()
    for env_var in ("OLLAMA_HOST", "HECATE_LLM_BASE_URL", "OPENAI_BASE_URL"):
        val = os.getenv(env_var, "").strip()
        if not val:
            continue
        target = val if "://" in val else f"http://{val}"
        try:
            parsed = urlsplit(target)
            host = (parsed.hostname or "").lower()
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if host:
                allowed.add((host, port))
                try:
                    for res in _ORIG_GETADDRINFO(host, port, proto=socket.IPPROTO_TCP):
                        allowed.add((res[4][0].lower(), port))
                except Exception:
                    pass
        except Exception:
            pass
    return allowed


def _is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if IP is loopback, link-local, private, or otherwise non-global."""
    if (
        not ip.is_global
        or ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in ipaddress.ip_network("169.254.0.0/16"):
            return True
    elif isinstance(ip, ipaddress.IPv6Address):
        if ip in ipaddress.ip_network("fe80::/10"):
            return True
        if ip.ipv4_mapped:
            return _is_ip_blocked(ip.ipv4_mapped)
        for prefix in (
            ipaddress.ip_network("64:ff9b::/96"),
            ipaddress.ip_network("64:ff9b:1::/48"),
        ):
            if ip in prefix:
                try:
                    v4 = ipaddress.IPv4Address(ip.packed[-4:])
                    if _is_ip_blocked(v4):
                        return True
                except Exception:
                    return True
    return False


def _check_socket_destination(address: Any) -> None:
    """Validate that address is global or an explicitly allowed LLM endpoint."""
    if not isinstance(address, tuple) or len(address) < 2:
        return
    host, port = address[0], address[1]
    if not isinstance(host, str) or not isinstance(port, int):
        return

    host_lower = host.lower()
    allowed_endpoints = _get_allowed_endpoints()
    if (host_lower, port) in allowed_endpoints:
        return

    if host_lower in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or host_lower.endswith(
        (".local", ".internal", ".onion")
    ):
        raise PermissionError(f"Egress to internal host {host}:{port} is blocked")

    try:
        ip = ipaddress.ip_address(host)
        if _is_ip_blocked(ip):
            raise PermissionError(f"Egress to non-public IP {host}:{port} is blocked")
        return
    except ValueError:
        pass

    try:
        infos = _ORIG_GETADDRINFO(host, port, proto=socket.IPPROTO_TCP)
    except Exception:
        return

    for info in infos:
        resolved_ip_str = info[4][0]
        if (resolved_ip_str.lower(), port) in allowed_endpoints:
            continue
        try:
            ip = ipaddress.ip_address(resolved_ip_str)
            if _is_ip_blocked(ip):
                raise PermissionError(
                    f"Egress to host {host}:{port} resolving to non-public IP {resolved_ip_str} is blocked"
                )
        except ValueError:
            raise PermissionError(f"Egress to host {host}:{port} is blocked") from None


def install_socket_egress_filter(force: bool = False) -> None:
    """Install process-wide socket egress filter blocking loopback, metadata and private destinations."""
    global _EGRESS_FILTER_INSTALLED
    if _EGRESS_FILTER_INSTALLED and not force:
        return

    def filtered_connect(self: socket.socket, address: Any) -> None:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            _check_socket_destination(address)
        return _ORIG_CONNECT(self, address)

    def filtered_connect_ex(self: socket.socket, address: Any) -> int:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            try:
                _check_socket_destination(address)
            except PermissionError:
                return errno.EPERM
        return _ORIG_CONNECT_EX(self, address)

    socket.socket.connect = filtered_connect  # type: ignore[assignment]
    socket.socket.connect_ex = filtered_connect_ex  # type: ignore[assignment]
    _EGRESS_FILTER_INSTALLED = True


def uninstall_socket_egress_filter() -> None:
    """Uninstall the socket egress filter and restore original socket connect methods."""
    global _EGRESS_FILTER_INSTALLED
    socket.socket.connect = _ORIG_CONNECT  # type: ignore[assignment]
    socket.socket.connect_ex = _ORIG_CONNECT_EX  # type: ignore[assignment]
    _EGRESS_FILTER_INSTALLED = False


def collect(url: str, indicators: dict[str, list[str]]) -> dict[str, Any]:
    install_socket_egress_filter()
    sanitize_worker_process_env()

    from hecate_agent.core.source_evidence import (
        build_indicator_records,
        extract_source_evidence,
    )
    from hecate_agent.core.source_extraction import SourceExtractionSession
    from hecate_agent.core.workspace import load_workspace_env, workspace_root

    load_workspace_env()
    sanitize_worker_process_env()

    cache_enabled = os.getenv("HECATE_RUNNER_SOURCE_EVIDENCE_CACHE_ENABLED", "true").lower() in {
        "1",
        "true",
        "yes",
    }
    session = SourceExtractionSession(
        max_calls=int(os.getenv("HECATE_RUNNER_SOURCE_EVIDENCE_MAX_CALLS", "16")),
        max_tokens=int(os.getenv("HECATE_RUNNER_SOURCE_EVIDENCE_MAX_TOKENS", "256000")),
        cache_path=workspace_root() / ".hecate" / "source_evidence.db" if cache_enabled else None,
        cache_ttl_sec=int(os.getenv("HECATE_RUNNER_SOURCE_EVIDENCE_CACHE_TTL_SEC", "86400")),
    )
    evidence = extract_source_evidence(url, session=session)
    records = (
        build_indicator_records(indicators, evidence, session=session) if evidence.text else []
    )
    return {"evidence": asdict(evidence), "records": [asdict(record) for record in records]}


def main() -> None:
    install_socket_egress_filter()
    sanitize_worker_process_env()
    request = json.load(sys.stdin)
    # Providers may print diagnostics. Keep stdout exclusively for the result.
    with contextlib.redirect_stdout(sys.stderr):
        result = collect(request["url"], request["indicators"])
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
