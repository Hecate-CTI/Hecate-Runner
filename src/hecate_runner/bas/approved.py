"""Reviewed, read-only procedures for unattended execution in the Linux lab.

Technique IDs alone are not an execution policy: CALDERA may map a technique
to downloads, payloads, or commands containing facts from intelligence. Pin the
ability and inspect its executable content before allowing it to run.

Catalog scope is intentional: these are general Linux discovery / canary
commands. Application-CVE Sigma rules that need product-specific predicates
should skip BAS rather than earn credit from an unrelated procedure. See
docs/BAS_AUTOMATION.md ("Honesty: BAS skip vs Sigma coverage") for the
policy and the future application-scoped expansion milestone.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from hecate_runner.bas.base import DetonationResult, SafetyViolationError


@dataclass(frozen=True)
class ApprovedProcedure:
    technique_id: str
    ability_id: str
    command: str
    observed_argv: tuple[str, ...] = ()
    managed: bool = False
    cleanup_command: str = ""
    cleanup_observed_argv: tuple[str, ...] = ()
    expected_files: tuple[str, ...] = ()
    expected_network: tuple[dict[str, Any], ...] = ()
    fidelity_scope: str = "behavioral"  # "behavioral" | "smoke_check"

    @property
    def argv(self) -> tuple[str, ...]:
        return self.observed_argv or tuple(shlex.split(self.command))


def _managed(
    technique: str,
    command: str,
    observed: tuple[str, ...] = (),
    cleanup_command: str = "",
    cleanup_observed: tuple[str, ...] = (),
    expected_files: tuple[str, ...] = (),
    expected_network: tuple[dict[str, Any], ...] = (),
    fidelity_scope: str = "behavioral",
) -> ApprovedProcedure:
    key = f"{command}:{cleanup_command}" if cleanup_command else command
    identity = str(uuid5(NAMESPACE_URL, f"https://hecate.local/bas/{technique}/v1/{key}"))
    return ApprovedProcedure(
        technique,
        identity,
        command,
        observed,
        True,
        cleanup_command,
        cleanup_observed,
        expected_files,
        expected_network,
        fidelity_scope,
    )


APPROVED_PROCEDURES = {
    "T1033": ApprovedProcedure("T1033", "bd527b63-9f9e-46e0-9816-b8434d2b8989", "whoami"),
    "T1057": ApprovedProcedure("T1057", "335cea7b-bec0-48c6-adfb-6066070f5f68", "ps"),
    "T1083": ApprovedProcedure("T1083", "52177cc1-b9ab-4411-ac21-2eadc4b5d3b8", "ls"),
    "T1082": _managed("T1082", "uname -a"),
    "T1016": _managed("T1016", "ip address show"),
    "T1087.001": _managed("T1087.001", "cut -d: -f1 /etc/passwd"),
    "T1069.001": ApprovedProcedure("T1069.001", "5c4dd985-89e3-4590-9b57-71fed66ff4e2", "groups"),
    "T1124": _managed("T1124", 'date -u +"%Y-%m-%dT%H:%M:%SZ"'),
    "T1059.004": _managed("T1059.004", "sh -c 'printf hecate-bas-shell-probe'"),
    "T1059.006": _managed(
        "T1059.006",
        "python3 -c 'import sys; sys.stdout.write(\"hecate-bas-python-probe\\n\")'",
        ("python3", "-c", 'import sys; sys.stdout.write("hecate-bas-python-probe\\n")'),
    ),
    "T1059.007": _managed(
        "T1059.007",
        "node -e 'process.stdout.write(\"hecate-bas-node-probe\\n\")'",
        ("node", "-e", 'process.stdout.write("hecate-bas-node-probe\\n")'),
    ),
    "T1140": _managed("T1140", "printf 'aGVjYXRlLWJhcy1wcm9iZQ==' | base64 -d", ("base64", "-d")),
    "T1070.004": _managed(
        "T1070.004",
        "sh -c 'touch /tmp/hecate-t1070-canary.tmp && rm -f /tmp/hecate-t1070-canary.tmp'",
        ("rm", "-f", "/tmp/hecate-t1070-canary.tmp"),
        cleanup_command="rm -f /tmp/hecate-t1070-canary.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1070-canary.tmp"),
        expected_files=("/tmp/hecate-t1070-canary.tmp",),
    ),
    "T1027": _managed(
        "T1027",
        "sh -c 'printf aGVjYXRlLWJhcw== | base64 -d > /tmp/hecate-t1027.tmp'",
        ("base64", "-d"),
        cleanup_command="rm -f /tmp/hecate-t1027.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1027.tmp"),
        expected_files=("/tmp/hecate-t1027.tmp",),
    ),
    "T1005": _managed(
        "T1005",
        "sh -c 'uname -a > /tmp/hecate-t1005.tmp'",
        ("uname", "-a"),
        cleanup_command="rm -f /tmp/hecate-t1005.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1005.tmp"),
        expected_files=("/tmp/hecate-t1005.tmp",),
    ),
    "T1053.003": _managed(
        "T1053.003",
        "sh -c 'printf \"* * * * * true # hecate-t1053\\n\" > /tmp/hecate-t1053.tmp && crontab /tmp/hecate-t1053.tmp'",
        ("crontab", "/tmp/hecate-t1053.tmp"),
        cleanup_command="sh -c 'crontab -r && rm -f /tmp/hecate-t1053.tmp'",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1053.tmp"),
        expected_files=("/tmp/hecate-t1053.tmp",),
        fidelity_scope="behavioral",
    ),
    "T1105": _managed(
        "T1105",
        "sh -c 'curl -f -sS -m 2 http://127.0.0.1:8888/ -o /tmp/hecate-t1105.tmp && test -s /tmp/hecate-t1105.tmp'",
        ("curl", "-f", "-sS", "-m", "2", "http://127.0.0.1:8888/", "-o", "/tmp/hecate-t1105.tmp"),
        cleanup_command="rm -f /tmp/hecate-t1105.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1105.tmp"),
        expected_files=("/tmp/hecate-t1105.tmp",),
        expected_network=(
            {"DestinationIp": "127.0.0.1", "DestinationPort": 8888, "Protocol": "tcp"},
        ),
        fidelity_scope="behavioral",
    ),
    "T1049": _managed("T1049", "ss -tan"),
    "T1007": _managed(
        "T1007",
        "systemctl list-units --type=service --state=running",
        ("systemctl", "list-units", "--type=service", "--state=running"),
    ),
    "T1518.001": _managed(
        "T1518.001",
        "systemctl status ufw",
        ("systemctl", "status", "ufw"),
    ),
    "T1018": _managed("T1018", "arp -a"),
    "T1222.002": _managed(
        "T1222.002",
        "sh -c 'touch /tmp/hecate-t1222.tmp && chmod 644 /tmp/hecate-t1222.tmp && rm -f /tmp/hecate-t1222.tmp'",
        ("chmod", "644", "/tmp/hecate-t1222.tmp"),
        cleanup_command="rm -f /tmp/hecate-t1222.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1222.tmp"),
        expected_files=("/tmp/hecate-t1222.tmp",),
    ),
    "T1036.005": _managed(
        "T1036.005",
        "sh -c 'touch /tmp/hecate-t1036-crond.tmp && rm -f /tmp/hecate-t1036-crond.tmp'",
        ("touch", "/tmp/hecate-t1036-crond.tmp"),
        cleanup_command="rm -f /tmp/hecate-t1036-crond.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1036-crond.tmp"),
        expected_files=("/tmp/hecate-t1036-crond.tmp",),
    ),
    "T1543.002": _managed(
        "T1543.002",
        "systemctl is-active cron",
        ("systemctl", "is-active", "cron"),
        fidelity_scope="smoke_check",
    ),
    "T1552.001": _managed(
        "T1552.001",
        "grep -s 'BEGIN PRIVATE KEY' /etc/ssl/certs/",
        ("grep", "-s", "BEGIN PRIVATE KEY", "/etc/ssl/certs/"),
    ),
    "T1003.008": _managed(
        "T1003.008",
        "head -n 1 /etc/passwd",
        ("head", "-n", "1", "/etc/passwd"),
    ),
    "T1046": _managed(
        "T1046",
        "nc -z -v -w 1 127.0.0.1 22",
        ("nc", "-z", "-v", "-w", "1", "127.0.0.1", "22"),
        expected_network=(
            {"DestinationIp": "127.0.0.1", "DestinationPort": 22, "Protocol": "tcp"},
        ),
    ),
    "T1526": _managed(
        "T1526",
        "curl -s -m 1 http://127.0.0.1:80/latest/meta-data/",
        ("curl", "-s", "-m", "1", "http://127.0.0.1:80/latest/meta-data/"),
        expected_network=(
            {"DestinationIp": "127.0.0.1", "DestinationPort": 80, "Protocol": "tcp"},
            {"DestinationIp": "169.254.169.254", "DestinationPort": 80, "Protocol": "tcp"},
        ),
    ),
    "T1613": _managed(
        "T1613",
        "cat /proc/1/cgroup",
        ("cat", "/proc/1/cgroup"),
    ),
    "T1071.001": _managed(
        "T1071.001",
        "curl -sI https://localhost/",
        ("curl", "-sI", "https://localhost/"),
        expected_network=(
            {
                "DestinationIp": "127.0.0.1",
                "DestinationHostname": "localhost",
                "DestinationPort": 443,
                "Protocol": "tcp",
            },
        ),
        fidelity_scope="smoke_check",
    ),
    "T1190": _managed(
        "T1190",
        "curl -s http://127.0.0.1:80/",
        ("curl", "-s", "http://127.0.0.1:80/"),
        expected_network=(
            {"DestinationIp": "127.0.0.1", "DestinationPort": 80, "Protocol": "tcp"},
        ),
        fidelity_scope="smoke_check",
    ),
    "T1041": _managed(
        "T1041",
        "sh -c 'printf hecate-exfil-test | wc -c'",
        ("wc", "-c"),
        fidelity_scope="smoke_check",
    ),
}


# These exact, validated catalog commands do not create remote artifacts that
# need teardown. Keep this explicit: a new procedure is not exempt merely
# because somebody forgot to define its cleanup command.
ARTIFACT_FREE_TECHNIQUES = frozenset(
    {
        "T1033",
        "T1057",
        "T1083",
        "T1082",
        "T1016",
        "T1087.001",
        "T1069.001",
        "T1124",
        "T1059.004",
        "T1059.006",
        "T1059.007",
        "T1140",
        "T1049",
        "T1007",
        "T1518.001",
        "T1018",
        "T1543.002",
        "T1552.001",
        "T1003.008",
        "T1046",
        "T1526",
        "T1613",
        "T1071.001",
        "T1190",
        "T1041",
    }
)


def resolve_fidelity_scope(detonation: DetonationResult, requested: str | None = None) -> str:
    """A caller cannot upgrade a pinned smoke check to behavioral validation."""
    scopes = [
        requested,
        result_fidelity_scope(
            {
                "ability_id": detonation.ability_id,
                "fidelity_scope": detonation.raw_details.get("fidelity_scope"),
            }
        ),
    ]
    return next((str(scope) for scope in scopes if scope and scope != "behavioral"), "behavioral")


def result_fidelity_scope(result: Mapping[str, Any]) -> str:
    scope = str(result.get("fidelity_scope") or "behavioral")
    if scope == "behavioral":
        for procedure in APPROVED_PROCEDURES.values():
            if (
                procedure.ability_id == result.get("ability_id")
                and procedure.fidelity_scope != "behavioral"
            ):
                return procedure.fidelity_scope
    return scope


def _is_mock_or_synthetic(result: Mapping[str, Any]) -> bool:
    """True when the result is mock/synthesis — never live lab credit."""
    provider = str(result.get("provider") or "").strip().lower()
    backend = str(result.get("backend") or "").strip().lower()
    status = str(result.get("status") or "").strip().lower()
    if result.get("mock_fallback") is True:
        return True
    if provider == "mock" or backend == "mock":
        return True
    return status in {"simulation_match", "simulation_no_match"}


def confirms_technique(result: Mapping[str, Any]) -> bool:
    """Live behavioral BAS credit only — never mock, simulation, or smoke checks."""
    if _is_mock_or_synthetic(result):
        return False
    return (
        result.get("status") == "verified_true_positive"
        and result_fidelity_scope(result) == "behavioral"
    )


def result_status(result: Mapping[str, Any]) -> str:
    status = str(result.get("status", "unknown"))
    if _is_mock_or_synthetic(result) and status == "verified_true_positive":
        # Old drafts labeled mock runs as verified_true_positive — don't keep that lie.
        return "simulation_match"
    if status == "verified_true_positive" and not confirms_technique(result):
        return "smoke_check_match"
    return status


def catalog_digest() -> str:
    """Return a deterministic SHA-256 digest of the approved procedure catalog."""
    hasher = hashlib.sha256()
    for tech_id in sorted(APPROVED_PROCEDURES):
        proc = APPROVED_PROCEDURES[tech_id]
        payload = json.dumps(
            {
                "technique_id": proc.technique_id,
                "ability_id": proc.ability_id,
                "command": proc.command,
                "observed_argv": list(proc.observed_argv),
                "managed": proc.managed,
                "cleanup_command": proc.cleanup_command,
                "expected_files": list(proc.expected_files),
                "expected_network": [dict(n) for n in proc.expected_network],
                "artifact_free": tech_id in ARTIFACT_FREE_TECHNIQUES,
                "fidelity_scope": proc.fidelity_scope,
            },
            sort_keys=True,
        ).encode("utf-8")
        hasher.update(payload)
        hasher.update(b"\0")
    return hasher.hexdigest()


def ability_definition(procedure: ApprovedProcedure) -> dict[str, Any]:
    """Exact fixed content for a Hecate-managed ability; no CTI inputs."""
    if APPROVED_PROCEDURES.get(procedure.technique_id) != procedure or not procedure.managed:
        raise SafetyViolationError("Only catalog-managed abilities can be installed.")
    exec_config: dict[str, Any] = {"command": procedure.command, "timeout": 10}
    if procedure.cleanup_command:
        exec_config["cleanup"] = procedure.cleanup_command
    return {
        "id": procedure.ability_id,
        "name": f"Hecate isolated lab {procedure.technique_id}",
        "description": "Pinned non-destructive Linux lab procedure; local sensor verification.",
        "tactic": {
            "T1190": "initial-access",
            "T1059.004": "execution",
            "T1059.006": "execution",
            "T1059.007": "execution",
            "T1053.003": "persistence",
            "T1543.002": "persistence",
            "T1222.002": "defense-evasion",
            "T1036.005": "defense-evasion",
            "T1140": "defense-evasion",
            "T1070.004": "defense-evasion",
            "T1027": "defense-evasion",
            "T1003.008": "credential-access",
            "T1552.001": "credential-access",
            "T1005": "collection",
            "T1071.001": "command-and-control",
            "T1105": "command-and-control",
            "T1041": "exfiltration",
        }.get(procedure.technique_id, "discovery"),
        "technique": {"attack_id": procedure.technique_id, "name": procedure.technique_id},
        "platforms": {"linux": {"sh": exec_config}},
    }


def validate_approved_ability(ability: dict[str, Any], procedure: ApprovedProcedure) -> None:
    """Reject altered commands and any additional executable behavior."""
    if (
        ability.get("ability_id") != procedure.ability_id
        or ability.get("technique_id") != procedure.technique_id
        or ability.get("requirements")
        or ability.get("privilege")
    ):
        raise SafetyViolationError("Approved CALDERA ability identity or requirements changed.")
    executors = [e for e in ability.get("executors", []) if e.get("platform") == "linux"]
    if len(executors) != 1:
        raise SafetyViolationError("Approved ability requires exactly one Linux executor.")
    executor = executors[0]

    # Validate cleanup
    cleanup = executor.get("cleanup")
    if procedure.cleanup_command:
        expected = [procedure.cleanup_command]
        actual = [cleanup] if isinstance(cleanup, str) else list(cleanup or [])
        if actual != expected:
            raise SafetyViolationError("Approved CALDERA cleanup command altered or missing.")
    elif cleanup:
        raise SafetyViolationError("Unapproved cleanup command present on ability.")

    if (
        executor.get("name") != "sh"
        or executor.get("command") != procedure.command
        or any(
            executor.get(key)
            for key in (
                "payloads",
                "uploads",
                "variations",
                "code",
                "build_target",
                "parsers",
                "additional_info",
            )
        )
    ):
        raise SafetyViolationError("Approved CALDERA procedure content changed; execution refused.")


COMMON_PARENTS: tuple[str, ...] = (
    "/usr/sbin/php-fpm",
    "/usr/sbin/php-cgi",
    "/usr/sbin/apache2",
    "/usr/sbin/httpd",
    "/usr/sbin/nginx",
    "/usr/bin/python3",
    "/usr/bin/node",
    "/usr/bin/gunicorn",
    "/usr/bin/uwsgi",
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/cron",
    "/lib/systemd/systemd",
)


def select_approved_rule(
    rules: list[dict[str, Any]], techniques: list[str], allowed: list[str]
) -> tuple[ApprovedProcedure, str] | None:
    """Select a matching Linux process rule, without broadening to parent techniques.

    Prefers ``behavioral`` procedures. A ``smoke_check`` procedure is only chosen
    when no behavioral match exists; orchestrator/runtime still demote those to
    ``smoke_check_match`` and never set ``bas_verified``.
    """
    behavioral = _select_approved_rule(rules, techniques, allowed, fidelity="behavioral")
    if behavioral is not None:
        return behavioral
    return _select_approved_rule(rules, techniques, allowed, fidelity="smoke_check")


def _select_approved_rule(
    rules: list[dict[str, Any]],
    techniques: list[str],
    allowed: list[str],
    *,
    fidelity: str,
) -> tuple[ApprovedProcedure, str] | None:
    import yaml

    for rule in rules:
        text = rule.get("rule_yaml", "")
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue
        source = parsed.get("logsource") or {}
        if not isinstance(source, dict):
            continue
        category = source.get("category", "")
        product = str(source.get("product") or "").lower()
        if (
            product and product not in ("linux", "container", "containers", "unix")
        ) or category not in (
            "process_creation",
            "file_event",
            "file_change",
            "network_connection",
        ):
            continue
        tags = {str(t).lower() for t in parsed.get("tags") or []}
        rule_techniques = {str(t).upper() for t in rule.get("techniques") or []}
        rule_techniques.update(
            t.removeprefix("attack.").upper() for t in tags if t.startswith("attack.t")
        )
        for technique in techniques:
            if (
                technique in allowed
                and technique in rule_techniques
                and technique in APPROVED_PROCEDURES
            ):
                procedure = APPROVED_PROCEDURES[technique]
                if procedure.fidelity_scope != fidelity:
                    continue
                if _procedure_matches_rule(procedure, text, COMMON_PARENTS):
                    return procedure, text
    return None


def _procedure_matches_rule(
    procedure: ApprovedProcedure, rule_yaml: str, common_parents: tuple[str, ...]
) -> bool:
    """True when synthetic observations of the pinned command can hit the rule."""
    from hecate_agent.core.sigma_evaluator import SigmaEvaluator

    candidates: list[dict[str, Any]] = []

    # 1. Process creation candidates
    bin_directories = ("/bin", "/usr/bin", "/sbin", "/usr/sbin")
    for directory in bin_directories:
        candidates.append(
            {
                "data_source": "process_creation",
                "category": "process_creation",
                "product": "linux",
                "Image": f"{directory}/{procedure.argv[0]}",
                "CommandLine": shlex.join(procedure.argv),
                "User": "root",
            }
        )
    if procedure.command.startswith(("sh -c", "bash -c")):
        candidates.append(
            {
                "data_source": "process_creation",
                "category": "process_creation",
                "product": "linux",
                "Image": "/bin/sh",
                "CommandLine": procedure.command,
                "User": "root",
            }
        )
        candidates.append(
            {
                "data_source": "process_creation",
                "category": "process_creation",
                "product": "linux",
                "Image": "/bin/bash",
                "CommandLine": procedure.command,
                "User": "root",
            }
        )

    for directory in ("/bin", "/usr/bin"):
        for parent in common_parents:
            candidates.append(
                {
                    "data_source": "process_creation",
                    "category": "process_creation",
                    "product": "linux",
                    "Image": f"{directory}/{procedure.argv[0]}",
                    "CommandLine": shlex.join(procedure.argv),
                    "ParentImage": parent,
                    "User": (
                        "www-data"
                        if any(
                            w in parent
                            for w in (
                                "php",
                                "apache",
                                "httpd",
                                "nginx",
                                "gunicorn",
                                "uwsgi",
                                "lighttpd",
                            )
                        )
                        else "root"
                    ),
                }
            )

    # 2. File event candidates
    for fpath in procedure.expected_files:
        candidates.append(
            {
                "data_source": "file_event",
                "category": "file_event",
                "product": "linux",
                "TargetFilename": fpath,
                "Image": f"/usr/bin/{procedure.argv[0]}",
                "CommandLine": shlex.join(procedure.argv),
            }
        )

    # 3. Network connection candidates
    network_targets: list[dict[str, Any]] = list(procedure.expected_network)
    if not network_targets:
        import re
        import urllib.parse

        url_matches = re.findall(r"https?://[^\s'\"`]+", procedure.command)
        for url in url_matches:
            try:
                parsed = urllib.parse.urlsplit(url)
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                host = parsed.hostname or "127.0.0.1"
                network_targets.append(
                    {
                        "DestinationIp": "127.0.0.1"
                        if host in ("127.0.0.1", "localhost")
                        else host,
                        "DestinationPort": port,
                        "DestinationHostname": host if host not in ("127.0.0.1", "::1") else None,
                        "Protocol": "tcp",
                    }
                )
            except Exception:
                pass
        nc_match = re.search(r"\bnc\s+(?:-[a-zA-Z0-9]+\s+)*([^\s]+)\s+(\d+)", procedure.command)
        if nc_match:
            host, port = nc_match.group(1), int(nc_match.group(2))
            network_targets.append(
                {
                    "DestinationIp": "127.0.0.1" if host in ("127.0.0.1", "localhost") else host,
                    "DestinationPort": port,
                    "Protocol": "tcp",
                }
            )

    for net in network_targets:
        dst_ip = net.get("DestinationIp", "127.0.0.1")
        dst_port = int(net.get("DestinationPort", 80))
        proto = net.get("Protocol", "tcp")
        dst_host = net.get("DestinationHostname")

        for directory in ("/bin", "/usr/bin"):
            base_net = {
                "data_source": "network_connection",
                "category": "network_connection",
                "product": "linux",
                "Image": f"{directory}/{procedure.argv[0]}",
                "CommandLine": shlex.join(procedure.argv),
                "DestinationIp": dst_ip,
                "DestinationPort": dst_port,
                "Protocol": proto,
                "Initiated": True,
                "User": "root",
            }
            if dst_host:
                base_net["DestinationHostname"] = dst_host
            candidates.append(base_net)

            if dst_ip in ("127.0.0.1", "localhost"):
                ext_net = dict(base_net)
                ext_net["DestinationIp"] = "198.51.100.1"
                candidates.append(ext_net)

            for parent in common_parents:
                parent_net = dict(base_net)
                parent_net["ParentImage"] = parent
                parent_net["User"] = (
                    "www-data"
                    if any(
                        w in parent
                        for w in (
                            "php",
                            "apache",
                            "httpd",
                            "nginx",
                            "gunicorn",
                            "uwsgi",
                            "lighttpd",
                        )
                    )
                    else "root"
                )
                candidates.append(parent_net)
                if dst_ip in ("127.0.0.1", "localhost"):
                    ext_parent_net = dict(parent_net)
                    ext_parent_net["DestinationIp"] = "198.51.100.1"
                    candidates.append(ext_parent_net)

        if procedure.technique_id == "T1190" or any(
            w in procedure.command for w in ("curl", "wget")
        ):
            for parent in common_parents:
                if any(w in parent for w in ("apache", "httpd", "nginx", "php")):
                    web_net = {
                        "data_source": "network_connection",
                        "category": "network_connection",
                        "product": "linux",
                        "Image": parent,
                        "DestinationIp": dst_ip,
                        "DestinationPort": dst_port,
                        "Protocol": proto,
                        "Initiated": True,
                        "User": "www-data",
                    }
                    if dst_host:
                        web_net["DestinationHostname"] = dst_host
                    candidates.append(web_net)
                    if dst_ip in ("127.0.0.1", "localhost"):
                        ext_web_net = dict(web_net)
                        ext_web_net["DestinationIp"] = "198.51.100.1"
                        candidates.append(ext_web_net)

    try:
        return bool(SigmaEvaluator.evaluate_rule(rule_yaml, candidates, []).true_positives > 0)
    except Exception:
        return False


def explain_approved_selection(
    rules: list[dict[str, Any]], techniques: list[str], allowed: list[str]
) -> str:
    """Human-readable reason when ``select_approved_rule`` returns None."""
    import yaml

    if not rules:
        return "No Sigma rules available for approved BAS selection."
    if not techniques:
        return "Hunt has no ATT&CK techniques to map to approved procedures."
    if not allowed:
        return "HECATE_BAS_AUTO_TECHNIQUES is empty; no approved procedures are eligible."

    allowed_set = set(allowed)
    approved_hits = [t for t in techniques if t in APPROVED_PROCEDURES and t in allowed_set]
    if not approved_hits:
        return (
            "No hunt techniques are both allowlisted and in the approved procedure catalog "
            f"(techniques={techniques!r}, allowlist_count={len(allowed_set)})."
        )

    linux_rules = 0
    predicate_misses = 0
    for rule in rules:
        text = rule.get("rule_yaml", "")
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue
        source = parsed.get("logsource") or {}
        if not isinstance(source, dict):
            continue
        category = source.get("category", "")
        product = str(source.get("product") or "").lower()
        if (
            product and product not in ("linux", "container", "containers", "unix")
        ) or category not in (
            "process_creation",
            "file_event",
            "file_change",
            "network_connection",
        ):
            continue
        linux_rules += 1
        tags = {str(t).lower() for t in parsed.get("tags") or []}
        rule_techniques = {str(t).upper() for t in rule.get("techniques") or []}
        rule_techniques.update(
            t.removeprefix("attack.").upper() for t in tags if t.startswith("attack.t")
        )
        for technique in approved_hits:
            if technique not in rule_techniques:
                continue
            procedure = APPROVED_PROCEDURES[technique]
            if not _procedure_matches_rule(procedure, text, COMMON_PARENTS):
                predicate_misses += 1

    if linux_rules == 0:
        return (
            "No Linux process/file/network Sigma rules available for approved BAS "
            f"(catalog techniques present: {approved_hits})."
        )
    if predicate_misses:
        return (
            "Approved procedures exist for this hunt, but none exercise the drafted "
            f"Linux rule predicates (checked {predicate_misses} technique/rule pair(s); "
            f"techniques={approved_hits})."
        )
    return "No approved procedure exercises this hunt's Linux rule predicates."
