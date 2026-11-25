"""Unit tests for BAS network predicates and scripting interpreter procedures."""

from __future__ import annotations

from hecate_runner.bas.approved import (
    APPROVED_PROCEDURES,
    ARTIFACT_FREE_TECHNIQUES,
    ability_definition,
    explain_approved_selection,
    select_approved_rule,
)
from hecate_runner.bas.sensor import parse_net_trace


def test_python_and_node_procedures_cataloged_and_artifact_free():
    """T1059.006 and T1059.007 must be in catalog, artifact-free, and map to execution tactic."""
    assert "T1059.006" in APPROVED_PROCEDURES
    assert "T1059.007" in APPROVED_PROCEDURES

    py_proc = APPROVED_PROCEDURES["T1059.006"]
    node_proc = APPROVED_PROCEDURES["T1059.007"]

    assert py_proc.fidelity_scope == "behavioral"
    assert node_proc.fidelity_scope == "behavioral"
    assert py_proc.argv[0] == "python3"
    assert node_proc.argv[0] == "node"

    assert "T1059.006" in ARTIFACT_FREE_TECHNIQUES
    assert "T1059.007" in ARTIFACT_FREE_TECHNIQUES

    py_ability = ability_definition(py_proc)
    assert py_ability["tactic"] == "execution"
    assert py_ability["platforms"]["linux"]["sh"]["command"] == py_proc.command

    node_ability = ability_definition(node_proc)
    assert node_ability["tactic"] == "execution"
    assert node_ability["platforms"]["linux"]["sh"]["command"] == node_proc.command


def test_python_procedure_matches_webserver_spawned_interpreter_rule():
    """T1059.006 exercises process rules where webservers spawn python."""
    rule_yaml = """
title: Web Server Spawning Python Interpreter
logsource:
  category: process_creation
  product: linux
tags:
  - attack.t1059.006
detection:
  selection_parent:
    ParentImage|endswith:
      - /httpd
      - /apache2
      - /nginx
  selection_child:
    Image|endswith:
      - /python
      - /python3
  condition: selection_parent and selection_child
"""
    selection = select_approved_rule(
        [{"rule_yaml": rule_yaml, "techniques": ["T1059.006"]}],
        ["T1059.006"],
        ["T1059.006"],
    )
    assert selection is not None
    proc, matched_yaml = selection
    assert proc.technique_id == "T1059.006"
    assert matched_yaml == rule_yaml


def test_node_procedure_matches_javascript_interpreter_rule():
    """T1059.007 exercises process rules where webservers spawn node."""
    rule_yaml = """
title: Web Server Spawning Node Interpreter
logsource:
  category: process_creation
  product: linux
tags:
  - attack.t1059.007
detection:
  selection_parent:
    ParentImage|endswith:
      - /nginx
      - /httpd
  selection_child:
    Image|endswith:
      - /node
  condition: selection_parent and selection_child
"""
    selection = select_approved_rule(
        [{"rule_yaml": rule_yaml, "techniques": ["T1059.007"]}],
        ["T1059.007"],
        ["T1059.007"],
    )
    assert selection is not None
    proc, matched_yaml = selection
    assert proc.technique_id == "T1059.007"
    assert matched_yaml == rule_yaml


def test_network_connection_rule_matches_t1105():
    """T1105 exercises network_connection rules checking curl and DestinationPort 8888."""
    rule_yaml = """
title: Ingress Tool Transfer Network Connection
logsource:
  category: network_connection
  product: linux
tags:
  - attack.t1105
detection:
  selection_net:
    DestinationPort: 8888
    Initiated: true
  selection_proc:
    Image|endswith:
      - /curl
  condition: selection_net and selection_proc
"""
    selection = select_approved_rule(
        [{"rule_yaml": rule_yaml, "techniques": ["T1105"]}],
        ["T1105"],
        ["T1105"],
    )
    assert selection is not None
    proc, _ = selection
    assert proc.technique_id == "T1105"


def test_network_connection_rule_matches_t1046():
    """T1046 exercises network_connection rules checking nc and DestinationPort 22."""
    rule_yaml = """
title: Port Discovery via Netcat
logsource:
  category: network_connection
  product: linux
tags:
  - attack.t1046
detection:
  selection:
    DestinationPort: 22
    Image|endswith:
      - /nc
  condition: selection
"""
    selection = select_approved_rule(
        [{"rule_yaml": rule_yaml, "techniques": ["T1046"]}],
        ["T1046"],
        ["T1046"],
    )
    assert selection is not None
    proc, _ = selection
    assert proc.technique_id == "T1046"


def test_network_connection_rule_matches_t1190_with_loopback_filter():
    """T1190 exercises web outbound connection rules that exclude loopback destinations."""
    rule_yaml = """
title: Web Server Outbound Connection
logsource:
  category: network_connection
  product: linux
tags:
  - attack.t1190
detection:
  selection:
    Image|endswith:
      - /httpd
      - /apache2
    Initiated: true
  filter:
    DestinationIp|cidr:
      - 127.0.0.0/8
      - ::1/128
  condition: selection and not filter
"""
    selection = select_approved_rule(
        [{"rule_yaml": rule_yaml, "techniques": ["T1190"]}],
        ["T1190"],
        ["T1190"],
    )
    assert selection is not None
    proc, _ = selection
    assert proc.technique_id == "T1190"
    assert proc.fidelity_scope == "smoke_check"


def test_network_rule_unrelated_port_or_process_does_not_match():
    """Honesty check: rules requiring completely unrelated ports or processes are rejected."""
    rule_unrelated_port = """
title: Outbound Connection to Unrelated Port
logsource:
  category: network_connection
  product: linux
tags:
  - attack.t1105
detection:
  selection:
    DestinationPort: 65534
    Image|endswith: /curl
  condition: selection
"""
    assert (
        select_approved_rule(
            [{"rule_yaml": rule_unrelated_port, "techniques": ["T1105"]}],
            ["T1105"],
            ["T1105"],
        )
        is None
    )

    reason = explain_approved_selection(
        [{"rule_yaml": rule_unrelated_port, "techniques": ["T1105"]}],
        ["T1105"],
        ["T1105"],
    )
    assert "none exercise the drafted Linux rule predicates" in reason


def test_parse_net_trace_sets_initiated_true():
    """parse_net_trace must mark all outbound connect events with Initiated: True."""
    trace = (
        '10 100.100 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.1")}, 16) = 0\n'
        '11 100.200 connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("198.51.100.2")}, 16) <unfinished ...>\n'
        "11 100.300 <... connect resumed> ) = 0\n"
    )
    events = parse_net_trace(trace, start=99.0, end=101.0, host="lab-host")
    assert len(events) == 2
    for ev in events:
        assert ev["Initiated"] is True
        assert ev["category"] == "network_connection"
        assert ev["Protocol"] == "tcp"
