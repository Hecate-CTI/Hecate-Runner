"""Tests for Slack authorization, role gates, path traversal rejection, and symlink protection."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from slack_bolt import App, BoltRequest, BoltResponse

from hecate_runner.config import Settings
from hecate_runner.lifecycle import find_hunt_path
from hecate_runner.slack_auth import SlackAction, SlackAuthorizer
from hecate_runner.slack_bot import (
    SlackBotService,
    deploy_queries_for_hunt,
    extract_tuning_instruction,
    park_hunt,
    promote_hunt,
    replay_hunt_purple_team,
    review_hunt,
    sync_queries_for_hunt,
    undeploy_queries_for_hunt,
)


class TestSlackAuthorizer:
    """Test unit logic of SlackAuthorizer."""

    def test_permissive_when_disabled(self):
        auth = SlackAuthorizer(enabled=False)
        decision = auth.authorize(
            SlackAction.DEPLOY,
            actor="U_ANYONE",
            team_id="T_ANY",
            channel_id="C_ANY",
            target="H-0001",
        )
        assert decision.allowed is True
        assert "disabled" in decision.reason.lower()
        assert len(auth.audit_log) == 1

    def test_deny_by_default_when_no_controls_configured(self):
        auth = SlackAuthorizer(enabled=True)
        decision = auth.authorize(
            SlackAction.READ,
            actor="U12345",
            team_id="T1",
            channel_id="C1",
        )
        assert decision.allowed is False
        assert "deny-by-default" in decision.reason.lower()

    def test_team_allowlist_enforcement(self):
        auth = SlackAuthorizer(
            enabled=True,
            allowed_teams=["T_CORP_SOC"],
            allowed_users=["U_ANALYST"],
        )
        # Correct team
        dec1 = auth.authorize(
            SlackAction.READ,
            actor="U_ANALYST",
            team_id="T_CORP_SOC",
        )
        assert dec1.allowed is True

        # Rogue team
        dec2 = auth.authorize(
            SlackAction.READ,
            actor="U_ANALYST",
            team_id="T_EXTERNAL",
        )
        assert dec2.allowed is False
        assert "not in allowed teams" in dec2.reason

    def test_channel_allowlist_enforcement(self):
        auth = SlackAuthorizer(
            enabled=True,
            allowed_channels=["C_WAR_ROOM", "#threat-hunting"],
            allowed_users=["U_ANALYST"],
        )
        # Channel ID match
        dec1 = auth.authorize(
            SlackAction.READ,
            actor="U_ANALYST",
            channel_id="C_WAR_ROOM",
        )
        assert dec1.allowed is True

        # Channel name match (with or without #)
        dec2 = auth.authorize(
            SlackAction.READ,
            actor="U_ANALYST",
            channel_id="C999",
            channel_name="threat-hunting",
        )
        assert dec2.allowed is True

        # Disallowed channel
        dec3 = auth.authorize(
            SlackAction.READ,
            actor="U_ANALYST",
            channel_id="C_RANDOM",
            channel_name="general",
        )
        assert dec3.allowed is False
        assert "not in allowed channels" in dec3.reason

    def test_user_and_role_differentiation(self):
        auth = SlackAuthorizer(
            enabled=True,
            allowed_users=["U_READER", "alice"],
            deploy_users=["U_DEPLOYER", "bob"],
        )

        # 1. Reader attempting READ -> Allowed
        d_read = auth.authorize(SlackAction.READ, actor="U_READER")
        assert d_read.allowed is True

        # 2. Reader attempting TUNE -> Allowed (in allowed_users)
        d_tune = auth.authorize(SlackAction.TUNE, actor="U_READER")
        assert d_tune.allowed is True

        # 3. Reader attempting DEPLOY -> Denied (deploy_users required)
        d_deploy = auth.authorize(SlackAction.DEPLOY, actor="U_READER")
        assert d_deploy.allowed is False
        assert "role: deploy_users required" in d_deploy.reason

        # 4. Reader attempting SWEEP -> Denied
        d_sweep = auth.authorize(SlackAction.SWEEP, actor="U_READER")
        assert d_sweep.allowed is False

        # 5. Deployer attempting DEPLOY -> Allowed
        d_dep_ok = auth.authorize(SlackAction.DEPLOY, actor="U_DEPLOYER")
        assert d_dep_ok.allowed is True

        # 6. Deployer attempting SWEEP -> Allowed
        d_sw_ok = auth.authorize(SlackAction.SWEEP, actor="bob")
        assert d_sw_ok.allowed is True

        # 7. Deployer attempting READ -> Allowed (deploy_users inherit general actions)
        d_dep_read = auth.authorize(SlackAction.READ, actor="U_DEPLOYER")
        assert d_dep_read.allowed is True

        # 8. Unlisted user -> Denied for any action
        d_unlisted = auth.authorize(SlackAction.READ, actor="U_STRANGER")
        assert d_unlisted.allowed is False
        assert "not in allowed users" in d_unlisted.reason

    def test_identity_extraction(self):
        # Slash command payload
        cmd_body = {
            "user_id": "U001",
            "user_name": "charlie",
            "team_id": "T001",
            "channel_id": "C001",
        }
        actor, name, team, ch = SlackAuthorizer.extract_identity(cmd_body)
        assert actor == "U001"
        assert name == "charlie"
        assert team == "T001"
        assert ch == "C001"

        # Block actions payload
        action_body = {
            "user": {"id": "U002", "name": "dana"},
            "team": {"id": "T002"},
            "channel": {"id": "C002"},
        }
        actor, name, team, ch = SlackAuthorizer.extract_identity(action_body)
        assert actor == "U002"
        assert name == "dana"
        assert team == "T002"
        assert ch == "C002"

        # Message event payload
        event = {"user": "U003", "channel": "C003"}
        actor, name, team, ch = SlackAuthorizer.extract_identity({"team_id": "T003"}, event=event)
        assert actor == "U003"
        assert ch == "C003"
        assert team == "T003"

    def test_audit_log_ring_buffer(self):
        auth = SlackAuthorizer(enabled=False, max_audit_records=5)
        for i in range(10):
            auth.authorize(SlackAction.READ, actor=f"U_{i}", target=f"H-{i:04d}")

        assert len(auth.audit_log) == 5
        assert auth.audit_log[-1].actor == "U_9"
        assert auth.audit_log[0].actor == "U_5"
        as_dict = auth.audit_log[-1].to_dict()
        assert as_dict["allowed"] is True
        assert as_dict["action"] == "read"


class TestTuningDirectiveExtraction:
    """Test filtering conversational chatter vs explicit tuning directives."""

    @pytest.mark.parametrize(
        "chatter",
        [
            "Looks great team!",
            "Can we review this tomorrow?",
            "Thanks for the update.",
            "What technique is this testing?",
            "Approved on my end.",
            "LGTM",
            "",
            "   ",
        ],
    )
    def test_conversational_chatter_ignored(self, chatter: str):
        assert extract_tuning_instruction(chatter) is None

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            (
                "tune: exclude svchost.exe with parent services.exe",
                "exclude svchost.exe with parent services.exe",
            ),
            (
                "tune H-0700 exclude svchost.exe with parent services.exe",
                "exclude svchost.exe with parent services.exe",
            ),
            (
                "exclude: Image == 'powershell.exe'",
                "exclude: Image == 'powershell.exe'",
            ),
            (
                "exclude svchost.exe",
                "exclude svchost.exe",
            ),
            (
                "filter: CommandLine contains '/debug'",
                "filter: CommandLine contains '/debug'",
            ),
            (
                "filter CommandLine contains '/test'",
                "filter CommandLine contains '/test'",
            ),
            (
                "suppress: CommandLine == 'whoami.exe'",
                "suppress: CommandLine == 'whoami.exe'",
            ),
            (
                "whitelist: ParentImage == 'system'",
                "whitelist: ParentImage == 'system'",
            ),
            (
                "allowlist: Image == 'calc.exe'",
                "allowlist: Image == 'calc.exe'",
            ),
            (
                "add: Image pwsh.exe",
                "add: Image pwsh.exe",
            ),
            (
                "<@U12345> tune: exclude svchost.exe",
                "exclude svchost.exe",
            ),
            (
                "@hecate exclude svchost.exe",
                "exclude svchost.exe",
            ),
            (
                "<@U12345> tune H-0123 exclude svchost.exe",
                "exclude svchost.exe",
            ),
        ],
    )
    def test_explicit_tuning_directives_extracted(self, text: str, expected: str):
        result = extract_tuning_instruction(text)
        assert result == expected


class TestPathTraversalAndSymlinkHardening:
    """Test safety gates on hunt IDs and refusal of symlinks."""

    @pytest.mark.parametrize(
        "invalid_id",
        [
            "../../etc/passwd",
            "../queries/H-0100",
            "/absolute/path/H-0100",
            "H-0100/sub",
            "H-0100\\sub",
            "H-0100\x00extra",
            "NOT_A_HUNT",
            "",
            "   ",
        ],
    )
    def test_invalid_hunt_id_rejection_in_deploy_functions(self, tmp_path: Path, invalid_id: str):
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with pytest.raises(ValueError):
            deploy_queries_for_hunt(workspace, invalid_id)
        with pytest.raises(ValueError):
            undeploy_queries_for_hunt(workspace, invalid_id)
        with pytest.raises(ValueError):
            sync_queries_for_hunt(workspace, invalid_id)

        res_park = park_hunt(workspace, invalid_id)
        assert res_park["ok"] is False
        assert "Invalid hunt ID" in res_park["error"]

        res_prom = promote_hunt(workspace, invalid_id)
        assert res_prom["ok"] is False
        assert "Invalid hunt ID" in res_prom["error"]

        res_rev = review_hunt(workspace, invalid_id, approve=True, reviewer="alice")
        assert res_rev["ok"] is False
        assert "Invalid hunt ID" in res_rev["error"]

        res_purp = replay_hunt_purple_team(workspace, invalid_id)
        assert res_purp["ok"] is False
        assert "Invalid hunt ID" in res_purp["error"]

    def test_find_hunt_path_traversal_safe(self, tmp_path: Path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        hunts_dir = workspace / "hunts" / "2026"
        hunts_dir.mkdir(parents=True)
        (hunts_dir / "H-0100.md").write_text("---\nhunt_id: H-0100\n---", encoding="utf-8")

        # Valid hunt ID located
        assert find_hunt_path(workspace, "H-0100") is not None

        # Invalid hunt ID safely raises ValueError
        with pytest.raises(ValueError):
            find_hunt_path(workspace, "../../etc/passwd")
        with pytest.raises(ValueError):
            find_hunt_path(workspace, "INVALID")

    def test_symlink_query_file_refusal(self, tmp_path: Path):
        workspace = tmp_path / "workspace"
        query_dir = workspace / "queries" / "H-0150"
        query_dir.mkdir(parents=True)

        # Real query file
        real_file = query_dir / "real.kql"
        real_file.write_text("DeviceProcessEvents | where FileName == 'test.exe'", encoding="utf-8")

        # Secret file outside workspace
        secret_file = tmp_path / "secret.kql"
        secret_file.write_text("SECRET DATA", encoding="utf-8")

        # Symlink inside query_dir pointing outside
        symlink_file = query_dir / "symlink.kql"
        symlink_file.symlink_to(secret_file)

        with pytest.raises(ValueError, match="Refusing symlinked query file"):
            deploy_queries_for_hunt(workspace, "H-0150", dry_run=True)

        with pytest.raises(ValueError, match="Refusing symlinked query file"):
            sync_queries_for_hunt(workspace, "H-0150", dry_run=True)

        with pytest.raises(ValueError, match="Refusing symlinked query file"):
            undeploy_queries_for_hunt(workspace, "H-0150", dry_run=True)

    def test_symlink_query_directory_refusal(self, tmp_path: Path):
        workspace = tmp_path / "workspace"
        queries_root = workspace / "queries"
        queries_root.mkdir(parents=True)

        target_dir = tmp_path / "target_h0151"
        target_dir.mkdir()
        (target_dir / "test.kql").write_text("DeviceEvents", encoding="utf-8")

        # Symlink query directory
        symlink_dir = queries_root / "H-0151"
        symlink_dir.symlink_to(target_dir)

        # Must refuse symlink directory
        with pytest.raises(ValueError):
            deploy_queries_for_hunt(workspace, "H-0151", dry_run=True)
        with pytest.raises(ValueError):
            sync_queries_for_hunt(workspace, "H-0151", dry_run=True)
        with pytest.raises(ValueError):
            undeploy_queries_for_hunt(workspace, "H-0151", dry_run=True)


class TestSlackBotServiceAuthorizationIntegration:
    """Test full integration of SlackBotService handlers with authorization."""

    def _setup_service(self, workspace: Path, **auth_kwargs):
        mock_app = App(token="xoxb-fake", signing_secret="fake", token_verification_enabled=False)
        settings = Settings(
            hecate_workspace=workspace,
            slack_bot_token="xoxb-fake",
            slack_app_token="xapp-fake",
            slack_interactive_enabled=True,
            slack_auth_enabled=True,
            **auth_kwargs,
        )
        service = SlackBotService(settings=settings, app=mock_app)
        return service, mock_app

    def test_slash_command_unauthorized_denied(self, tmp_path: Path):
        _service, app = self._setup_service(
            tmp_path,
            slack_allowed_users=["U_AUTHORIZED"],
        )

        respond_mock = MagicMock()
        body = {
            "text": "status",
            "user_id": "U_STRANGER",
            "user_name": "stranger",
            "channel_id": "C1",
        }

        # Find command listener
        req = BoltRequest(
            body={"command": "/hecate", "text": "status", "user_id": "U_STRANGER"},
            mode="socket_mode",
        )
        resp = BoltResponse(status=200)
        listener = next(item for item in app._listeners if item.matches(req=req, resp=resp))

        listener.ack_function(ack=MagicMock(), body=body, respond=respond_mock)
        assert respond_mock.called
        call_text = respond_mock.call_args[1].get("text", "")
        assert "Access Denied" in call_text

    def test_slash_deploy_requires_deploy_role(self, tmp_path: Path):
        _service, app = self._setup_service(
            tmp_path,
            slack_allowed_users=["U_ANALYST"],
            slack_deploy_users=["U_LEAD"],
        )

        respond_mock = MagicMock()
        # Ordinary analyst attempting deploy -> Denied
        body_analyst = {
            "text": "deploy H-0100",
            "user_id": "U_ANALYST",
            "user_name": "analyst",
            "channel_id": "C1",
        }

        req = BoltRequest(
            body={"command": "/hecate", "text": "deploy H-0100", "user_id": "U_ANALYST"},
            mode="socket_mode",
        )
        resp = BoltResponse(status=200)
        listener = next(item for item in app._listeners if item.matches(req=req, resp=resp))

        listener.ack_function(ack=MagicMock(), body=body_analyst, respond=respond_mock)
        assert "Access Denied" in respond_mock.call_args[1].get("text", "")
        assert "deploy_users required" in respond_mock.call_args[1].get("text", "")

        # Lead attempting deploy -> Passed authorization check
        respond_mock.reset_mock()
        body_lead = {
            "text": "deploy H-0100",
            "user_id": "U_LEAD",
            "user_name": "lead",
            "channel_id": "C1",
        }
        listener.ack_function(ack=MagicMock(), body=body_lead, respond=respond_mock)
        # Since queries/H-0100 doesn't exist, it responds with "No queries found"
        # confirming it passed authorization gate!
        assert "No queries found" in respond_mock.call_args[1].get("text", "")

    def test_slash_command_invalid_hunt_id_rejected(self, tmp_path: Path):
        _service, app = self._setup_service(
            tmp_path,
            slack_allowed_users=["U_LEAD"],
            slack_deploy_users=["U_LEAD"],
        )

        respond_mock = MagicMock()
        body = {
            "text": "deploy ../../etc/passwd",
            "user_id": "U_LEAD",
            "user_name": "lead",
            "channel_id": "C1",
        }

        req = BoltRequest(
            body={"command": "/hecate", "text": "deploy ../../etc/passwd", "user_id": "U_LEAD"},
            mode="socket_mode",
        )
        resp = BoltResponse(status=200)
        listener = next(item for item in app._listeners if item.matches(req=req, resp=resp))

        listener.ack_function(ack=MagicMock(), body=body, respond=respond_mock)
        assert "Invalid hunt ID" in respond_mock.call_args[1].get("text", "")

    def test_interactive_action_authorization_gate(self, tmp_path: Path):
        _service, app = self._setup_service(
            tmp_path,
            slack_allowed_users=["U_ANALYST"],
            slack_deploy_users=["U_LEAD"],
        )

        req = BoltRequest(
            body={
                "type": "block_actions",
                "actions": [{"action_id": "hecate_deploy_queries", "value": "H-0100"}],
            },
            mode="socket_mode",
        )
        resp = BoltResponse(status=200)
        listener = next(item for item in app._listeners if item.matches(req=req, resp=resp))

        say_mock = MagicMock()
        # Unauthorized user clicks deploy button
        body_unauth = {
            "type": "block_actions",
            "actions": [{"value": "H-0100"}],
            "user": {"id": "U_ANALYST", "name": "analyst"},
            "channel": {"id": "C1"},
        }
        listener.ack_function(ack=MagicMock(), body=body_unauth, say=say_mock)
        assert say_mock.called
        assert "Access Denied" in say_mock.call_args[1].get("text", "")
        assert "deploy_users required" in say_mock.call_args[1].get("text", "")

    def test_thread_message_conversational_chatter_ignored(self, tmp_path: Path):
        _service, app = self._setup_service(
            tmp_path,
            slack_allowed_users=["U_ANALYST"],
        )

        # Thread message listener
        req = BoltRequest(
            body={
                "type": "event_callback",
                "event": {"type": "message", "text": "Looks great team!"},
            },
            mode="socket_mode",
        )
        resp = BoltResponse(status=200)
        listener = next(item for item in app._listeners if item.matches(req=req, resp=resp))

        say_mock = MagicMock()
        body = {
            "type": "event_callback",
            "event": {
                "type": "message",
                "text": "Looks great team!",
                "user": "U_ANALYST",
                "thread_ts": "123456.789",
                "channel": "C1",
            },
        }
        listener.ack_function(body=body, say=say_mock)
        # Should not say anything or attempt rule tune for chatter
        assert not say_mock.called

    def test_thread_message_tuning_unauthorized_user_denied(self, tmp_path: Path):
        _service, app = self._setup_service(
            tmp_path,
            slack_allowed_users=["U_AUTHORIZED"],
        )

        body = {
            "type": "event_callback",
            "event": {
                "type": "message",
                "text": "tune H-0100 exclude svchost.exe",
                "user": "U_UNAUTHORIZED",
                "thread_ts": "123456.789",
                "channel": "C1",
            },
        }

        req = BoltRequest(
            body={
                "type": "event_callback",
                "event": {"type": "message", "text": "tune H-0100 exclude svchost.exe"},
            },
            mode="socket_mode",
        )
        resp = BoltResponse(status=200)
        listener = next(item for item in app._listeners if item.matches(req=req, resp=resp))

        say_mock = MagicMock()
        listener.ack_function(body=body, say=say_mock)
        assert say_mock.called
        assert "Access Denied" in say_mock.call_args[1].get("text", "")
