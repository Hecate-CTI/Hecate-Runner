"""Slack authentication, authorization, and audit logging for Hecate.

Enforces deny-by-default role-based access control across:
- Slack action listeners (buttons, overflows)
- Slash commands (/hecate)
- Modal submissions
- Thread messages & app mentions
"""

from __future__ import annotations

import enum
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from hecate_runner.config import Settings

log = logging.getLogger(__name__)


class SlackAction(enum.StrEnum):
    """Categorized operations for Slack interaction authorization."""

    READ = "read"  # Status, help, pending review list, history, diff, audit
    TUNE = "tune"  # Tuning Sigma rules from findings or messages
    REVIEW = "review"  # Approving/rejecting hunts, parking/suppressing
    DEPLOY = "deploy"  # Live deploying, undeploying, syncing, or reconciling queries
    SWEEP = "sweep"  # Executing or cancelling automated hunt sweeps
    HUNT = "hunt"  # Initiating ad-hoc hunts, running purple team replay


@dataclass
class AuthorizationDecision:
    """Audit record and decision outcome for a Slack action request."""

    allowed: bool
    reason: str
    action: SlackAction
    actor: str
    target: str | None = None
    team_id: str | None = None
    channel_id: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "action": self.action.value,
            "actor": self.actor,
            "target": self.target,
            "team_id": self.team_id,
            "channel_id": self.channel_id,
            "timestamp": self.timestamp,
        }


class SlackAuthorizer:
    """Enforces team, channel, user, and role authorization for Slack bot events."""

    def __init__(
        self,
        enabled: bool = False,
        allowed_teams: list[str] | set[str] | None = None,
        allowed_channels: list[str] | set[str] | None = None,
        allowed_users: list[str] | set[str] | None = None,
        deploy_users: list[str] | set[str] | None = None,
        max_audit_records: int = 500,
    ) -> None:
        self.enabled = bool(enabled)
        self.allowed_teams: set[str] = {
            t.strip().upper() for t in (allowed_teams or []) if t.strip()
        }
        self.allowed_channels: set[str] = set()
        for c in allowed_channels or []:
            c_str = c.strip()
            if c_str:
                self.allowed_channels.add(c_str)
                if c_str.startswith("#"):
                    self.allowed_channels.add(c_str.lstrip("#"))
        self.allowed_users: set[str] = {
            u.strip().lstrip("@") for u in (allowed_users or []) if u.strip()
        }
        self.deploy_users: set[str] = {
            u.strip().lstrip("@") for u in (deploy_users or []) if u.strip()
        }
        self.audit_log: deque[AuthorizationDecision] = deque(maxlen=max_audit_records)

    @classmethod
    def from_settings(cls, settings: Settings) -> SlackAuthorizer:
        """Instantiate authorizer from runner configuration."""
        return cls(
            enabled=getattr(settings, "slack_auth_enabled", False),
            allowed_teams=getattr(settings, "slack_allowed_teams", []),
            allowed_channels=getattr(settings, "slack_allowed_channels", []),
            allowed_users=getattr(settings, "slack_allowed_users", []),
            deploy_users=getattr(settings, "slack_deploy_users", []),
        )

    @staticmethod
    def extract_identity(
        body: dict[str, Any], event: dict[str, Any] | None = None
    ) -> tuple[str, str | None, str | None, str | None]:
        """Extract (actor_id, actor_name, team_id, channel_id) from various Slack payloads."""
        actor_id = "unknown"
        actor_name: str | None = None
        team_id: str | None = None
        channel_id: str | None = None

        if event:
            actor_id = str(event.get("user") or "unknown")
            channel_id = event.get("channel")

        # Slash command payload
        if "user_id" in body:
            actor_id = str(body.get("user_id") or actor_id)
            actor_name = body.get("user_name")
            team_id = body.get("team_id")
            channel_id = body.get("channel_id") or channel_id
        # Block action / view submission payload
        elif "user" in body and isinstance(body["user"], dict):
            user_info = body["user"]
            actor_id = str(user_info.get("id") or actor_id)
            actor_name = user_info.get("username") or user_info.get("name")

        if not team_id:
            if isinstance(body.get("team"), dict):
                team_id = body["team"].get("id")
            elif isinstance(body.get("team"), str):
                team_id = body.get("team")
            elif body.get("team_id"):
                team_id = str(body["team_id"])

        if not channel_id:
            if isinstance(body.get("channel"), dict):
                channel_id = body["channel"].get("id")
            elif isinstance(body.get("channel"), str):
                channel_id = body.get("channel")
            elif isinstance(body.get("container"), dict):
                channel_id = body["container"].get("channel_id")

        return actor_id, actor_name, team_id, channel_id

    def authorize(
        self,
        action: SlackAction,
        actor: str,
        team_id: str | None = None,
        channel_id: str | None = None,
        channel_name: str | None = None,
        target: str | None = None,
        username: str | None = None,
    ) -> AuthorizationDecision:
        """Evaluate authorization for an actor attempting a specific Slack action."""
        if not self.enabled:
            decision = AuthorizationDecision(
                allowed=True,
                reason="Authorization disabled (permissive mode)",
                action=action,
                actor=actor,
                target=target,
                team_id=team_id,
                channel_id=channel_id,
            )
            self._record_decision(decision)
            return decision

        # 1. Deny-by-default if no access controls are configured
        if not (
            self.allowed_users or self.deploy_users or self.allowed_channels or self.allowed_teams
        ):
            decision = AuthorizationDecision(
                allowed=False,
                reason="Deny-by-default: no Slack access controls configured",
                action=action,
                actor=actor,
                target=target,
                team_id=team_id,
                channel_id=channel_id,
            )
            self._record_decision(decision)
            return decision

        # 2. Workspace/Team check
        if self.allowed_teams:
            norm_team = (team_id or "").strip().upper()
            if not norm_team or norm_team not in self.allowed_teams:
                decision = AuthorizationDecision(
                    allowed=False,
                    reason=f"Workspace/Team '{team_id or 'unknown'}' is not in allowed teams",
                    action=action,
                    actor=actor,
                    target=target,
                    team_id=team_id,
                    channel_id=channel_id,
                )
                self._record_decision(decision)
                return decision

        # 3. Channel check
        if self.allowed_channels and channel_id:
            cand_channels = {channel_id}
            if channel_name:
                cand_channels.add(channel_name)
                cand_channels.add(f"#{channel_name.lstrip('#')}")
                cand_channels.add(channel_name.lstrip("#"))
            if not cand_channels.intersection(self.allowed_channels):
                decision = AuthorizationDecision(
                    allowed=False,
                    reason=f"Channel '{channel_id}' is not in allowed channels",
                    action=action,
                    actor=actor,
                    target=target,
                    team_id=team_id,
                    channel_id=channel_id,
                )
                self._record_decision(decision)
                return decision

        # 4. User and Role check
        actor_ids = {a.strip().lstrip("@") for a in (actor, username) if a and str(a).strip()}

        # Deploy & Sweep actions require deploy role
        if action in (SlackAction.DEPLOY, SlackAction.SWEEP):
            if self.deploy_users:
                if not actor_ids.intersection(self.deploy_users):
                    decision = AuthorizationDecision(
                        allowed=False,
                        reason=f"User '{actor}' is not authorized for deployment or sweep execution (role: deploy_users required)",
                        action=action,
                        actor=actor,
                        target=target,
                        team_id=team_id,
                        channel_id=channel_id,
                    )
                    self._record_decision(decision)
                    return decision
            elif self.allowed_users:
                # Fall back to allowed_users if deploy_users is not specified
                if not actor_ids.intersection(self.allowed_users):
                    decision = AuthorizationDecision(
                        allowed=False,
                        reason=f"User '{actor}' is not in allowed users",
                        action=action,
                        actor=actor,
                        target=target,
                        team_id=team_id,
                        channel_id=channel_id,
                    )
                    self._record_decision(decision)
                    return decision
            else:
                decision = AuthorizationDecision(
                    allowed=False,
                    reason="No authorized deploy users configured",
                    action=action,
                    actor=actor,
                    target=target,
                    team_id=team_id,
                    channel_id=channel_id,
                )
                self._record_decision(decision)
                return decision

        # General actions (READ, TUNE, REVIEW, HUNT)
        else:
            all_permitted_users = self.allowed_users | self.deploy_users
            if all_permitted_users and not actor_ids.intersection(all_permitted_users):
                decision = AuthorizationDecision(
                    allowed=False,
                    reason=f"User '{actor}' is not in allowed users",
                    action=action,
                    actor=actor,
                    target=target,
                    team_id=team_id,
                    channel_id=channel_id,
                )
                self._record_decision(decision)
                return decision

        decision = AuthorizationDecision(
            allowed=True,
            reason=f"Authorized for {action.value}",
            action=action,
            actor=actor,
            target=target,
            team_id=team_id,
            channel_id=channel_id,
        )
        self._record_decision(decision)
        return decision

    def _record_decision(self, decision: AuthorizationDecision) -> None:
        """Record decision in audit ring buffer and emit structured log."""
        self.audit_log.append(decision)
        if decision.allowed:
            log.info(
                "Slack authorization ALLOWED: action=%s actor=%s target=%s team=%s channel=%s reason=%s",
                decision.action.value,
                decision.actor,
                decision.target or "none",
                decision.team_id or "none",
                decision.channel_id or "none",
                decision.reason,
            )
        else:
            log.warning(
                "Slack authorization DENIED: action=%s actor=%s target=%s team=%s channel=%s reason=%s",
                decision.action.value,
                decision.actor,
                decision.target or "none",
                decision.team_id or "none",
                decision.channel_id or "none",
                decision.reason,
            )
