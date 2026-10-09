"""Policy-enforcing secrets service for the CyberCon identity demo.

This module is the SECURITY BOUNDARY. In secured mode, every secret access
goes through `request_secret`, which consults the access policy and writes an
audit entry BEFORE returning any value. Enforcement lives here, in code — the
LLM is never trusted to self-restrict.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Resolve demo paths relative to this file so the agent can run from anywhere.
ROOT = Path(__file__).resolve().parent
ENV_DIR = ROOT / "acme-financial"
SECRETS_FILE = ENV_DIR / "secrets" / "credentials.json"
POLICY_FILE = ENV_DIR / "policies" / "agent_access_policy.json"
AUDIT_LOG = ENV_DIR / "logs" / "agent_activity.log"

# Runtime access state (revocations + JIT grant times). Kept in a file so the
# web server, which handles each request independently, and the CLI share it.
STATE_FILE = ENV_DIR / "logs" / "access_state.json"

logger = logging.getLogger("acme.secrets")


def _load_state() -> dict:
    """Return runtime access state, with sane empty defaults."""

    if not STATE_FILE.exists():
        return {"revoked": [], "jit_grants": {}}

    data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    data.setdefault("revoked", [])
    data.setdefault("jit_grants", {})
    return data


def _save_state(state: dict) -> None:
    """Persist runtime access state."""

    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _epoch() -> float:
    """Current UNIX time (used for JIT token age checks)."""

    return datetime.now(timezone.utc).timestamp()


@dataclass
class AccessDecision:
    """Outcome of a single secret access request."""

    secret_id: str
    allowed: bool
    reason: str
    value: dict | None = None


def _now() -> str:
    # ISO-8601 UTC timestamp for every audit record.
    return datetime.now(timezone.utc).isoformat()


def _write_audit(mode: str, record: dict) -> None:
    """Append one structured JSON line to the audit log."""

    # Stamp every record with mode + time so the trail is self-describing.
    entry = {"timestamp": _now(), "mode": mode, **record}

    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def _load_json(path: Path) -> dict:
    """Load a JSON file, logging a clear error if it is missing/invalid."""

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.error("required file not found: %s", path)
        raise
    except json.JSONDecodeError as exc:
        logger.error("invalid JSON in %s: %s", path, exc)
        raise


def _load_all_secrets() -> dict:
    """Return the raw secrets map (minus the warning marker)."""

    data = _load_json(SECRETS_FILE)
    return {k: v for k, v in data.items() if not k.startswith("_")}


def request_secret_unrestricted(secret_id: str) -> AccessDecision:
    """Unrestricted mode: no policy, no gate. Always returns the secret.

    This models an over-privileged agent with standing access to the store.
    The access is still audited so the demo can show WHAT was reached.
    """

    secrets = _load_all_secrets()
    value = secrets.get(secret_id)

    # Even without a gate we record the access, to contrast the two trails.
    if value is None:
        _write_audit(
            "unrestricted",
            {"event": "secret_access", "secret_id": secret_id, "result": "not_found"},
        )
        return AccessDecision(secret_id, False, "secret not found", None)

    _write_audit(
        "unrestricted",
        {
            "event": "secret_access",
            "secret_id": secret_id,
            "result": "granted_no_policy",
        },
    )
    return AccessDecision(
        secret_id, True, "no policy enforced (standing access)", value
    )


def _deny(secret_id: str, reason: str) -> AccessDecision:
    """Audit and return a denial — one place so every deny is logged."""

    _write_audit(
        "secured",
        {
            "event": "access_decision",
            "secret_id": secret_id,
            "decision": "deny",
            "reason": reason,
        },
    )
    return AccessDecision(secret_id, False, reason, None)


def request_secret_secured(secret_id: str) -> AccessDecision:
    """Secured mode: deny-by-default, least-privilege, revocation, JIT, audit.

    Decision order (first match wins): revocation → approval → allow-list →
    JIT expiry → grant. Every outcome is written to the audit trail.
    """

    policy = _load_json(POLICY_FILE)
    secrets = _load_all_secrets()
    state = _load_state()

    allowed = {item["secret_id"] for item in policy.get("allowed_secrets", [])}
    needs_approval = set(policy.get("sensitive_requires_approval", []))

    # Revocation wins over everything: a revoked secret is denied even if the
    # policy still allow-lists it. This is the live "revoke access" control.
    if secret_id in state["revoked"]:
        return _deny(secret_id, "denied: access has been revoked for this agent")

    # Sensitive secrets require explicit human approval (denied unattended).
    if secret_id in needs_approval:
        return _deny(secret_id, "denied: sensitive secret requires human approval")

    # Deny-by-default: anything not explicitly allowed is refused.
    if secret_id not in allowed:
        return _deny(
            secret_id, "denied: not in least-privilege allow-list (deny-by-default)"
        )

    value = secrets.get(secret_id)
    if value is None:
        return _deny(secret_id, "denied: allow-listed but secret missing from store")

    # JIT: a prior grant is only valid for ttl_seconds. A request after the
    # token's lifetime is denied until a fresh grant is issued.
    jit = policy.get("just_in_time", {})
    ttl = jit.get("ttl_seconds", 300)
    granted_at = state["jit_grants"].get(secret_id)
    if jit.get("enabled") and granted_at is not None and (_epoch() - granted_at) > ttl:
        # Expire the stale token so the next grant starts a fresh window.
        state["jit_grants"].pop(secret_id, None)
        _save_state(state)
        age = int(_epoch() - granted_at)
        return _deny(secret_id, f"denied: JIT token expired ({age}s old, ttl={ttl}s)")

    # Grant: record (or refresh) the JIT grant time and return the secret.
    state["jit_grants"][secret_id] = _epoch()
    _save_state(state)
    reason = f"granted: in allow-list; just-in-time ttl={ttl}s"
    _write_audit(
        "secured",
        {
            "event": "access_decision",
            "secret_id": secret_id,
            "decision": "allow",
            "reason": reason,
        },
    )
    return AccessDecision(secret_id, True, reason, value)


def revoke_access(secret_id: str) -> None:
    """Revoke an agent's access to a secret (live Govern control)."""

    state = _load_state()
    if secret_id not in state["revoked"]:
        state["revoked"].append(secret_id)
    # A revoked secret's JIT token is meaningless — drop it.
    state["jit_grants"].pop(secret_id, None)
    _save_state(state)
    _write_audit(
        "secured",
        {
            "event": "access_revoked",
            "secret_id": secret_id,
            "decision": "revoke",
            "reason": "access revoked by owner",
        },
    )


def reset_access_state() -> None:
    """Clear revocations and JIT grants so a demo starts from a clean slate."""

    _save_state({"revoked": [], "jit_grants": {}})


def clear_jit_grants() -> None:
    """Drop JIT grant timers (keep revocations) so a run's timing restarts."""

    state = _load_state()
    state["jit_grants"] = {}
    _save_state(state)


def access_state_summary() -> dict:
    """Expose current revocations + JIT token ages for the UI."""

    state = _load_state()
    policy = _load_json(POLICY_FILE)
    ttl = policy.get("just_in_time", {}).get("ttl_seconds", 300)

    # Report each live JIT token's remaining seconds for a countdown display.
    now = _epoch()
    tokens = {
        sid: max(0, int(ttl - (now - granted)))
        for sid, granted in state["jit_grants"].items()
    }
    return {"revoked": state["revoked"], "ttl_seconds": ttl, "jit_remaining": tokens}


def read_audit_log() -> list[dict]:
    """Return the audit trail as a list of records (newest last)."""

    # Missing log simply means no runs yet — return an empty trail.
    if not AUDIT_LOG.exists():
        return []

    records = []
    for line in AUDIT_LOG.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))

    return records


def clear_audit_log() -> None:
    """Truncate the audit log so a demo run starts from a clean trail."""

    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    AUDIT_LOG.write_text("", encoding="utf-8")
