"""Tools exposed to the agent.

Each public function is a tool the LLM may call. File access is confined to the
demo environment directory. Secret access is routed through `secrets_service`,
which is where authorization is actually enforced in secured mode.
"""

from __future__ import annotations

import logging
from pathlib import Path

import secrets_service as svc

logger = logging.getLogger("acme.tools")

ENV_DIR = svc.ENV_DIR


def _safe_path(relative: str) -> Path:
    """Resolve a path and refuse anything outside the demo directory.

    This is a hard sandbox: it blocks `../` traversal regardless of mode, so
    the demo can never touch real files on the presenter's machine.
    """

    target = (ENV_DIR / relative).resolve()

    # Containment check: the resolved path must live under ENV_DIR.
    if ENV_DIR not in target.parents and target != ENV_DIR:
        raise ValueError(f"path escapes demo sandbox: {relative}")

    return target


def list_files(subdirectory: str = "") -> dict:
    """List files available in the demo environment.

    Args:
        subdirectory: optional path under the demo root to scope the listing.
    """

    base = _safe_path(subdirectory) if subdirectory else ENV_DIR

    # Walk the tree and return paths relative to the demo root.
    found = [
        str(p.relative_to(ENV_DIR)) for p in sorted(base.rglob("*")) if p.is_file()
    ]
    return {"files": found}


def read_config(relative_path: str) -> dict:
    """Read an application configuration or env file as text.

    Args:
        relative_path: path (relative to the demo root) of the file to read.
    """

    # Reject anything that escapes the sandbox, returning a clean tool error.
    try:
        target = _safe_path(relative_path)
    except ValueError as exc:
        return {"error": str(exc)}

    # Only allow reading the config/env files, not the raw secrets store.
    if "secrets/" in relative_path.replace("\\", "/"):
        return {
            "error": "use request_secret to access the secrets store, not read_config"
        }

    try:
        return {"path": relative_path, "content": target.read_text(encoding="utf-8")}
    except FileNotFoundError:
        return {"error": f"file not found: {relative_path}"}


def request_secret(secret_id: str, mode: str) -> dict:
    """Request a secret by id. Authorization depends on `mode`.

    Args:
        secret_id: identifier of the secret in the store (e.g. "finance_app_db").
        mode: "unrestricted" or "secured" — selects the enforcement path.
    """

    # Route to the matching enforcement path in the secrets service.
    if mode == "secured":
        decision = svc.request_secret_secured(secret_id)
    else:
        decision = svc.request_secret_unrestricted(secret_id)

    # Return a flat, LLM-friendly result. Denied requests carry no value.
    result = {
        "secret_id": decision.secret_id,
        "allowed": decision.allowed,
        "reason": decision.reason,
    }
    if decision.allowed and decision.value is not None:
        result["secret"] = decision.value

    return result
