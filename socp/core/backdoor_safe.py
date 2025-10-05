# socp/core/backdoor_safe.py
"""
Safe, explicit backdoor enablement helper for lab-only simulations.

Enabling the lab simulation requires:
  - environment variable SOCP_ALLOW_BACKDOOR=1
  - a token file at SOCP_BACKDOOR_TOKEN_PATH (default: /tmp/socp_backdoor_token)

This module writes an audit line when backdoor mode is observed.
"""

from __future__ import annotations
import os
import time
import getpass
import logging
from typing import Optional

log = logging.getLogger("socp.backdoor_safe")

DEFAULT_TOKEN_PATH = os.getenv("SOCP_BACKDOOR_TOKEN_PATH", "/tmp/socp_backdoor_token")
AUDIT_LOG = os.getenv("SOCP_BACKDOOR_AUDIT", "/tmp/socp_backdoor_audit.log")

def _env_present() -> bool:
    return os.getenv("SOCP_ALLOW_BACKDOOR", "0") == "1"

def _token_present(token_path: Optional[str] = None) -> bool:
    p = token_path or DEFAULT_TOKEN_PATH
    return os.path.exists(p)

def backdoor_enabled(token_path: Optional[str] = None) -> bool:
    """
    Returns True only when both the env var SOCP_ALLOW_BACKDOOR=1 and the token file exist.
    If enabled, append an audit entry to AUDIT_LOG.
    """
    enabled = _env_present() and _token_present(token_path)
    if enabled:
        try:
            with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
                fh.write(f"{int(time.time())}\tENABLED\tuser={getpass.getuser()}\n")
        except Exception:
            # Do not raise if audit log can't be written
            pass
    return enabled

def require_backdoor_or_raise(token_path: Optional[str] = None) -> None:
    """
    Helper for PoC scripts: raises a RuntimeError if the lab backdoor is not enabled.
    """
    if not backdoor_enabled(token_path):
        raise RuntimeError(
            "Lab backdoor not enabled. To enable, set SOCP_ALLOW_BACKDOOR=1 and create the token file."
        )

def audit_note(note: str) -> None:
    """
    Append a free-form note to the audit log.
    """
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{int(time.time())}\tNOTE\t{note}\n")
    except Exception:
        pass
