"""Gatekeeper - Shared Authentication Service."""

from gatekeeper.client import GatekeeperClient

__all__ = ["GatekeeperClient", "create_app"]


def create_app(*args, **kwargs):
    """Application factory for Gatekeeper (lazy import to avoid server deps)."""
    from gatekeeper.app import create_app as _create_app

    return _create_app(*args, **kwargs)
