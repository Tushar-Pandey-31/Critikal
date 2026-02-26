"""
Shared utility for resolving the Foundry project root directory.

BUG-009 fix: This logic was duplicated in lead_agent.py and test_writer_sandbox.py.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_foundry_root(base: Path) -> Path:
    """
    Walk from `base` to find the directory that actually contains foundry.toml.

    For repos like Ethernaut:
        base          = /tmp/.../ethernaut          (repo root)
        foundry.toml  = /tmp/.../ethernaut/contracts/foundry.toml
        returns       = /tmp/.../ethernaut/contracts  <- Foundry project root

    Falls back to `base` if no foundry.toml found anywhere under it.
    """
    if (base / "foundry.toml").exists():
        return base

    for name in ("contracts", "src", "protocol", "packages"):
        candidate = base / name
        if candidate.is_dir() and (candidate / "foundry.toml").exists():
            return candidate

    try:
        for child in sorted(base.iterdir()):
            if child.is_dir() and (child / "foundry.toml").exists():
                return child
    except PermissionError:
        pass

    logger.debug(f"Could not find foundry.toml under {base}. Using base as-is.")
    return base
