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

    For monorepos like movement:
        base          = /tmp/.../movement
        foundry.toml  = /tmp/.../movement/protocol-units/settlement/mcr/contracts/foundry.toml
        returns       = /tmp/.../movement/protocol-units/settlement/mcr/contracts

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

    # Deep search: walk up to 6 levels for monorepos with nested Solidity projects.
    # Prefer the foundry.toml closest to a `src/` directory containing .sol files.
    _skip = {"lib", "node_modules", "out", "cache", ".git", "broadcast"}
    best: Path | None = None
    best_depth = 999
    try:
        for toml in base.rglob("foundry.toml"):
            if any(part in _skip for part in toml.parts):
                continue
            depth = len(toml.relative_to(base).parts)
            if depth > 7:
                continue
            candidate_dir = toml.parent
            has_src = (candidate_dir / "src").is_dir() and any((candidate_dir / "src").rglob("*.sol"))
            effective_depth = depth - (1 if has_src else 0)
            if effective_depth < best_depth:
                best_depth = effective_depth
                best = candidate_dir
    except (PermissionError, OSError):
        pass

    if best:
        logger.info(f"Deep-resolved foundry root: {best} (depth={best_depth})")
        return best

    logger.debug(f"Could not find foundry.toml under {base}. Using base as-is.")
    return base
