"""
Kill Signals — Centralized pattern-level false positive rejection.

Each vulnerability class has known mitigations. If the mitigation is present
in the source code, the finding is a false positive and should be killed or
heavily penalized before reaching the jury.

This module is called by:
1. AttackHypothesisWorker (post-LLM, pre-output)
2. Gate evaluator (as additional evidence)
3. Jury context builder (as mandatory context)

Kill signals are DETERMINISTIC — no LLM needed. They grep for specific
patterns in source code and return a verdict.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class KillSignalResult:
    """Result of a kill signal check."""
    triggered: bool           # True = mitigation exists, finding is likely FP
    signal_name: str          # e.g. "VIRTUAL_SHARES", "NONREENTRANT"
    evidence: str             # The specific code pattern found
    confidence_cap: int       # Max confidence if this signal fires (0-30)
    explanation: str           # Why this kills the finding


def check_kill_signals(
    vulnerability_class: str,
    source_code: str,
    function_name: str = "",
) -> list[KillSignalResult]:
    """
    Check all applicable kill signals for a given vulnerability class.

    Returns a list of triggered kill signals (empty if none fired).
    """
    results = []
    vuln = vulnerability_class.lower().replace(" ", "_").replace("-", "_")
    code = source_code or ""

    # ── Reentrancy / CEI Violation ──────────────────────────────
    if vuln in ("reentrancy", "cei_violation", "cross_contract_reentrancy"):
        # Check for nonReentrant modifier
        if re.search(r'\bnonReentrant\b', code):
            results.append(KillSignalResult(
                triggered=True,
                signal_name="NONREENTRANT",
                evidence="nonReentrant modifier found",
                confidence_cap=20,
                explanation=(
                    "Function or contract uses ReentrancyGuard (nonReentrant modifier). "
                    "This blocks standard reentrancy attacks. Check if ALL cross-callable "
                    "functions also have this guard before fully dismissing."
                ),
            ))

        # Check for ReentrancyGuard import/inheritance
        if re.search(r'ReentrancyGuard', code):
            results.append(KillSignalResult(
                triggered=True,
                signal_name="REENTRANCY_GUARD_INHERITED",
                evidence="ReentrancyGuard contract inherited",
                confidence_cap=25,
                explanation=(
                    "Contract inherits ReentrancyGuard. Verify the modifier is applied "
                    "to the specific vulnerable function."
                ),
            ))

    # ── First Depositor / Share Inflation ────────────────────────
    if vuln in ("inflation_attack", "first_depositor", "invariant_violation",
                "accounting_mismatch", "flash_loan_amplification"):
        # Virtual shares / offset pattern
        virtual_patterns = [
            r'VIRTUAL_AMOUNT',
            r'_decimalsOffset\s*\(',
            r'VIRTUAL_SHARES',
            r'OFFSET\s*=\s*1e',
            r'virtualAssets',
            r'virtualShares',
            r'_VIRTUAL_',
            r'1e6\s*\+',   # Common pattern: assets + 1e6
        ]
        for pattern in virtual_patterns:
            match = re.search(pattern, code)
            if match:
                results.append(KillSignalResult(
                    triggered=True,
                    signal_name="VIRTUAL_SHARES",
                    evidence=f"Pattern '{match.group()}' found — virtual share offset exists",
                    confidence_cap=20,
                    explanation=(
                        "Vault uses virtual shares/offset to prevent first-depositor inflation. "
                        "This is the standard mitigation (ERC4626 virtual offset). "
                        "First depositor attacks are NOT exploitable with this pattern."
                    ),
                ))
                break  # One match is enough

    # ── Oracle Manipulation ──────────────────────────────────────
    if vuln in ("oracle_manipulation", "flash_loan_amplification",
                "flash_loan_manipulation", "sandwich_attack"):
        # TWAP oracle check
        twap_patterns = [
            r'\bTWAP\b',
            r'twapPrice',
            r'observe\s*\(',
            r'consult\s*\(',
            r'getTimeWeightedAverage',
            r'OracleLibrary\.consult',
        ]
        for pattern in twap_patterns:
            match = re.search(pattern, code)
            if match:
                results.append(KillSignalResult(
                    triggered=True,
                    signal_name="TWAP_ORACLE",
                    evidence=f"TWAP pattern '{match.group()}' found",
                    confidence_cap=30,
                    explanation=(
                        "Protocol uses TWAP oracle instead of spot price. "
                        "Single-block manipulation is significantly harder with TWAP. "
                        "Check the TWAP window length — ≥30 minutes is considered safe."
                    ),
                ))
                break

        # Staleness check
        if re.search(r'updatedAt|staleness|heartbeat|sequencerUptime', code, re.IGNORECASE):
            results.append(KillSignalResult(
                triggered=True,
                signal_name="ORACLE_STALENESS_CHECK",
                evidence="Oracle staleness/heartbeat check found",
                confidence_cap=30,
                explanation=(
                    "Protocol checks oracle staleness (updatedAt/heartbeat). "
                    "Stale oracle exploitation is mitigated."
                ),
            ))

    # ── Fee-on-Transfer ──────────────────────────────────────────
    if vuln in ("fee_on_transfer", "fee_accounting", "accounting_desync"):
        # Balance before/after pattern
        balance_check = re.search(
            r'balanceOf\s*\(.*\)\s*[-−]\s*\w*[Bb]efore|'
            r'[Bb]efore\s*=\s*\w+\.balanceOf|'
            r'[Aa]fter\s*[-−]\s*[Bb]efore',
            code,
        )
        if balance_check:
            results.append(KillSignalResult(
                triggered=True,
                signal_name="BALANCE_DELTA_PATTERN",
                evidence=f"Balance before/after pattern: '{balance_check.group()}'",
                confidence_cap=20,
                explanation=(
                    "Code measures actual balance change (after - before) instead of "
                    "trusting the input amount. Fee-on-transfer accounting is handled."
                ),
            ))

    # ── Signature Replay ─────────────────────────────────────────
    if vuln in ("signature_replay", "permit_replay", "replay_attack"):
        checks_found = 0
        if re.search(r'\bnonce[s]?\b', code, re.IGNORECASE):
            checks_found += 1
        if re.search(r'chainId|block\.chainid|CHAIN_ID', code):
            checks_found += 1
        if re.search(r'usedSignatures|usedNonces|_useNonce', code, re.IGNORECASE):
            checks_found += 1

        if checks_found >= 2:
            results.append(KillSignalResult(
                triggered=True,
                signal_name="REPLAY_PROTECTION",
                evidence=f"Found {checks_found}/3 replay protection checks (nonce, chainId, mark-used)",
                confidence_cap=20,
                explanation=(
                    "Signature includes nonce and chainId, and used signatures are tracked. "
                    "Standard replay protection is in place."
                ),
            ))

    # ── Access Control (for unprotected_mutator findings) ────────
    if vuln in ("unprotected_mutator", "privilege_escalation", "guard_inconsistency"):
        if function_name:
            # Check if the specific function has an access control modifier
            func_pattern = rf'function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\b(onlyOwner|onlyAdmin|onlyRole|requiresAuth|auth|onlyGovernance|whenNotPaused)\b'
            match = re.search(func_pattern, code)
            if match:
                results.append(KillSignalResult(
                    triggered=True,
                    signal_name="ACCESS_CONTROL_MODIFIER",
                    evidence=f"Function {function_name} has modifier: {match.group(1)}",
                    confidence_cap=15,
                    explanation=(
                        f"Function {function_name} is protected by {match.group(1)} modifier. "
                        f"Unprotected mutator finding is a false positive."
                    ),
                ))

    # ── Initializer Replay ───────────────────────────────────────
    if vuln in ("initializer_replay", "proxy_abuse"):
        if re.search(r'_disableInitializers\s*\(\)', code):
            results.append(KillSignalResult(
                triggered=True,
                signal_name="INITIALIZERS_DISABLED",
                evidence="_disableInitializers() found in constructor",
                confidence_cap=15,
                explanation=(
                    "Implementation contract calls _disableInitializers() in constructor. "
                    "Direct initialization of implementation contract is blocked."
                ),
            ))

    return results


def apply_kill_signals_to_confidence(
    confidence: int,
    kill_results: list[KillSignalResult],
) -> tuple[int, str]:
    """
    Apply kill signal results to cap confidence.

    Returns (new_confidence, explanation_string).
    """
    if not kill_results:
        return confidence, ""

    # Use the lowest confidence cap among all triggered signals
    lowest_cap = min(kr.confidence_cap for kr in kill_results)
    signal_names = ", ".join(kr.signal_name for kr in kill_results)

    if confidence > lowest_cap:
        explanation = (
            f"Kill signal(s) [{signal_names}] triggered — confidence capped "
            f"from {confidence} to {lowest_cap}. "
            + " | ".join(kr.explanation for kr in kill_results)
        )
        return lowest_cap, explanation

    return confidence, f"Kill signal(s) [{signal_names}] checked but confidence already ≤ cap."
