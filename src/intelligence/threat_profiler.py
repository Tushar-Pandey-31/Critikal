"""
Protocol-Type Threat Profiler (P0.1)

Auto-classifies a codebase's protocol type(s) from function signatures,
state variable names, and structural patterns in the knowledge graph.

Returns ranked adversaries, critical invariants, temporal threat windows,
and agent routing decisions per hotspot.

Usage:
    profiler = ThreatProfiler()
    protocol_types = profiler.classify(graph)
    threat_profile = profiler.get_threat_profile(protocol_types[0])
    agents = profiler.get_agent_routing(protocol_types[0], hotspot_signals)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx
import yaml

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"
_PROFILES_PATH = _DATA_DIR / "threat_profiles.yaml"


# ════════════════════════════════════════════════════════════
#  Data Models
# ════════════════════════════════════════════════════════════


@dataclass
class Adversary:
    name: str
    capability: str
    priority: int = 0


@dataclass
class TemporalThreat:
    phase: str  # deployment | steady_state | market_stress | governance | deprecation
    threats: list[str] = field(default_factory=list)


@dataclass
class ThreatProfile:
    protocol_type: str
    adversaries: list[Adversary] = field(default_factory=list)
    invariants: list[str] = field(default_factory=list)
    temporal_threats: list[TemporalThreat] = field(default_factory=list)
    composability_risks: list[str] = field(default_factory=list)
    agent_routing: dict[str, list[str]] = field(default_factory=dict)

    def format_for_prompt(self) -> str:
        """Format threat profile as a compact string for LLM prompt injection."""
        lines = [
            f"═══ THREAT INTELLIGENCE: {self.protocol_type.upper()} PROTOCOL ═══",
            "",
            "ADVERSARIES (ranked by priority):",
        ]
        for adv in sorted(self.adversaries, key=lambda a: a.priority):
            lines.append(f"  {adv.priority}. {adv.name}: {adv.capability}")

        lines.append("")
        lines.append("CRITICAL INVARIANTS (violations = bugs):")
        for inv in self.invariants:
            lines.append(f"  • {inv}")

        lines.append("")
        lines.append("COMPOSABILITY RISKS:")
        for risk in self.composability_risks:
            lines.append(f"  • {risk}")

        if self.temporal_threats:
            lines.append("")
            lines.append("TEMPORAL THREATS:")
            for tt in self.temporal_threats:
                lines.append(f"  [{tt.phase}]")
                for t in tt.threats:
                    lines.append(f"    • {t}")

        return "\n".join(lines)


# ════════════════════════════════════════════════════════════
#  Detection Signals — code patterns that identify protocol types
# ════════════════════════════════════════════════════════════

# Each entry: protocol_type -> (function_sigs, state_var_names, patterns)
# A protocol type is detected when enough signals match.

DETECTION_SIGNALS: dict[str, dict[str, list[str]]] = {
    "lending": {
        "function_sigs": [
            "borrow",
            "repay",
            "liquidate",
            "liquidateCall",
            "flashLoan",
            "getAccountLiquidity",
            "getHypotheticalAccountLiquidity",
            "accrueInterest",
            "seize",
            "enterMarkets",
            "exitMarket",
        ],
        "state_vars": [
            "totalBorrows",
            "totalReserves",
            "borrowIndex",
            "borrowRate",
            "collateralFactor",
            "liquidationIncentive",
            "healthFactor",
            "accountBorrows",
            "supplyRate",
            "reserveFactor",
        ],
        "patterns": [
            "LTV",
            "healthFactor",
            "accountLiquidity",
        ],
    },
    "dex_amm": {
        "function_sigs": [
            "swap",
            "addLiquidity",
            "removeLiquidity",
            "mint",
            "burn",
            "getAmountOut",
            "getAmountIn",
            "getReserves",
            "skim",
            "sync",
        ],
        "state_vars": [
            "reserve0",
            "reserve1",
            "sqrtPriceX96",
            "liquidity",
            "feeGrowthGlobal",
            "tick",
            "tickSpacing",
            "fee",
            "kLast",
            "totalLiquidity",
        ],
        "patterns": [
            "MINIMUM_LIQUIDITY",
            "priceCumulativeLast",
            "observation",
        ],
    },
    "vault": {
        "function_sigs": [
            "deposit",
            "withdraw",
            "redeem",
            "convertToShares",
            "convertToAssets",
            "totalAssets",
            "previewDeposit",
            "previewMint",
            "previewRedeem",
            "previewWithdraw",
            "maxDeposit",
            "maxMint",
            "maxWithdraw",
            "maxRedeem",
        ],
        "state_vars": [
            "totalAssets",
            "totalShares",
            "asset",
            "sharePrice",
            "lastHarvestTimestamp",
            "performanceFee",
            "managementFee",
        ],
        "patterns": [
            "ERC4626",
            "_decimalsOffset",
            "totalSupply",
        ],
    },
    "stablecoin": {
        "function_sigs": [
            "mint",
            "burn",
            "peg",
            "rebase",
            "debase",
            "collateralize",
            "decollateralize",
        ],
        "state_vars": [
            "targetPrice",
            "pegPrice",
            "collateralRatio",
            "debtCeiling",
            "globalDebt",
            "stabilityFee",
        ],
        "patterns": [
            "CDPManager",
            "Vat",
            "stabilityPool",
        ],
    },
    "bridge": {
        "function_sigs": [
            "sendMessage",
            "receiveMessage",
            "relayMessage",
            "verifyProof",
            "finalizeDeposit",
            "finalizeWithdrawal",
            "processMessage",
            "retryMessage",
        ],
        "state_vars": [
            "nonce",
            "messageHash",
            "processedMessages",
            "relayer",
            "sequencer",
            "l1Bridge",
            "l2Bridge",
        ],
        "patterns": [
            "crossChain",
            "L1",
            "L2",
            "rollup",
        ],
    },
    "governance": {
        "function_sigs": [
            "propose",
            "castVote",
            "castVoteBySig",
            "queue",
            "execute",
            "cancel",
            "getVotes",
            "delegate",
        ],
        "state_vars": [
            "votingDelay",
            "votingPeriod",
            "proposalThreshold",
            "quorumNumerator",
            "timelock",
            "proposals",
        ],
        "patterns": [
            "GovernorBravo",
            "TimelockController",
            "proposal",
        ],
    },
    "perpetuals": {
        "function_sigs": [
            "openPosition",
            "closePosition",
            "increasePosition",
            "decreasePosition",
            "liquidatePosition",
            "settleFunding",
            "setPrice",
            "updateCumulativeFundingRate",
        ],
        "state_vars": [
            "fundingRate",
            "openInterest",
            "maxLeverage",
            "maintenanceMargin",
            "positionSize",
            "entryPrice",
        ],
        "patterns": [
            "perp",
            "funding",
            "margin",
            "leverage",
        ],
    },
    "liquid_staking": {
        "function_sigs": [
            "stake",
            "unstake",
            "requestWithdrawal",
            "claimWithdrawal",
            "rebase",
            "distributeRewards",
            "reportBeacon",
        ],
        "state_vars": [
            "totalPooledEther",
            "totalShares",
            "beaconBalance",
            "withdrawalQueue",
            "rewardsPerShare",
            "validatorCount",
        ],
        "patterns": [
            "stETH",
            "rETH",
            "beacon",
            "validator",
        ],
    },
}

# Minimum number of signals required to classify a protocol type
_MIN_SIGNAL_THRESHOLD = 3


# ════════════════════════════════════════════════════════════
#  ThreatProfiler
# ════════════════════════════════════════════════════════════


class ThreatProfiler:
    """
    Classifies a codebase's protocol type(s) from graph signals
    and loads bespoke threat intelligence.
    """

    def __init__(self, profiles_path: str | Path | None = None):
        self._profiles_path = Path(profiles_path) if profiles_path else _PROFILES_PATH
        self._profiles_data: dict[str, Any] = {}
        self._load_profiles()

    def _load_profiles(self) -> None:
        """Load threat profiles from YAML."""
        if not self._profiles_path.exists():
            logger.warning(f"Threat profiles not found at {self._profiles_path}")
            return
        try:
            with open(self._profiles_path) as f:
                self._profiles_data = yaml.safe_load(f) or {}
            logger.info(f"Loaded {len(self._profiles_data)} threat profiles")
        except Exception as e:
            logger.error(f"Failed to load threat profiles: {e}")

    def classify(self, graph: nx.DiGraph) -> list[dict[str, Any]]:
        """
        Detect protocol type(s) from knowledge graph signals.

        Returns a list of detected types sorted by confidence (highest first):
            [{"type": "vault", "confidence": 0.85, "matched_signals": 12}, ...]
        """
        if graph.number_of_nodes() == 0:
            return [{"type": "unknown", "confidence": 0.0, "matched_signals": 0}]

        # Collect all function names and state variable names from graph
        function_names: set[str] = set()
        state_var_names: set[str] = set()
        source_code_concat = ""

        for node_id, data in graph.nodes(data=True):
            node_type = data.get("type", "")
            if node_type == "function":
                fname = data.get("name", "")
                if fname:
                    function_names.add(fname)
                # Also collect source code for pattern matching
                src = data.get("source_code", "")
                if src:
                    source_code_concat += src + "\n"
            elif node_type == "state_variable":
                vname = data.get("name", "")
                if vname:
                    state_var_names.add(vname)

        # Score each protocol type against collected signals
        results: list[dict[str, Any]] = []

        for proto_type, signals in DETECTION_SIGNALS.items():
            matched = 0
            total = 0

            # Check function signature matches
            sig_matches = [
                s
                for s in signals.get("function_sigs", [])
                if s in function_names or any(s.lower() in fn.lower() for fn in function_names)
            ]
            matched += len(sig_matches)
            total += len(signals.get("function_sigs", []))

            # Check state variable matches
            var_matches = [
                s
                for s in signals.get("state_vars", [])
                if s in state_var_names or any(s.lower() in vn.lower() for vn in state_var_names)
            ]
            matched += len(var_matches)
            total += len(signals.get("state_vars", []))

            # Check code pattern matches
            pattern_matches = [p for p in signals.get("patterns", []) if p.lower() in source_code_concat.lower()]
            matched += len(pattern_matches)
            total += len(signals.get("patterns", []))

            if matched >= _MIN_SIGNAL_THRESHOLD and total > 0:
                confidence = min(1.0, matched / (total * 0.5))  # generous — 50% match = full confidence
                results.append(
                    {
                        "type": proto_type,
                        "confidence": round(confidence, 2),
                        "matched_signals": matched,
                        "total_signals": total,
                        "matched_functions": sig_matches,
                        "matched_vars": var_matches,
                        "matched_patterns": pattern_matches,
                    }
                )

        # Sort by confidence (highest first)
        results.sort(key=lambda r: (-r["confidence"], -r["matched_signals"]))

        if not results:
            results.append({"type": "unknown", "confidence": 0.0, "matched_signals": 0})

        logger.info(f"Protocol classification: {[r['type'] for r in results]}")
        return results

    def get_threat_profile(self, protocol_type: str) -> ThreatProfile:
        """
        Load the full threat profile for a protocol type.
        Returns a ThreatProfile with adversaries, invariants, temporal threats, etc.
        """
        raw = self._profiles_data.get(protocol_type, {})
        if not raw:
            logger.warning(f"No threat profile found for '{protocol_type}'")
            return ThreatProfile(protocol_type=protocol_type)

        # Parse adversaries
        adversaries = []
        for adv_dict in raw.get("adversaries", []):
            adversaries.append(
                Adversary(
                    name=adv_dict.get("name", "Unknown"),
                    capability=adv_dict.get("capability", ""),
                    priority=adv_dict.get("priority", 99),
                )
            )

        # Parse invariants
        invariants = raw.get("invariants", [])

        # Parse temporal threats
        temporal_threats = []
        for phase, threats in raw.get("temporal_threats", {}).items():
            temporal_threats.append(TemporalThreat(phase=phase, threats=threats))

        # Parse composability risks
        composability_risks = raw.get("composability_risks", [])

        # Parse agent routing rules
        agent_routing = raw.get("agent_routing", {})

        return ThreatProfile(
            protocol_type=protocol_type,
            adversaries=adversaries,
            invariants=invariants,
            temporal_threats=temporal_threats,
            composability_risks=composability_risks,
            agent_routing=agent_routing,
        )

    def get_agent_routing(
        self,
        protocol_type: str,
        hotspot_signals: dict[str, Any],
    ) -> list[str]:
        """
        Determine which specialist agents should analyze a given hotspot.
        Implements Decision D1: orchestrator decides, not exhaustive spawning.

        Args:
            protocol_type: The detected protocol type (e.g., "vault")
            hotspot_signals: Dict of graph-derived signals for the hotspot, e.g.:
                {
                    "has_external_calls": True,
                    "has_oracle_dependency": False,
                    "has_math_operations": True,
                    "has_division": True,
                    "has_role_checks": False,
                    "is_initializer": False,
                    "writes_state": True,
                    "has_reentrancy_risk": False,
                    "matched_vector_count": 5,
                }

        Returns:
            List of agent type strings to spawn, e.g.:
            ["attack_hypothesis", "assumption", "math_precision", "vector_scan"]
        """
        profile = self.get_threat_profile(protocol_type)
        routing_rules = profile.agent_routing

        # Always-spawn agents
        agents = list(routing_rules.get("always", ["attack_hypothesis", "assumption"]))

        # Conditional routing based on hotspot signals
        if hotspot_signals.get("has_external_calls") or hotspot_signals.get("has_oracle_dependency"):
            agents.extend(routing_rules.get("when_external_calls", ["composability"]))

        if hotspot_signals.get("has_math_operations") or hotspot_signals.get("has_division"):
            agents.extend(routing_rules.get("when_math_heavy", ["math_precision"]))

        if hotspot_signals.get("has_role_checks") or hotspot_signals.get("is_initializer"):
            agents.extend(routing_rules.get("when_multi_role", ["access_control"]))

        if hotspot_signals.get("has_reentrancy_risk"):
            agents.extend(routing_rules.get("when_reentrancy", []))

        # Vector scan agent: always spawn if matched vectors exist
        if hotspot_signals.get("matched_vector_count", 0) > 0:
            if "vector_scan" not in agents:
                agents.append("vector_scan")

        # Deduplicate while preserving order
        seen: set[str] = set()
        deduped: list[str] = []
        for a in agents:
            if a not in seen:
                seen.add(a)
                deduped.append(a)

        return deduped

    def extract_hotspot_signals(self, graph: nx.DiGraph, hotspot_node_id: str) -> dict[str, Any]:
        """
        Extract routing-relevant signals from a hotspot's graph node.
        These signals feed into get_agent_routing().
        """
        if not graph.has_node(hotspot_node_id):
            return {}

        data = graph.nodes[hotspot_node_id]
        signals: dict[str, Any] = {}

        # External call signals
        has_external = False
        for _, target, edge_data in graph.out_edges(hotspot_node_id, data=True):
            if edge_data.get("relationship") == "CROSS_CONTRACT_CALL" or edge_data.get("type") == "CROSS_CONTRACT_CALL":
                has_external = True
                break
        signals["has_external_calls"] = has_external

        # Oracle dependency
        signals["has_oracle_dependency"] = bool(data.get("has_oracle_pattern", False))

        # Math operations — check source code for division/multiplication patterns
        source = data.get("source_code", "")
        signals["has_math_operations"] = bool(
            "/" in source or "%" in source or "**" in source or "mulDiv" in source or "FullMath" in source
        )
        signals["has_division"] = "/" in source and "//" not in source  # exclude comments

        # Access control signals
        signals["has_role_checks"] = bool(data.get("is_protected", False))
        signals["is_initializer"] = bool(
            data.get("name", "").lower() in ("initialize", "init", "__init")
            or "initializer" in str(data.get("modifiers", [])).lower()
        )

        # State mutation
        signals["writes_state"] = bool(data.get("writes_state", False))

        # Reentrancy risk
        signals["has_reentrancy_risk"] = bool(data.get("reentrancy_risk", False))

        return signals
