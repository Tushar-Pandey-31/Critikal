import asyncio
import logging
from src.agents.base_worker import WorkerAgent, WorkerOutput, WorkerTask

logger = logging.getLogger(__name__)
from src.tools.etherscan_client import EtherscanClient
from src.utils.graph_queries import (
    get_external_entry_points,
    get_privileged_roles,
)


# Known protocol type signatures — extend as needed
PROTOCOL_SIGNATURES = {
    "vault": ["deposit", "withdraw", "harvest", "earn", "totalAssets", "pricePerShare"],
    "dex": ["swap", "addLiquidity", "removeLiquidity", "getAmountsOut", "pool"],
    "lending": ["borrow", "repay", "liquidate", "collateral", "healthFactor"],
    "governance": ["propose", "vote", "execute", "queue", "cancel", "timelock"],
    "bridge": ["bridgeTokens", "lock", "unlock", "mint", "burn", "relay"],
    "staking": ["stake", "unstake", "claimRewards", "getReward", "earned"],
}

# Maps protocol type → historically high-risk attack patterns
KNOWN_ATTACK_PATTERNS = {
    "vault": [
        "reentrancy in withdraw/deposit",
        "ERC4626 share inflation (first depositor attack)",
        "fee-on-transfer token accounting errors",
        "yield strategy reentrancy",
    ],
    "dex": [
        "price oracle manipulation via flash loans",
        "sandwich attacks on slippage tolerance",
        "reentrancy in swap callbacks (uniswap v3 style)",
        "liquidity manipulation for unfair pricing",
    ],
    "lending": [
        "oracle price manipulation → bad debt",
        "reentrancy in liquidation callbacks",
        "interest rate model manipulation",
        "collateral factor misconfiguration",
    ],
    "governance": [
        "flash loan governance takeover",
        "timelock bypass via delegatecall",
        "proposal frontrunning",
        "vote manipulation via token flash loans",
    ],
    "bridge": [
        "signature replay across chains",
        "message validation bypass",
        "reentrancy in unlock/mint",
        "cross-chain oracle inconsistency",
    ],
    "staking": [
        "reward calculation manipulation",
        "reentrancy in claimRewards",
        "flash loan stake-unstake for reward inflation",
    ],
    "unknown": [
        "unprotected state mutation",
        "access control misconfiguration",
        "integer overflow/underflow",
        "reentrancy in external calls",
    ],
}


class ReconWorker(WorkerAgent):
    """
    Gathers protocol-level intelligence before vulnerability analysis.
    Produces context for Attack Workers — does NOT generate findings.

    Input (input_data keys):
        contract_names: list[str]     — from graph
        contract_addresses: dict      — {name: "0x..."} if known, else {}
        repo_url: str | None

    Output:
        WorkerOutput with confidence=0, attack_path=[]
        raw_output contains full ReconReport
    """

    model_name: str = "gemini-2.5-flash"

    def get_worker_type(self) -> str:
        return "recon"

    def __init__(self, graph, llm_client, etherscan_client: EtherscanClient | None = None):
        self.graph = graph
        self.llm = llm_client
        self.etherscan = etherscan_client or EtherscanClient()  # auto-stubs if no key

    async def run(self, task: WorkerTask) -> WorkerOutput:
        input_data = task.context
        contract_names: list[str] = input_data.get("contract_names", [])
        contract_addresses: dict = input_data.get("contract_addresses", {})
        repo_url: str | None = input_data.get("repo_url")

        # Run all three intel sources in parallel
        graph_intel, rag_intel, onchain_intel = await asyncio.gather(
            self._gather_graph_intel(contract_names),
            self._gather_rag_intel(contract_names),
            self._gather_onchain_intel(contract_addresses),
        )

        # Classify protocol type from graph intel
        protocol_type = self._classify_protocol(graph_intel)

        # Build attack pattern list from type + RAG findings
        known_patterns = KNOWN_ATTACK_PATTERNS.get(protocol_type, KNOWN_ATTACK_PATTERNS["unknown"])
        rag_patterns = rag_intel.get("additional_patterns", [])
        all_patterns = list(dict.fromkeys(known_patterns + rag_patterns))  # dedup, preserve order

        # Build trust assumptions from graph roles + onchain deployer
        trust_assumptions = self._build_trust_assumptions(graph_intel, onchain_intel)

        # Upgradeability: detected from graph (proxy patterns) or Etherscan
        upgradeability = self._detect_upgradeability(graph_intel, onchain_intel)

        raw_output = {
            "protocol_summary": self._generate_summary(
                contract_names, protocol_type, graph_intel, onchain_intel
            ),
            "protocol_type": protocol_type,
            "trust_assumptions": trust_assumptions,
            "upgradeability_model": upgradeability,
            "known_attack_patterns": all_patterns,
            "recommended_focus_areas": self._recommend_focus(
                protocol_type, graph_intel, onchain_intel
            ),
            "rag_sources_used": rag_intel.get("sources_used", []),
            "onchain_risk_signals": {
                "contract_age_days": onchain_intel.get("contract_age_days"),
                "previous_exploits_detected": onchain_intel.get("previous_exploits_detected", False),
                "exploit_summary": onchain_intel.get("exploit_summary"),
                "recent_large_withdrawals": onchain_intel.get("recent_large_withdrawals", False),
                "flash_loan_interactions": onchain_intel.get("flash_loan_interactions", False),
                "is_proxy": onchain_intel.get("is_proxy", False),
                "data_source": onchain_intel.get("data_source", "stub"),
            },
        }

        return WorkerOutput(
            worker_type="recon",
            hypothesis=None,        # Recon never generates hypotheses
            evidence_node_ids=[],   # Contract-level only — no function node IDs
            attack_path=[],         # Always empty — Recon has no exploit path
            confidence=0,           # Always 0 — Recon is context, not a finding
            raw_output=raw_output,
        )

    # ------------------------------------------------------------------ #
    #  Internal Methods                                                     #
    # ------------------------------------------------------------------ #

    async def _gather_graph_intel(self, contract_names: list[str]) -> dict:
        """Pull structural metadata from the knowledge graph."""
        all_entry_points = []
        all_roles = {}

        for name in contract_names:
            entry_points = get_external_entry_points(self.graph, contract_name=name)
            roles = get_privileged_roles(self.graph, contract_name=name)
            all_entry_points.extend(entry_points)
            if roles:
                all_roles[name] = roles

        # Extract function names for protocol classification
        function_names = [ep.get("name", "") for ep in all_entry_points]

        return {
            "function_names": function_names,
            "privileged_roles": all_roles,
            "entry_point_count": len(all_entry_points),
        }

    async def _gather_rag_intel(self, contract_names: list[str]) -> dict:
        """
        Query the RAG system with protocol-relevant queries.
        Returns additional attack patterns from historical audits.
        """
        from src.knowledge.rag_system import search_security_knowledge  # adjust import

        # We don't know the protocol type yet, so query broadly
        queries = [
            "reentrancy vulnerability DeFi protocol exploit",
            "access control privilege escalation smart contract",
            "flash loan attack oracle manipulation",
            "common DeFi audit findings critical vulnerabilities",
        ]

        all_results = []
        sources_used = []

        for query in queries:
            try:
                results = search_security_knowledge(query, k=3)
                all_results.extend(results)
                sources_used.extend([r.get("source", "") for r in results if r.get("source")])
            except Exception:
                pass  # RAG failure is non-fatal — continue without it

        # Extract any additional patterns mentioned in RAG results
        additional_patterns = []
        for result in all_results:
            content = result.get("content", "")
            # Basic extraction — LLM synthesis could replace this later
            if "reentrancy" in content.lower():
                additional_patterns.append("reentrancy pattern detected in historical reports")
            if "flash loan" in content.lower():
                additional_patterns.append("flash loan attack pattern in historical reports")

        return {
            "sources_used": list(set(sources_used)),
            "additional_patterns": list(set(additional_patterns)),
            "raw_results": all_results,
        }

    async def _gather_onchain_intel(self, contract_addresses: dict) -> dict:
        """
        Pull on-chain data for each known address.
        If no addresses provided, returns all-stub data.
        """
        if not contract_addresses:
            return {
                "contract_age_days": None,
                "previous_exploits_detected": False,
                "exploit_summary": None,
                "recent_large_withdrawals": False,
                "flash_loan_interactions": False,
                "is_proxy": False,
                "data_source": "stub",
            }

        # Use the first address as the primary contract
        # Future: aggregate across all contracts in protocol
        primary_address = next(iter(contract_addresses.values()))

        try:
            contract_info = self.etherscan.get_contract_info(primary_address)
            exploit_history = self.etherscan.get_exploit_history(primary_address)
            tx_profile = self.etherscan.get_transaction_profile(primary_address)

            exploit_summary = None
            if exploit_history.previous_exploits_detected and exploit_history.exploits:
                top = exploit_history.exploits[0]
                exploit_summary = (
                    f"Largest suspicious outflow: {top.value_lost_eth:.2f} ETH "
                    f"in tx {top.tx_hash[:10]}..."
                )

            return {
                "contract_age_days": contract_info.contract_age_days,
                "previous_exploits_detected": exploit_history.previous_exploits_detected,
                "exploit_summary": exploit_summary,
                "recent_large_withdrawals": tx_profile.recent_large_withdrawals,
                "flash_loan_interactions": tx_profile.flash_loan_interactions,
                "is_proxy": contract_info.is_proxy,
                "implementation_address": contract_info.implementation_address,
                "data_source": contract_info.data_source,
            }

        except Exception as e:
            # Etherscan failure is non-fatal
            logger.info(f"[ReconWorker] Etherscan error: {e}. Continuing with stub data.")
            return {
                "contract_age_days": None,
                "previous_exploits_detected": False,
                "exploit_summary": None,
                "recent_large_withdrawals": False,
                "flash_loan_interactions": False,
                "is_proxy": False,
                "data_source": "stub",
            }

    def _classify_protocol(self, graph_intel: dict) -> str:
        """
        Classify protocol type by checking function names against signatures.
        Returns the type with the most signature matches.
        """
        function_names_lower = [f.lower() for f in graph_intel.get("function_names", [])]

        scores = {}
        for protocol_type, signatures in PROTOCOL_SIGNATURES.items():
            score = sum(
                1 for sig in signatures
                if any(sig.lower() in fname for fname in function_names_lower)
            )
            scores[protocol_type] = score

        best_type = max(scores, key=scores.get)
        return best_type if scores[best_type] > 0 else "unknown"

    def _build_trust_assumptions(self, graph_intel: dict, onchain_intel: dict) -> list[str]:
        assumptions = []
        roles = graph_intel.get("privileged_roles", {})

        for contract, role_list in roles.items():
            for role in role_list:
                role_name = role.get("role_name", "unknown")
                assumptions.append(f"{role_name} in {contract} is trusted")

        if onchain_intel.get("is_proxy"):
            assumptions.append("Proxy implementation can be upgraded by admin")

        if not assumptions:
            assumptions.append("No privileged roles detected — verify manually")

        return assumptions

    def _detect_upgradeability(self, graph_intel: dict, onchain_intel: dict) -> str:
        if onchain_intel.get("is_proxy"):
            impl = onchain_intel.get("implementation_address")
            return "proxy" if impl else "proxy (implementation unknown)"

        # Heuristic: look for upgradeable function names in graph
        function_names = [f.lower() for f in graph_intel.get("function_names", [])]
        if any("upgrade" in f or "implementation" in f for f in function_names):
            return "proxy (detected from function names)"

        if any("beacon" in f for f in function_names):
            return "beacon"

        return "none"

    def _generate_summary(
        self,
        contract_names: list[str],
        protocol_type: str,
        graph_intel: dict,
        onchain_intel: dict,
    ) -> str:
        age = onchain_intel.get("contract_age_days")
        age_str = f"{age} days old" if age else "age unknown"
        entry_count = graph_intel.get("entry_point_count", 0)

        return (
            f"Protocol contains {len(contract_names)} contract(s) "
            f"classified as type '{protocol_type}'. "
            f"{entry_count} external entry points detected. "
            f"Contract is {age_str}."
        )

    def _recommend_focus(self, protocol_type: str, graph_intel: dict, onchain_intel: dict) -> list[str]:
        focus = []

        # Type-based base recommendations
        if protocol_type == "vault":
            focus.append("Audit withdraw() for reentrancy and balance accounting")
            focus.append("Check deposit() for share inflation edge cases")
        elif protocol_type == "lending":
            focus.append("Audit liquidation logic for oracle dependency")
            focus.append("Check collateral accounting for reentrancy")
        elif protocol_type == "dex":
            focus.append("Audit price calculation functions for manipulation")
            focus.append("Check swap callbacks for reentrancy")
        elif protocol_type == "governance":
            focus.append("Check vote counting for flash loan manipulation")
            focus.append("Audit proposal execution for access control")

        # Onchain signal escalations
        if onchain_intel.get("previous_exploits_detected"):
            focus.insert(0, "⚠️  PRIOR EXPLOIT DETECTED — review historical attack vector first")

        if onchain_intel.get("flash_loan_interactions"):
            focus.append("Flash loan interactions detected on-chain — oracle manipulation likely worth investigating")

        if onchain_intel.get("is_proxy"):
            focus.append("Proxy pattern detected — audit upgrade access control and storage layout")

        age = onchain_intel.get("contract_age_days")
        if age is not None and age < 30:
            focus.append(f"Contract is only {age} days old — higher risk, less battle-tested")

        return focus
