import asyncio
import logging
import re
from pathlib import Path
from src.agents.base_worker import WorkerAgent, WorkerOutput, WorkerTask

logger = logging.getLogger(__name__)
from src.tools.etherscan_client import EtherscanClient
from src.utils.graph_queries import (
    get_external_entry_points,
    get_privileged_roles,
)

# Keywords that indicate deliberate design choices — NOT vulnerabilities
DESIGN_INTENT_KEYWORDS = [
    "permissionless", "anyone can", "no access control", "by design",
    "intentionally", "trusted", "not supported", "known limitation",
    "on behalf of", "on behalf", "delegated", "authorized caller",
    "fee-on-transfer tokens are not supported",
    "rebasing tokens are not supported",
]

# Doc files to scan in any repo (case-insensitive)
DOC_FILE_PATTERNS = [
    "README.md", "readme.md", "README.rst",
    "WHITEPAPER.md", "whitepaper.md", "WHITEPAPER.pdf",
    "SECURITY.md", "security.md",
    "SPECIFICATION.md", "specification.md",
    "DESIGN.md", "design.md",
    "ARCHITECTURE.md", "architecture.md",
]

# Directories to scan for docs
DOC_DIR_PATTERNS = ["docs", "doc", "documentation", "audits", "audit-reports"]


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
        repo_path: str | None = input_data.get("repo_path")

        # Run all SIX intel sources in parallel
        graph_intel, rag_intel, onchain_intel, docs_intel, natspec_intel, compiler_intel, test_intel = await asyncio.gather(
            self._gather_graph_intel(contract_names),
            self._gather_rag_intel(contract_names),
            self._gather_onchain_intel(contract_addresses),
            self._gather_repo_docs_intel(repo_path),
            self._gather_natspec_intel(repo_path),
            self._gather_compiler_intel(repo_path),
            self._gather_test_intent_intel(repo_path),
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

        # Build design context from new intel sources
        design_context = {
            "design_summary": docs_intel.get("design_summary", ""),
            "doc_files_read": docs_intel.get("files_read", []),
            "natspec_intent": natspec_intel.get("function_natspec", {}),
            "intentional_patterns": natspec_intel.get("intentional_patterns", []),
            "compiler_info": compiler_intel,
            "tested_areas": test_intel,
        }
        print(f"  [Recon] Design context: {len(design_context['doc_files_read'])} docs, "
              f"{len(design_context['intentional_patterns'])} intentional patterns, "
              f"solidity={compiler_intel.get('solidity_version', '?')}, "
              f"safe_math={compiler_intel.get('has_safe_math', '?')}")

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
            "design_context": design_context,
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
        Uses contract names for targeted queries instead of generic strings.
        """
        from src.knowledge.rag_system import search_security_knowledge

        # Build protocol-specific queries from contract names
        queries = []
        for name in contract_names[:5]:  # cap at 5 to avoid overloading RAG
            queries.append(f"{name} vulnerability exploit audit finding")
            queries.append(f"{name} security issue known bug")

        # Add broad queries only if we have few contracts
        if len(contract_names) <= 2:
            queries.extend([
                "lending protocol liquidation vulnerability exploit",
                "DeFi callback reentrancy CEI violation",
            ])

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

    # ------------------------------------------------------------------ #
    #  NEW: Design-Intent Intelligence Sources (generalised)              #
    # ------------------------------------------------------------------ #

    async def _gather_repo_docs_intel(self, repo_path: str | None) -> dict:
        """
        Scans the repo for README, docs/, whitepaper, audits/, SECURITY.md.
        Reads first 3000 chars of each and summarises with LLM.
        Fully generalised — works on any repo structure.
        """
        if not repo_path:
            return {"design_summary": "", "files_read": []}

        root = Path(repo_path)
        if not root.exists():
            return {"design_summary": "", "files_read": []}

        collected_text = []
        files_read = []

        # Scan for doc files in root
        for pattern in DOC_FILE_PATTERNS:
            for f in root.rglob(pattern):
                if "node_modules" in str(f) or "/lib/" in str(f):
                    continue
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")[:3000]
                    collected_text.append(f"--- {f.relative_to(root)} ---\n{text}")
                    files_read.append(str(f.relative_to(root)))
                except Exception:
                    pass
                if len(files_read) >= 10:  # cap to avoid overloading
                    break

        # Scan doc directories
        for dir_name in DOC_DIR_PATTERNS:
            for doc_dir in root.rglob(dir_name):
                if not doc_dir.is_dir():
                    continue
                if "node_modules" in str(doc_dir) or "/lib/" in str(doc_dir):
                    continue
                for f in sorted(doc_dir.rglob("*.md"))[:5]:  # max 5 docs per dir
                    try:
                        text = f.read_text(encoding="utf-8", errors="replace")[:2000]
                        collected_text.append(f"--- {f.relative_to(root)} ---\n{text}")
                        files_read.append(str(f.relative_to(root)))
                    except Exception:
                        pass

        if not collected_text:
            return {"design_summary": "", "files_read": []}

        # Use LLM to summarise docs
        all_docs = "\n\n".join(collected_text)[:12000]  # cap total input
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(self.llm.invoke, [
                    {"role": "system", "content": (
                        "You are a security auditor pre-reading protocol documentation. "
                        "Summarise in 3-5 bullet points:\n"
                        "1. What is this protocol? (1 sentence)\n"
                        "2. What functions are INTENTIONALLY permissionless? (list them)\n"
                        "3. What token types are NOT supported? (e.g. fee-on-transfer, rebasing)\n"
                        "4. What security assumptions does the protocol make?\n"
                        "5. Any known limitations or prior audit findings mentioned?\n"
                        "Be concise. Output only the bullet points."
                    )},
                    {"role": "user", "content": all_docs}
                ]),
                timeout=60
            )
            summary = response.content if hasattr(response, "content") else str(response)
        except Exception as e:
            logger.warning(f"[Recon] LLM doc summary failed: {e}")
            summary = ""

        print(f"  [Recon] Read {len(files_read)} doc file(s): {files_read}")
        return {"design_summary": summary, "files_read": files_read}

    async def _gather_natspec_intel(self, repo_path: str | None) -> dict:
        """
        Extracts natspec comments (/// @notice, /// @dev, /// @custom:) from
        all .sol files in src/ or contracts/. Detects design-intent keywords.
        Fully generalised — no protocol-specific code.
        """
        if not repo_path:
            return {"function_natspec": {}, "intentional_patterns": []}

        root = Path(repo_path)
        src_dirs = []
        for d in ["src", "contracts"]:
            for candidate in root.rglob(d):
                if candidate.is_dir() and "node_modules" not in str(candidate) and "/lib/" not in str(candidate):
                    src_dirs.append(candidate)

        if not src_dirs:
            src_dirs = [root]  # fallback: scan from root

        natspec_re = re.compile(r'///\s*(@\w+)?\s*(.*)', re.MULTILINE)
        function_re = re.compile(r'function\s+(\w+)\s*\(')

        function_natspec: dict[str, list[str]] = {}
        intentional_patterns: list[str] = []
        seen_patterns: set[str] = set()

        for src_dir in src_dirs:
            for sol_file in src_dir.rglob("*.sol"):
                if "test" in str(sol_file).lower() or "mock" in str(sol_file).lower():
                    continue
                try:
                    content = sol_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                lines = content.split("\n")
                current_natspec: list[str] = []

                for line in lines:
                    stripped = line.strip()

                    # Collect natspec lines
                    ns_match = natspec_re.match(stripped)
                    if ns_match:
                        ns_text = ns_match.group(2).strip()
                        if ns_text:
                            current_natspec.append(ns_text)

                            # Check for design-intent keywords
                            lower = ns_text.lower()
                            for keyword in DESIGN_INTENT_KEYWORDS:
                                if keyword in lower and keyword not in seen_patterns:
                                    pattern_desc = f"{sol_file.name}: '{ns_text.strip()}'"
                                    intentional_patterns.append(pattern_desc)
                                    seen_patterns.add(keyword)
                        continue

                    # If we hit a function declaration, assign collected natspec
                    fn_match = function_re.search(stripped)
                    if fn_match and current_natspec:
                        fn_name = fn_match.group(1)
                        function_natspec[fn_name] = list(current_natspec)
                        current_natspec = []
                    elif not stripped.startswith("//"):
                        # Non-comment, non-function line resets natspec buffer
                        if stripped and not stripped.startswith("*") and not stripped.startswith("/*"):
                            current_natspec = []

        print(f"  [Recon] Natspec: {len(function_natspec)} functions documented, "
              f"{len(intentional_patterns)} intentional pattern(s)")
        return {
            "function_natspec": function_natspec,
            "intentional_patterns": intentional_patterns,
        }

    async def _gather_compiler_intel(self, repo_path: str | None) -> dict:
        """
        Detects the Solidity compiler version from pragma directives or foundry.toml.
        Determines if safe math (0.8+), unchecked blocks, etc. are relevant.
        Fully generalised — works on any Solidity project.
        """
        result = {
            "solidity_version": "unknown",
            "has_safe_math": False,
            "has_unchecked_blocks": False,
            "multiple_versions": False,
        }

        if not repo_path:
            return result

        root = Path(repo_path)
        pragma_re = re.compile(r'pragma\s+solidity\s+[\^~>=<]*\s*(0\.\d+\.\d+)')
        unchecked_re = re.compile(r'unchecked\s*\{')

        versions: set[str] = set()
        has_unchecked = False

        src_dirs = []
        for d in ["src", "contracts"]:
            for candidate in root.rglob(d):
                if candidate.is_dir() and "node_modules" not in str(candidate) and "/lib/" not in str(candidate):
                    src_dirs.append(candidate)
        if not src_dirs:
            src_dirs = [root]

        for src_dir in src_dirs:
            for sol_file in src_dir.rglob("*.sol"):
                if "test" in str(sol_file).lower() or "mock" in str(sol_file).lower():
                    continue
                try:
                    content = sol_file.read_text(encoding="utf-8", errors="replace")[:2000]
                except Exception:
                    continue

                m = pragma_re.search(content)
                if m:
                    versions.add(m.group(1))

                if unchecked_re.search(content):
                    has_unchecked = True

        if versions:
            sorted_versions = sorted(versions)
            primary = sorted_versions[-1]  # use highest version
            result["solidity_version"] = primary
            result["multiple_versions"] = len(versions) > 1

            # 0.8.0+ has built-in overflow/underflow protection
            parts = primary.split(".")
            if len(parts) == 3:
                try:
                    minor = int(parts[1])
                    result["has_safe_math"] = minor >= 8
                except ValueError:
                    pass

        result["has_unchecked_blocks"] = has_unchecked

        print(f"  [Recon] Compiler: solidity={result['solidity_version']}, "
              f"safe_math={result['has_safe_math']}, "
              f"unchecked={result['has_unchecked_blocks']}")
        return result

    async def _gather_test_intent_intel(self, repo_path: str | None) -> dict:
        """
        Scans test/ directory for test file names and function patterns.
        Identifies what the developers already test (fuzz, invariant, unit).
        Fully generalised — works on any Foundry/Hardhat project.
        """
        result = {
            "test_file_count": 0,
            "tested_functions": [],
            "fuzz_targets": [],
            "invariant_targets": [],
            "has_fork_tests": False,
        }

        if not repo_path:
            return result

        root = Path(repo_path)
        test_dirs = list(root.rglob("test"))
        test_dirs = [d for d in test_dirs if d.is_dir()
                     and "node_modules" not in str(d)
                     and "/lib/" not in str(d)]

        if not test_dirs:
            return result

        test_fn_re = re.compile(r'function\s+(test\w+|invariant_\w+|testFuzz_\w+|testFail_\w+)\s*\(')
        fork_re = re.compile(r'vm\.createFork|vm\.selectFork|fork', re.IGNORECASE)

        tested = set()
        fuzz = set()
        invariant = set()
        has_fork = False
        file_count = 0

        for test_dir in test_dirs:
            for sol_file in test_dir.rglob("*.sol"):
                file_count += 1
                try:
                    content = sol_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                for m in test_fn_re.finditer(content):
                    fn_name = m.group(1)
                    tested.add(fn_name)
                    if fn_name.startswith("testFuzz_") or fn_name.startswith("testFuzz"):
                        fuzz.add(fn_name)
                    elif fn_name.startswith("invariant_"):
                        invariant.add(fn_name)

                if fork_re.search(content):
                    has_fork = True

        result["test_file_count"] = file_count
        result["tested_functions"] = sorted(tested)[:50]  # cap
        result["fuzz_targets"] = sorted(fuzz)[:20]
        result["invariant_targets"] = sorted(invariant)[:20]
        result["has_fork_tests"] = has_fork

        print(f"  [Recon] Tests: {file_count} file(s), {len(tested)} test fn(s), "
              f"{len(fuzz)} fuzz, {len(invariant)} invariant")
        return result
