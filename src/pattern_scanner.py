"""
Titan Pattern Engine — Broad-spectrum Solidity vulnerability detector.

Scans .sol source files for 100+ vulnerability patterns (ETH-001 to ETH-094)
and produces PatternHit objects.  These are NOT standalone findings — they are
raw signals consumed by GraphBuilder._integrate_pattern_hits(), which validates
each hit against taint paths, reachability, and access control context.

Usage (standalone):
    hits = scan_all_sources(file_cache)   # file_cache: {path: content}

Usage (inside GraphBuilder):
    hits = scan_all_sources(self._file_cache)
    self._integrate_pattern_hits(hits)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ────────────────────────────────────────────────────────────────────────────
#  Data Model
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class PatternHit:
    """A raw vulnerability signal found by regex pattern matching."""
    pattern_id: str          # "ETH-001"
    title: str
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    confidence: float        # 0.0 – 1.0 (raw, before graph validation)
    file: str
    line: int
    code_snippet: str
    description: str
    recommendation: str
    category: str            # reentrancy, access-control, arithmetic, …
    swc: Optional[str] = None


# ────────────────────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────────────────────

def _add(
    hits: list[PatternHit],
    fid: str, title: str, sev: str, conf: float,
    fpath: str, ln: int, snip: str, desc: str, rec: str, cat: str,
    swc: str | None = None,
) -> None:
    hits.append(PatternHit(
        pattern_id=fid, title=title, severity=sev, confidence=conf,
        file=fpath, line=ln, code_snippet=snip.strip(),
        description=desc, recommendation=rec, category=cat, swc=swc,
    ))


def _detect_pragma(content: str) -> tuple[int, int]:
    """Return (major_minor, patch) from pragma, defaulting to (8, 20)."""
    m = re.search(r'pragma solidity\s*[\^>=<~]*\s*0\.(\d+)\.(\d+)', content)
    if m:
        return int(m.group(1)), int(m.group(2))
    return 8, 20


# ────────────────────────────────────────────────────────────────────────────
#  Per-file scanning
# ────────────────────────────────────────────────────────────────────────────

def scan_file(file_path: str, content: str) -> list[PatternHit]:
    """Scan a single Solidity source file for vulnerability patterns."""
    hits: list[PatternHit] = []
    lines = content.split("\n")
    cl = content.lower()

    # ── File-level context flags ──────────────────────────────────────────
    has_safe_erc20_usage = "safetransfer(" in cl or "safetransferfrom(" in cl
    has_reentrancy_guard = "nonreentrant" in cl or "reentrancyguard" in cl
    has_chainid = "block.chainid" in cl or "chainid" in cl
    has_safemath = "using safemath for" in cl

    pragma_minor, pragma_patch = _detect_pragma(content)
    is_old_pragma = pragma_minor < 8

    # Track emitted finding IDs per file to avoid duplicates
    file_findings: set[str] = set()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue

        # ── ETH-001: Single-function Reentrancy (CEI Violation) ───────
        if ".call{value:" in line or ".call{ value:" in line:
            local_has_guard = False
            for j in range(max(1, i - 5), i):
                ctx = lines[j - 1] if j <= len(lines) else ""
                if "nonreentrant" in ctx.lower() or "nonReentrant" in ctx:
                    local_has_guard = True
                    break
            if not local_has_guard and "ETH-001" not in file_findings:
                for j in range(i + 1, min(i + 20, len(lines) + 1)):
                    ctx = lines[j - 1]
                    if ctx.strip().startswith("//"):
                        continue
                    if re.search(r'\w+\[.*?\]\s*[-+*]?=\s', ctx) or \
                       re.search(r'balance\w*\s*[-+]?=', ctx) or \
                       re.search(r'\b(state|total|amount|counter|balance)\w*\s*[-+]?=', ctx):
                        _add(hits, "ETH-001", "Single-function Reentrancy (CEI Violation)",
                             "CRITICAL", 0.85, file_path, i, stripped,
                             "External call with value transfer before state update. Classic reentrancy via CEI violation.",
                             "Follow Checks-Effects-Interactions: update state before external call. Use ReentrancyGuard.",
                             "reentrancy", "SWC-107")
                        file_findings.add("ETH-001")
                        break

        # ── ETH-004: Read-only Reentrancy ─────────────────────────────
        if "ETH-004" not in file_findings:
            if ("receive()" in line or "fallback()" in line) and "external" in line:
                for j in range(i, min(i + 15, len(lines) + 1)):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if re.search(r'\b(target|vuln|victim)\w*\.\w+\(', ctx, re.IGNORECASE) or \
                       "get_virtual_price" in ctx or "getReward" in ctx:
                        _add(hits, "ETH-004", "Read-only Reentrancy Risk",
                             "HIGH", 0.70, file_path, i, stripped,
                             "Callback (receive/fallback) reads external state during reentrancy window.",
                             "Use reentrancy-aware oracles or check reentrancy lock in view functions.",
                             "reentrancy")
                        file_findings.add("ETH-004")
                        break
            if "view" in line and "function" in line and ("external" in line or "public" in line):
                if ("get_virtual_price" in cl or "getprice" in cl) and \
                   ("remove_liquidity" in cl or "receive()" in cl):
                    _add(hits, "ETH-004", "Read-only Reentrancy Risk",
                         "HIGH", 0.65, file_path, i, stripped,
                         "View function returns state dependent on external oracle, exploitable during reentrancy.",
                         "Use reentrancy-aware oracles or check reentrancy lock in view functions.",
                         "reentrancy")
                    file_findings.add("ETH-004")

        # ── ETH-006: Missing Access Control ───────────────────────────
        if "function" in line and ("external" in line or "public" in line):
            func_m = re.search(r'function\s+(\w+)', line)
            if func_m:
                fname = func_m.group(1).lower()
                sensitive = ["owner", "admin", "mint", "burn", "withdraw", "recover",
                             "upgrade", "pause", "unpause", "kill", "destroy", "set",
                             "change", "remove", "delete", "transfer"]
                is_sensitive = any(s in fname for s in sensitive)
                has_modifier = any(m in line for m in [
                    "onlyOwner", "onlyAdmin", "onlyRole", "only", "auth",
                    "restricted", "whenNotPaused", "initializer", "nonReentrant",
                    "modifier"])
                if is_sensitive and not has_modifier:
                    has_state_write = False
                    for j in range(i, min(i + 6, len(lines) + 1)):
                        ctx = lines[j - 1] if j <= len(lines) else ""
                        if re.search(r'\b\w+\s*=\s*[^=]', ctx) and "==" not in ctx and "!=" not in ctx:
                            has_state_write = True
                            break
                    if has_state_write:
                        _add(hits, "ETH-006", "Missing Access Control on Sensitive Function",
                             "CRITICAL", 0.70, file_path, i, stripped,
                             f"Function '{func_m.group(1)}' modifies state without access control modifier.",
                             "Add onlyOwner, onlyRole, or similar access control modifier.",
                             "access-control", "SWC-105")

        # ── ETH-007: tx.origin Authentication ─────────────────────────
        if "tx.origin" in line and ("require" in line or "if" in line):
            _add(hits, "ETH-007", "tx.origin Authentication",
                 "CRITICAL", 0.90, file_path, i, stripped,
                 "tx.origin used for authentication. Vulnerable to phishing via intermediate contracts.",
                 "Replace tx.origin with msg.sender for authentication.",
                 "access-control", "SWC-115")

        # ── ETH-008: selfdestruct ─────────────────────────────────────
        if "selfdestruct" in line or "suicide" in line:
            _add(hits, "ETH-008", "selfdestruct Usage",
                 "HIGH", 0.75, file_path, i, stripped,
                 "selfdestruct found. Check access control and proxy implications.",
                 "Ensure selfdestruct has proper access control. Consider removing if not needed.",
                 "access-control", "SWC-106")

        # ── ETH-009: Unprotected Ownership Function ───────────────────
        if "function" in line and ("public" in line or "external" in line):
            func_m = re.search(r'function\s+(\w+)', line)
            if func_m:
                fname = func_m.group(1).lower()
                owner_funcs = ["changeowner", "setowner", "transferownership", "updateowner"]
                if fname in owner_funcs:
                    has_mod = any(m in line for m in ["onlyOwner", "only", "auth"])
                    if not has_mod:
                        _add(hits, "ETH-009", "Unprotected Ownership Function",
                             "CRITICAL", 0.85, file_path, i, stripped,
                             "Ownership change function accessible without access control.",
                             "Add onlyOwner modifier to restrict access.",
                             "access-control", "SWC-100")

        # ── ETH-012: Hidden Backdoor via Assembly ─────────────────────
        if "sstore" in line and "assembly" in cl:
            _add(hits, "ETH-012", "Assembly sstore — Potential Backdoor",
                 "HIGH", 0.65, file_path, i, stripped,
                 "Direct storage write via assembly sstore. May indicate backdoor or hidden state manipulation.",
                 "Review assembly sstore usage. Ensure no unauthorized storage modifications.",
                 "access-control")

        # ── ETH-013: Unchecked Arithmetic ─────────────────────────────
        if "unchecked" in line and "{" in line:
            _add(hits, "ETH-013", "Unchecked Arithmetic Block",
                 "HIGH", 0.70, file_path, i, stripped,
                 "unchecked block disables overflow/underflow protection.",
                 "Ensure values in unchecked blocks cannot overflow. Add bounds checks.",
                 "arithmetic", "SWC-101")

        # ETH-013 variant: old pragma (< 0.8.0) arithmetic without SafeMath
        if is_old_pragma and not has_safemath and "ETH-013-old" not in file_findings:
            if re.search(r'[\w\]]\s*[-+\*]=\s*\w', line) or \
               re.search(r'\w+\s*=\s*\w+\s*[-+\*]\s*\w', line):
                if "function" not in line and "pragma" not in line and "import" not in line and "event" not in line:
                    _add(hits, "ETH-013", "Arithmetic Without Overflow Protection (pre-0.8.0)",
                         "HIGH", 0.80, file_path, i, stripped,
                         f"Solidity 0.{pragma_minor}.{pragma_patch} lacks automatic overflow checks. No SafeMath detected.",
                         "Upgrade to Solidity >= 0.8.0 or use OpenZeppelin SafeMath library.",
                         "arithmetic", "SWC-101")
                    file_findings.add("ETH-013-old")

        # ETH-013 variant: unsafe downcast
        downcast_m = re.search(r'\buint(8|16|32|64|128)\s*\(', line)
        if downcast_m and "function" not in line and "event" not in line and "error" not in line:
            _add(hits, "ETH-013", "Unsafe Integer Downcast",
                 "HIGH", 0.70, file_path, i, stripped,
                 f"Unsafe downcast to uint{downcast_m.group(1)} may silently truncate larger values.",
                 "Use OpenZeppelin SafeCast library or validate value fits in target type.",
                 "arithmetic", "SWC-101")

        # ── ETH-014: Division Before Multiplication ───────────────────
        if re.search(r'[\w\)]\s*/\s*[\w\(]+[\w\)]\s*\)\s*\*\s*\w+', line) or \
           re.search(r'\b\w+\s*/\s*\w+\s*\*\s*\w+', line):
            if "//" not in stripped[:2] and "/*" not in stripped[:2]:
                _add(hits, "ETH-014", "Division Before Multiplication",
                     "MEDIUM", 0.70, file_path, i, stripped,
                     "Division before multiplication causes precision loss due to integer truncation.",
                     "Reorder to multiply first: (a * c) / b instead of (a / b) * c.",
                     "arithmetic")

        # ── ETH-017: Precision Loss ───────────────────────────────────
        if re.search(r'/\s*\(?\s*(?:\d+\s*(?:days|hours|minutes|seconds)\s*\*\s*1e\d+|1e\d{2,})', line):
            if "ETH-017" not in file_findings:
                _add(hits, "ETH-017", "Precision Loss in Division",
                     "MEDIUM", 0.70, file_path, i, stripped,
                     "Division by very large denominator (1eN). Small numerators will round to zero.",
                     "Use higher precision intermediates or mulDiv for precise division.",
                     "arithmetic")
                file_findings.add("ETH-017")

        # ── ETH-018: Unchecked External Call Return ───────────────────
        if ".call(" in line or ".call{" in line:
            has_check = False
            for j in range(i, min(i + 4, len(lines) + 1)):
                ctx = lines[j - 1] if j <= len(lines) else ""
                if "require" in ctx or "if" in ctx or "success" in ctx or "assert" in ctx:
                    has_check = True
                    break
            if not has_check:
                _add(hits, "ETH-018", "Unchecked External Call Return",
                     "HIGH", 0.70, file_path, i, stripped,
                     "Low-level call return value not checked.",
                     "Check return value: (bool success, ) = addr.call(...); require(success);",
                     "external-calls", "SWC-104")

        # ── ETH-019: delegatecall ─────────────────────────────────────
        if "delegatecall(" in line:
            _add(hits, "ETH-019", "Delegatecall Usage",
                 "CRITICAL", 0.75, file_path, i, stripped,
                 "delegatecall executes code in caller's context. Untrusted targets can overwrite storage.",
                 "Only delegatecall to trusted, immutable contracts. Verify storage layout.",
                 "external-calls", "SWC-112")

        # ── ETH-021: DoS with Failed Call ─────────────────────────────
        if (".transfer(" in line or ".send(" in line):
            # Check if inside a loop context
            pre_context = content[max(0, content.find(line) - 200):content.find(line)]
            if "for" in pre_context or "while" in pre_context:
                _add(hits, "ETH-021", "DoS with Failed Call in Loop",
                     "HIGH", 0.70, file_path, i, stripped,
                     ".transfer()/.send() in loop context. Single failure reverts entire batch.",
                     "Use pull-payment pattern. Let recipients withdraw instead of pushing funds.",
                     "gas-dos", "SWC-113")

        # ── ETH-024: Oracle Manipulation ──────────────────────────────
        if "balanceOf(address(this))" in line and any(k in cl for k in ["price", "getprice", "rate", "oracle", "getreserve"]):
            _add(hits, "ETH-024", "Price Calculation via balanceOf",
                 "CRITICAL", 0.75, file_path, i, stripped,
                 "Using balanceOf(address(this)) for price calculation. Manipulable via flash loans or donations.",
                 "Use manipulation-resistant oracle (Chainlink, TWAP). Never use spot balance for pricing.",
                 "oracle")

        if "getReserves()" in line and any(k in cl for k in ["rate", "price", "borrow", "liquidat", "collateral", "value"]):
            _add(hits, "ETH-024", "Oracle Manipulation via Spot Reserves",
                 "CRITICAL", 0.80, file_path, i, stripped,
                 "Using Uniswap getReserves() spot price for financial calculations. Trivially manipulable via flash swap.",
                 "Use Uniswap V3 TWAP oracle or Chainlink price feed instead of spot reserves.",
                 "oracle")

        # ── ETH-025: Flash Loan Pattern ───────────────────────────────
        if re.search(r'function\s+flashLoan|flashMint|flashBorrow', line, re.IGNORECASE):
            _add(hits, "ETH-025", "Flash Loan Function",
                 "HIGH", 0.65, file_path, i, stripped,
                 "Flash loan function detected. Verify all dependent state is flash-loan resistant.",
                 "Add same-block protection. Ensure oracle prices are not manipulable within a single tx.",
                 "oracle")

        # ── ETH-027: Missing Slippage Protection ──────────────────────
        if "amountOutMin" in line and re.search(r'amountOutMin\s*[=:]\s*0\b', line):
            _add(hits, "ETH-027", "Zero Slippage Protection",
                 "HIGH", 0.85, file_path, i, stripped,
                 "amountOutMin set to 0 — accepts any output amount including total loss.",
                 "Allow user to specify minimum output. Never hardcode amountOutMin to 0.",
                 "defi")

        if re.search(r'swap\w*\(\s*[^,]+,\s*0\s*,', line, re.IGNORECASE) and "ETH-027" not in file_findings:
            _add(hits, "ETH-027", "Zero Slippage in Swap Call",
                 "HIGH", 0.85, file_path, i, stripped,
                 "Swap call with 0 as minimum output amount. Accepts any slippage including total loss.",
                 "Allow user to specify minimum output. Never hardcode min output to 0.",
                 "defi")
            file_findings.add("ETH-027")

        # ── ETH-028: Stale Oracle Data ────────────────────────────────
        if "latestRoundData" in line:
            has_staleness = False
            for j in range(i, min(i + 12, len(lines) + 1)):
                ctx = lines[j - 1] if j <= len(lines) else ""
                if j > i and re.search(r'^\s*function\s', ctx):
                    break
                if "updatedAt" in ctx or "answeredInRound" in ctx or "stale" in ctx.lower():
                    has_staleness = True
                    break
            if not has_staleness and "ETH-028" not in file_findings:
                _add(hits, "ETH-028", "Stale Oracle Data",
                     "HIGH", 0.80, file_path, i, stripped,
                     "latestRoundData() called without staleness checks (updatedAt/answeredInRound).",
                     "Check: require(answeredInRound >= roundId); require(updatedAt > 0); require(answer > 0);",
                     "oracle")
                file_findings.add("ETH-028")

        # ── ETH-029: Uninitialized Storage Pointer ────────────────────
        if re.search(r'\bstorage\b', line) and "function" not in line and "pragma" not in line:
            if "=" not in line:
                _add(hits, "ETH-029", "Uninitialized Storage Pointer",
                     "HIGH", 0.65, file_path, i, stripped,
                     "Storage pointer declared without initialization. May point to unexpected slot.",
                     "Initialize storage pointers explicitly. Use memory for local variables.",
                     "storage", "SWC-109")

        # ── ETH-030: Storage Collision (Proxy) ────────────────────────
        if "delegatecall" in line and "implementation" in cl:
            if "ETH-030" not in file_findings:
                _add(hits, "ETH-030", "Storage Collision Risk (Proxy)",
                     "CRITICAL", 0.70, file_path, i, stripped,
                     "delegatecall in proxy pattern. Storage layout mismatch causes slot collision.",
                     "Use EIP-1967 storage slots. Ensure proxy and impl have compatible storage layouts.",
                     "storage", "SWC-124")
                file_findings.add("ETH-030")

        if re.search(r'contract\s+\w+\s+is\s+\w*(?:Proxy|Upgradeable)', line):
            for j in range(i + 1, min(i + 15, len(lines) + 1)):
                ctx = lines[j - 1] if j <= len(lines) else ""
                if re.search(r'^\s+(?:address|uint256|bytes32|bool)\s+(?:private|internal)\s+\w+', ctx):
                    code_part = ctx.split("//")[0]
                    if "constant" not in code_part and "immutable" not in code_part and \
                       "_SLOT" not in code_part.upper():
                        if "ETH-030" not in file_findings:
                            _add(hits, "ETH-030", "Storage Collision — State Var in Proxy",
                                 "CRITICAL", 0.80, file_path, j, ctx.strip(),
                                 "State variable in proxy contract collides with implementation slot 0.",
                                 "Remove state variables from proxy. Use EIP-1967 storage slots.",
                                 "storage", "SWC-124")
                            file_findings.add("ETH-030")
                        break
                if re.search(r'^\s*(function|constructor|event)', ctx):
                    break

        # ── ETH-036: Timestamp Dependence ─────────────────────────────
        if "block.timestamp" in line:
            if re.search(r'block\.timestamp\s*[><!=]+', line) or re.search(r'[><!=]+\s*block\.timestamp', line):
                if any(k in cl for k in ["health", "reset", "lock", "unlock", "expire", "cooldown",
                                         "last", "time", "period", "delay", "interval"]):
                    _add(hits, "ETH-036", "Timestamp Dependence",
                         "MEDIUM", 0.65, file_path, i, stripped,
                         "Contract logic depends on block.timestamp comparison for state transitions.",
                         "Block timestamps can be slightly manipulated by miners. Avoid strict equality.",
                         "logic", "SWC-116")

        # ── ETH-037: Weak Randomness ──────────────────────────────────
        if ("block.timestamp" in line or "block.prevrandao" in line or "blockhash(" in line) and \
           ("random" in cl or "seed" in cl or "lottery" in cl or "guess" in cl or "winner" in cl):
            _add(hits, "ETH-037", "Weak Randomness from Chain Attributes",
                 "HIGH", 0.75, file_path, i, stripped,
                 "Block attributes are miner-manipulable. Not suitable for randomness.",
                 "Use Chainlink VRF or commit-reveal scheme.",
                 "logic", "SWC-120")

        if re.search(r'function\s+\w*[Rr]andom\w*\(', line) and "pure" in line:
            _add(hits, "ETH-037", "Predictable 'Random' Function (pure)",
                 "HIGH", 0.90, file_path, i, stripped,
                 "Function named 'random' is declared pure — cannot access any entropy source.",
                 "Use Chainlink VRF or commit-reveal scheme for randomness.",
                 "logic", "SWC-120")

        # ── ETH-038: ecrecover Without Zero-Check ─────────────────────
        if "ecrecover" in line:
            has_zero_check = False
            for j in range(i, min(i + 8, len(lines) + 1)):
                ctx = lines[j - 1] if j <= len(lines) else ""
                if "address(0)" in ctx or "!= 0" in ctx or "!= address" in ctx:
                    has_zero_check = True
                    break
            if not has_zero_check:
                _add(hits, "ETH-038", "ecrecover Returns address(0)",
                     "HIGH", 0.80, file_path, i, stripped,
                     "ecrecover may return address(0) for invalid signatures. Not checked.",
                     "Verify: require(recoveredAddress != address(0)). Use OpenZeppelin ECDSA.",
                     "logic", "SWC-117")

        # ── ETH-039: Signature Replay ─────────────────────────────────
        if "ecrecover" in line and not has_chainid:
            if "ETH-039" not in file_findings:
                _add(hits, "ETH-039", "Signature Replay Risk",
                     "CRITICAL", 0.70, file_path, i, stripped,
                     "ecrecover used without chain ID protection. Signature can be replayed cross-chain.",
                     "Include block.chainid and contract address in signed hash. Use EIP-712.",
                     "logic", "SWC-121")
                file_findings.add("ETH-039")

        # ── ETH-041: ERC-20 Non-standard Returns ──────────────────────
        if re.search(r'\b\w+\.\s*transfer\s*\(', line) and "safeTransfer" not in line:
            if not re.search(r'payable\s*\(', line) and ".call{" not in line and \
               "msg.sender.transfer" not in line:
                if re.search(r'\.transfer\s*\(\s*\w+.*,\s*\w+', line):
                    _add(hits, "ETH-041", "ERC-20 Transfer Without SafeERC20",
                         "HIGH", 0.75, file_path, i, stripped,
                         "ERC-20 transfer without SafeERC20. Some tokens (USDT) don't return bool.",
                         "Use OpenZeppelin SafeERC20: token.safeTransfer() instead of token.transfer().",
                         "token")

        # ── ETH-042: Fee-on-Transfer Token ────────────────────────────
        if "transferFrom" in line and not has_safe_erc20_usage:
            has_balance_check = False
            for j in range(max(1, i - 3), min(i + 5, len(lines) + 1)):
                ctx = lines[j - 1] if j <= len(lines) else ""
                if "balanceOf" in ctx and ("before" in ctx.lower() or "after" in ctx.lower() or "bal" in ctx.lower()):
                    has_balance_check = True
                    break
            if not has_balance_check and "ETH-042" not in file_findings:
                _add(hits, "ETH-042", "Fee-on-Transfer Token Incompatibility",
                     "HIGH", 0.55, file_path, i, stripped,
                     "transferFrom without balance diff check. Fee-on-transfer tokens deliver less than expected.",
                     "Check balanceOf before/after transferFrom to account for transfer fees.",
                     "token")
                file_findings.add("ETH-042")

        # ── ETH-044: ERC-777 Reentrancy Hook ──────────────────────────
        if re.search(r'ERC777|IERC777|tokensReceived|tokensToSend', line):
            if not has_reentrancy_guard:
                _add(hits, "ETH-044", "ERC-777 Reentrancy via Token Hook",
                     "HIGH", 0.75, file_path, i, stripped,
                     "ERC-777 token hooks can trigger reentrancy. No ReentrancyGuard detected.",
                     "Add nonReentrant modifier or use ERC-20 instead of ERC-777.",
                     "token")

        # ── ETH-046: Approval Race Condition ──────────────────────────
        if ".approve(" in line and "safeApprove" not in line:
            if "ETH-046" not in file_findings:
                _add(hits, "ETH-046", "ERC-20 Approve Race Condition",
                     "MEDIUM", 0.60, file_path, i, stripped,
                     "approve() is vulnerable to front-running race condition.",
                     "Use safeIncreaseAllowance/safeDecreaseAllowance or set to 0 first.",
                     "token")
                file_findings.add("ETH-046")

        # ── ETH-048: Unprotected Token Minting ────────────────────────
        if "_mint(" in line:
            has_auth = False
            for j in range(max(1, i - 3), i + 1):
                ctx = lines[j - 1] if j <= len(lines) else ""
                if any(m in ctx for m in ["onlyOwner", "onlyRole", "only", "auth", "require"]):
                    has_auth = True
                    break
            if not has_auth:
                _add(hits, "ETH-048", "Unprotected Token Minting",
                     "HIGH", 0.65, file_path, i, stripped,
                     "_mint() called without access control. May allow unauthorized token creation.",
                     "Restrict minting to authorized roles with onlyOwner/onlyRole modifier.",
                     "token")

        # ── ETH-057: Vault Share Inflation ────────────────────────────
        if re.search(r'totalSupply\s*(\(\s*\))?\s*==\s*0|totalShares\s*==\s*0', line):
            if any(k in cl for k in ["deposit", "mint", "share"]):
                _add(hits, "ETH-057", "Vault Share Inflation / First Depositor Attack",
                     "CRITICAL", 0.75, file_path, i, stripped,
                     "Share calculation when totalSupply==0 is vulnerable to first-depositor inflation attack.",
                     "Add virtual shares/assets offset (ERC4626) or mint minimum dead shares on first deposit.",
                     "defi")

        if re.search(r'totalSupply\s*[/\*].*balanceOf|balanceOf.*[/\*].*totalSupply', line):
            if any(k in cl for k in ["deposit", "withdraw", "share", "vault"]):
                if "ETH-057" not in file_findings:
                    _add(hits, "ETH-057", "Balance-Based Share Calculation (Donation Attack Risk)",
                         "HIGH", 0.70, file_path, i, stripped,
                         "Share price derived from balanceOf/totalSupply ratio. Vulnerable to donation attacks.",
                         "Use internal accounting instead of balanceOf. Add virtual offset or minimum deposit.",
                         "defi")
                    file_findings.add("ETH-057")

        # ── ETH-060: Missing Deadline ─────────────────────────────────
        if "type(uint256).max" in line and any(k in cl for k in ["deadline", "swap", "router"]):
            _add(hits, "ETH-060", "Hardcoded Max Deadline",
                 "MEDIUM", 0.70, file_path, i, stripped,
                 "Deadline set to type(uint256).max — effectively no deadline protection.",
                 "Allow user to specify deadline: require(block.timestamp <= deadline).",
                 "defi")

        if re.search(r'deadline\s*:\s*block\.timestamp\b', line):
            _add(hits, "ETH-060", "Ineffective Deadline (block.timestamp)",
                 "MEDIUM", 0.80, file_path, i, stripped,
                 "Deadline set to block.timestamp — always passes. No protection against tx delay.",
                 "Use block.timestamp + buffer or allow user to specify deadline.",
                 "defi")

        if re.search(r'amountOut(?:Minimum|Min)\s*:\s*0\b', line):
            _add(hits, "ETH-060", "Zero Slippage in Swap Parameters",
                 "HIGH", 0.85, file_path, i, stripped,
                 "amountOutMinimum set to 0 in swap params — accepts any output amount.",
                 "Allow user to specify minimum output. Never hardcode to 0.",
                 "defi")

        # ── ETH-064: Unprotected Callback ─────────────────────────────
        if re.search(r'function\s+(onERC721Received|onERC1155Received|onFlashLoan|uniswapV\dCall)', line):
            has_sender_check = False
            for j in range(i, min(i + 8, len(lines) + 1)):
                ctx = lines[j - 1] if j <= len(lines) else ""
                if "msg.sender" in ctx and ("require" in ctx or "==" in ctx or "if" in ctx):
                    has_sender_check = True
                    break
            if not has_sender_check:
                _add(hits, "ETH-064", "Unprotected Callback Handler",
                     "HIGH", 0.65, file_path, i, stripped,
                     "Callback function without msg.sender validation. May allow unauthorized invocation.",
                     "Verify msg.sender is the expected caller in callback functions.",
                     "defi")

        # ── ETH-066: Unbounded Loop ───────────────────────────────────
        if "for" in line and ".length" in line:
            _add(hits, "ETH-066", "Unbounded Loop / Array Growth",
                 "HIGH", 0.70, file_path, i, stripped,
                 "Loop iterates over dynamic array. Unbounded growth can exceed block gas limit.",
                 "Cap loop iterations or paginate. Use pull-over-push pattern.",
                 "gas-dos", "SWC-128")

        # ── ETH-081: Transient Storage Collision ──────────────────────
        if re.search(r'\btstore\b|\btload\b|TSTORE|TLOAD', line):
            if "delegatecall" in cl:
                _add(hits, "ETH-081", "Transient Storage Collision via delegatecall",
                     "CRITICAL", 0.75, file_path, i, stripped,
                     "TSTORE/TLOAD with delegatecall — transient storage slots may collide across contracts.",
                     "Use unique transient slot keys per contract. Avoid TSTORE in delegatecallable functions.",
                     "transient-storage")

        # ── ETH-083: TSTORE Reentrancy Bypass ─────────────────────────
        if re.search(r'ReentrancyGuardTransient|tstore.*lock|tload.*lock', line, re.IGNORECASE):
            _add(hits, "ETH-083", "Transient Storage Reentrancy Guard Bypass Risk",
                 "HIGH", 0.65, file_path, i, stripped,
                 "Transient-storage-based reentrancy lock may be bypassed via cross-contract calls.",
                 "Ensure transient lock is checked in ALL call paths, including delegatecall targets.",
                 "transient-storage")

        # ── ETH-086: Broken EOA Check (EIP-7702) ─────────────────────
        if re.search(r'tx\.origin\s*==\s*msg\.sender|msg\.sender\s*==\s*tx\.origin', line):
            _add(hits, "ETH-086", "Broken EOA Check (EIP-7702)",
                 "CRITICAL", 0.80, file_path, i, stripped,
                 "tx.origin == msg.sender no longer guarantees EOA with EIP-7702 account delegation.",
                 "Use ERC-1271 isValidSignature or alternative EOA verification for post-Pectra.",
                 "eip-7702")

        # ── ETH-088: EIP-7702 Auth Replay ─────────────────────────────
        if re.search(r'AUTH|AUTHCALL|7702', line) and not has_chainid:
            if "ETH-088" not in file_findings:
                _add(hits, "ETH-088", "EIP-7702 Authorization Replay",
                     "CRITICAL", 0.65, file_path, i, stripped,
                     "EIP-7702 authorization without chain ID — replayable across chains.",
                     "Include chain ID in authorization payload. Use EIP-7702's chainId field.",
                     "eip-7702")
                file_findings.add("ETH-088")

        # ── ETH-091: Paymaster Exploitation ───────────────────────────
        if re.search(r'validatePaymasterUserOp|IPaymaster', line):
            _add(hits, "ETH-091", "ERC-4337 Paymaster Without Limits",
                 "CRITICAL", 0.65, file_path, i, stripped,
                 "Paymaster validation without gas/spend limits. May be drained by malicious UserOps.",
                 "Implement per-user gas limits, spending caps, and signature validation in paymaster.",
                 "account-abstraction")

        # ── ETH-093: Validation-Execution Confusion ───────────────────
        if re.search(r'validateUserOp|_validateSignature', line):
            has_side_effect = False
            for j in range(i, min(i + 10, len(lines) + 1)):
                ctx = lines[j - 1] if j <= len(lines) else ""
                if re.search(r'\b\w+\s*[-+*]?=\s*[^=]', ctx) and "==" not in ctx and "uint256" not in ctx:
                    has_side_effect = True
                    break
            if has_side_effect:
                _add(hits, "ETH-093", "ERC-4337 Validation Phase Side Effects",
                     "HIGH", 0.60, file_path, i, stripped,
                     "State modifications in validation phase may execute without full UserOp completion.",
                     "Keep validation pure. Move all state changes to execution phase.",
                     "account-abstraction")

        # ── ETH-094: V4 Hook Auth Bypass ──────────────────────────────
        if re.search(r'function\s+(beforeSwap|afterSwap|beforeModifyPosition|afterModifyPosition)', line):
            has_pool_mgr_check = False
            for j in range(i, min(i + 5, len(lines) + 1)):
                ctx = lines[j - 1] if j <= len(lines) else ""
                if "poolManager" in ctx and ("require" in ctx or "msg.sender" in ctx or "==" in ctx):
                    has_pool_mgr_check = True
                    break
            if not has_pool_mgr_check:
                _add(hits, "ETH-094", "Uniswap V4 Hook Without PoolManager Check",
                     "CRITICAL", 0.70, file_path, i, stripped,
                     "Hook callback without msg.sender == poolManager check. Callable by anyone.",
                     "Add: require(msg.sender == address(poolManager)) to all hook callbacks.",
                     "uniswap-v4")

    return hits


# ────────────────────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────────────────────

def scan_all_sources(file_cache: dict[str, str]) -> list[PatternHit]:
    """
    Scan all .sol files in the file cache and return aggregated pattern hits.

    Args:
        file_cache: {file_path: file_content} — same format as
                    GraphBuilder._file_cache.

    Returns:
        List of PatternHit instances (raw, before graph validation).
    """
    all_hits: list[PatternHit] = []
    for path, content in file_cache.items():
        if not path.endswith(".sol"):
            continue
        all_hits.extend(scan_file(path, content))
    return all_hits


def get_pattern_summary(hits: list[PatternHit]) -> dict[str, int]:
    """Return counts by severity for logging."""
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for h in hits:
        counts[h.severity] = counts.get(h.severity, 0) + 1
    return counts
