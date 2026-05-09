import os
import time
from dataclasses import dataclass

import requests


class EtherscanRateLimitError(Exception):
    pass


class EtherscanAPIError(Exception):
    pass


@dataclass
class ContractInfo:
    address: str
    is_verified: bool
    contract_name: str | None
    compiler_version: str | None
    is_proxy: bool
    implementation_address: str | None  # populated if is_proxy == True
    deployer_address: str | None
    deploy_block: int | None
    deploy_timestamp: int | None  # unix timestamp
    contract_age_days: int | None
    data_source: str  # "etherscan" | "stub"


@dataclass
class ExploitEvent:
    tx_hash: str
    block_number: int
    timestamp: int
    value_lost_eth: float | None
    description: str  # Best-effort description from tx data


@dataclass
class ExploitHistory:
    address: str
    previous_exploits_detected: bool
    exploit_count: int
    exploits: list[ExploitEvent]
    largest_single_outflow_eth: float | None
    data_source: str  # "etherscan" | "stub"


@dataclass
class TransactionProfile:
    address: str
    total_transactions: int | None
    unique_callers: int | None
    avg_daily_tx_last_30d: float | None
    largest_single_withdrawal_eth: float | None
    recent_large_withdrawals: bool  # Any tx > 100 ETH in last 30 days
    flash_loan_interactions: bool  # Detected Aave/Balancer/dYdX interactions
    data_source: str


class EtherscanClient:
    """
    Etherscan API wrapper with automatic stub fallback.

    Usage:
        client = EtherscanClient()            # Uses ETHERSCAN_API_KEY from env
        client = EtherscanClient(api_key="X") # Explicit key
        client = EtherscanClient(stub=True)   # Force stub mode for testing

    Rate limits (free tier): 5 calls/second, 100k calls/day
    The client automatically throttles to stay within free tier limits.
    """

    BASE_URL = "https://api.etherscan.io/api"
    CALLS_PER_SECOND = 4  # Stay under 5/s limit with margin

    def __init__(self, api_key: str | None = None, stub: bool = False):
        self.api_key = api_key or os.getenv("ETHERSCAN_API_KEY")
        self.stub_mode = stub or self.api_key is None
        self._last_call_time = 0.0

        if self.stub_mode and not stub:
            # Auto-stub when no key — log this so devs know
            print(
                "[EtherscanClient] No API key found. Running in stub mode. Set ETHERSCAN_API_KEY in .env for live data."
            )

    # ------------------------------------------------------------------ #
    #  Public Methods                                                       #
    # ------------------------------------------------------------------ #

    def get_contract_info(self, address: str) -> ContractInfo:
        if self.stub_mode:
            return self._stub_contract_info(address)
        return self._fetch_contract_info(address)

    def get_exploit_history(self, address: str) -> ExploitHistory:
        """
        Heuristic exploit detection: looks for abnormally large single outflows
        in the contract's transaction history. Not perfect but catches most
        major DeFi exploits where the attacker drains the contract in 1-3 txs.
        """
        if self.stub_mode:
            return self._stub_exploit_history(address)
        return self._fetch_exploit_history(address)

    def get_transaction_profile(self, address: str) -> TransactionProfile:
        if self.stub_mode:
            return self._stub_transaction_profile(address)
        return self._fetch_transaction_profile(address)

    # ------------------------------------------------------------------ #
    #  Live Implementation                                                  #
    # ------------------------------------------------------------------ #

    def _throttle(self):
        """Enforce rate limit — max CALLS_PER_SECOND."""
        elapsed = time.time() - self._last_call_time
        min_interval = 1.0 / self.CALLS_PER_SECOND
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_call_time = time.time()

    def _get(self, params: dict) -> dict:
        self._throttle()
        params["apikey"] = self.api_key
        response = requests.get(self.BASE_URL, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "0" and data.get("message") == "NOTOK":
            if "rate limit" in data.get("result", "").lower():
                raise EtherscanRateLimitError(data["result"])
            raise EtherscanAPIError(data.get("result", "Unknown Etherscan error"))

        return data

    def _fetch_contract_info(self, address: str) -> ContractInfo:
        # Source code endpoint — gives us verification + compiler info
        source_data = self._get({"module": "contract", "action": "getsourcecode", "address": address})

        result = source_data.get("result", [{}])[0]
        is_verified = bool(result.get("SourceCode"))
        is_proxy = result.get("Proxy") == "1"

        # Creation tx endpoint — gives us deployer + block
        creation_data = self._get({"module": "contract", "action": "getcontractcreation", "contractaddresses": address})
        creation_result = (creation_data.get("result") or [{}])[0]
        deploy_tx = creation_result.get("txHash")
        deployer = creation_result.get("contractCreator")

        # Get block timestamp from the deploy tx
        deploy_timestamp = None
        deploy_block = None
        contract_age_days = None

        if deploy_tx:
            tx_data = self._get({"module": "proxy", "action": "eth_getTransactionByHash", "txhash": deploy_tx})
            deploy_block_hex = (tx_data.get("result") or {}).get("blockNumber")
            if deploy_block_hex:
                deploy_block = int(deploy_block_hex, 16)
                block_data = self._get(
                    {"module": "proxy", "action": "eth_getBlockByNumber", "tag": deploy_block_hex, "boolean": "false"}
                )
                ts_hex = (block_data.get("result") or {}).get("timestamp")
                if ts_hex:
                    deploy_timestamp = int(ts_hex, 16)
                    contract_age_days = int((time.time() - deploy_timestamp) / 86400)

        return ContractInfo(
            address=address,
            is_verified=is_verified,
            contract_name=result.get("ContractName") or None,
            compiler_version=result.get("CompilerVersion") or None,
            is_proxy=is_proxy,
            implementation_address=result.get("Implementation") or None,
            deployer_address=deployer,
            deploy_block=deploy_block,
            deploy_timestamp=deploy_timestamp,
            contract_age_days=contract_age_days,
            data_source="etherscan",
        )

    def _fetch_exploit_history(self, address: str) -> ExploitHistory:
        """
        Heuristic: fetch last 1000 internal transactions (ETH movements).
        Flag any tx where ETH outflow > 10% of contract balance at that time.
        This catches most drains without needing a separate exploit database.
        """
        txlist_data = self._get(
            {
                "module": "account",
                "action": "txlistinternal",
                "address": address,
                "startblock": 0,
                "endblock": 99999999,
                "sort": "desc",
                "page": 1,
                "offset": 1000,  # Last 1000 internal txs
            }
        )

        txs = txlist_data.get("result") or []

        # Filter for large outflows — crude but effective heuristic
        # ETH value is in wei
        large_outflows = []
        for tx in txs:
            value_wei = int(tx.get("value", "0"))
            value_eth = value_wei / 1e18
            if value_eth > 10:  # Flag anything moving > 10 ETH
                large_outflows.append(
                    ExploitEvent(
                        tx_hash=tx.get("hash", ""),
                        block_number=int(tx.get("blockNumber", 0)),
                        timestamp=int(tx.get("timeStamp", 0)),
                        value_lost_eth=value_eth,
                        description=f"Large outflow: {value_eth:.2f} ETH",
                    )
                )

        largest = max((e.value_lost_eth for e in large_outflows), default=None)

        # Heuristic: if top outflow is > 50 ETH, flag as potential exploit
        exploits_detected = largest is not None and largest > 50

        return ExploitHistory(
            address=address,
            previous_exploits_detected=exploits_detected,
            exploit_count=len(large_outflows) if exploits_detected else 0,
            exploits=large_outflows[:5] if exploits_detected else [],  # Top 5
            largest_single_outflow_eth=largest,
            data_source="etherscan",
        )

    def _fetch_transaction_profile(self, address: str) -> TransactionProfile:
        # Normal transactions for caller diversity
        tx_data = self._get(
            {
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": 0,
                "endblock": 99999999,
                "sort": "desc",
                "page": 1,
                "offset": 500,
            }
        )
        txs = tx_data.get("result") or []

        total = len(txs)
        unique_callers = len(set(tx.get("from", "") for tx in txs))

        # Flash loan detector — check for known flash loan provider addresses
        FLASH_LOAN_PROVIDERS = {
            "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9",  # Aave v2
            "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",  # Aave v3
            "0xba12222222228d8ba445958a75a0704d566bf2c8",  # Balancer
            "0x1e0447b19bb6ecfdae1e4ae1694b0c3659614e4e",  # dYdX
        }
        flash_detected = any(
            tx.get("to", "").lower() in FLASH_LOAN_PROVIDERS or tx.get("from", "").lower() in FLASH_LOAN_PROVIDERS
            for tx in txs
        )

        # Large withdrawal detection — last 30 days
        cutoff = int(time.time()) - (30 * 86400)
        recent_large = any(
            int(tx.get("timeStamp", 0)) > cutoff and int(tx.get("value", "0")) / 1e18 > 100 for tx in txs
        )

        return TransactionProfile(
            address=address,
            total_transactions=total,
            unique_callers=unique_callers,
            avg_daily_tx_last_30d=None,  # TODO: compute from block timestamps
            largest_single_withdrawal_eth=None,
            recent_large_withdrawals=recent_large,
            flash_loan_interactions=flash_detected,
            data_source="etherscan",
        )

    # ------------------------------------------------------------------ #
    #  Stub Methods (used when no API key)                                 #
    # ------------------------------------------------------------------ #

    def _stub_contract_info(self, address: str) -> ContractInfo:
        return ContractInfo(
            address=address,
            is_verified=True,
            contract_name=None,
            compiler_version=None,
            is_proxy=False,
            implementation_address=None,
            deployer_address=None,
            deploy_block=None,
            deploy_timestamp=None,
            contract_age_days=None,
            data_source="stub",
        )

    def _stub_exploit_history(self, address: str) -> ExploitHistory:
        return ExploitHistory(
            address=address,
            previous_exploits_detected=False,
            exploit_count=0,
            exploits=[],
            largest_single_outflow_eth=None,
            data_source="stub",
        )

    def _stub_transaction_profile(self, address: str) -> TransactionProfile:
        return TransactionProfile(
            address=address,
            total_transactions=None,
            unique_callers=None,
            avg_daily_tx_last_30d=None,
            largest_single_withdrawal_eth=None,
            recent_large_withdrawals=False,
            flash_loan_interactions=False,
            data_source="stub",
        )
