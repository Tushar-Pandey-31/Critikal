# Critikal Benchmarks

## SCONE Benchmark (Smart CONtract Exploitation)

**Source:** [safety-research/SCONE-bench](https://github.com/safety-research/SCONE-bench)

**Size:** 405 contracts from real DeFi exploits (DeFiHackLabs)

| Chain   | Count |
|---------|-------|
| BSC     | 222   |
| Mainnet | 177   |
| Base    | 6     |

Each case provides:
- `case_name` — human-readable exploit name (e.g. `cream`, `euler`)
- `chain` — `mainnet` or `bsc`
- `fork_block_number` — block to fork at (snapshot state pre-exploit)
- `target_contract_address` — the vulnerable contract

## How Critikal Targets SCONE

Unlike the SCONE eval harness (which uses a Docker + MCP agent), Critikal targets contracts by:

1. **Fetching source code** from Etherscan/BSCscan using the `target_contract_address`
2. **Running the full pipeline** — graph build → hotspot detection → jury → TestWriter
3. **Measuring** whether the known vulnerability class is detected and a PoC compiles

### Running a SCONE case

```bash
# Run on a specific SCONE case by address
poetry run python benchmarks/run_scone_case.py --case cream --chain mainnet

# Run the first 10 mainnet cases
poetry run python benchmarks/run_scone_case.py --chain mainnet --limit 10

# Run all 177 mainnet cases (slow — ~8-12 hours)
poetry run python benchmarks/run_scone_case.py --chain mainnet
```

### Etherscan API Key Required

Set `ETHERSCAN_API_KEY` and `BSCSCAN_API_KEY` in `.env` to enable source fetching.

## Known Benchmark Results

| Benchmark         | Cases | Detected  | PoC Pass  | Notes                   |
|-------------------|-------|-----------|-----------|-------------------------|
| Damn Vulnerable DeFi | 18 | 4/5 (80%) | 1/1 (100%) | NaiveReceiverPool PoC proven |
| SCONE (mainnet)   | TBD   | TBD       | TBD       | In progress             |
