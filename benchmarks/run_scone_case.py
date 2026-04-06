#!/usr/bin/env python3
"""
benchmarks/run_scone_case.py
────────────────────────────────────────────────────────────────────────────
Run Critikal against one or more SCONE benchmark cases.

Each SCONE case provides:
  - A chain (mainnet / bsc / base)
  - A block number to fork at (pre-exploit snapshot)
  - A target contract address containing the vulnerability

This script:
  1. Reads benchmarks/scone_benchmark.csv
  2. For the selected case(s), fetches verified source code from Etherscan/BSCscan
  3. Writes source to a temp folder and runs the Critikal pipeline via --dir
  4. Records detect/PoC results to benchmarks/scone_results.jsonl

Usage:
  # Single case by name
  poetry run python benchmarks/run_scone_case.py --case cream

  # First 10 mainnet cases
  poetry run python benchmarks/run_scone_case.py --chain mainnet --limit 10

  # All BSC cases
  poetry run python benchmarks/run_scone_case.py --chain bsc

  # Show all available cases
  poetry run python benchmarks/run_scone_case.py --list
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BENCH_CSV = Path(__file__).parent / "scone_benchmark.csv"
RESULTS_FILE = Path(__file__).parent / "scone_results.jsonl"


def load_cases():
    with open(BENCH_CSV) as f:
        return list(csv.DictReader(f))


def fetch_etherscan_source(address: str, chain: str, api_key: str | None) -> dict[str, str]:
    """Fetch verified source code using Etherscan API V2 (works for ETH, BSC, Base, etc.)

    Etherscan V2 uses a single key + chain ID:
      mainnet  → chainid=1
      bsc      → chainid=56
      base     → chainid=8453

    Returns a {filename: source_code} dict. Empty if unverified.
    """
    chain_ids = {
        "mainnet": "1",
        "bsc":     "56",
        "base":    "8453",
    }
    chain_id = chain_ids.get(chain, "1")

    params = {
        "chainid": chain_id,
        "module":  "contract",
        "action":  "getsourcecode",
        "address": address,
        "apikey":  api_key or "",
    }
    try:
        import urllib.request
        import urllib.parse
        # Etherscan V2 unified endpoint
        url = f"https://api.etherscan.io/v2/api?{urllib.parse.urlencode(params)}"
        print(f"  [SCONE] Fetching source: chain={chain} (id={chain_id}) addr={address}")
        with urllib.request.urlopen(url, timeout=30) as r:
            data = json.loads(r.read())
    except Exception as e:
        print(f"  [SCONE] Etherscan V2 fetch failed: {e}")
        return {}

    # Handle Etherscan error strings (e.g. "result": "Invalid API Key")
    if data.get("status") == "0":
        print(f"  [SCONE] Etherscan API Error: {data.get('result')}")
        return {}
        
    result = data.get("result", [{}])
    if not result or not isinstance(result, list) or not isinstance(result[0], dict):
        print(f"  [SCONE] Unexpected API response format")
        return {}

    entry = result[0]
    source_code = entry.get("SourceCode", "")
    contract_name = entry.get("ContractName", "Contract")

    if not source_code:
        print(f"  [SCONE] No verified source (unverified contract?)")
        return {}

    # Etherscan returns JSON-wrapped multi-file sources or single file
    def parse_source(entry):
        src = entry.get("SourceCode", "")
        cname = entry.get("ContractName", "Contract")
        if not src:
            return {}

        if src.startswith("{{"):
            try:
                inner = json.loads(src[1:-1])
                sources = inner.get("sources", {})
                return {path: content.get("content", "") for path, content in sources.items()}
            except json.JSONDecodeError:
                pass

        if src.startswith("{"):
            try:
                inner = json.loads(src)
                sources = inner.get("sources", {})
                if sources:
                    return {path: content.get("content", "") for path, content in sources.items()}
            except json.JSONDecodeError:
                pass

        return {f"{cname}.sol": src}

    # IMPORTANT: Auto-resolve proxies (crucial for SCONE tests like Cream/Euler)
    if entry.get("Proxy") == "1" and entry.get("Implementation"):
        impl_addr = entry.get("Implementation")
        print(f"  [SCONE] Auto-resolving proxy -> fetching implementation {impl_addr}")
        impl_sources = fetch_etherscan_source(impl_addr, chain, api_key)
        # Combine proxy source + impl source so we have the full picture
        combined = parse_source(entry)
        combined.update(impl_sources)
        return combined

    # Normal fetch without proxy
    return parse_source(entry)



def run_critikal_on_dir(src_dir: Path, case: dict, extra_env: dict | None = None) -> dict:
    """Run Critikal pipeline on a directory of .sol files.

    Returns a result dict with keys: detected, poc_pass, findings, error.
    """
    env = os.environ.copy()
    # Raise hotspot budget for benchmark runs to avoid missing bugs
    env.setdefault("HOTSPOT_BUDGET", "30")
    # Disable fuzzing / expensive extras for speed
    env.setdefault("FUZZ_ENABLED", "false")
    if extra_env:
        env.update(extra_env)

    cmd = [
        "poetry", "run", "python", "-m", "src.main",
        "--repo", str(src_dir),
    ]

    print(f"  [SCONE] Running: {' '.join(cmd)}")
    t0 = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=Path(__file__).parent.parent,  # critikal root
        )
        
        stdout_lines = []
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            stdout_lines.append(line)
            
        proc.wait(timeout=3600)
        elapsed = time.time() - t0
        stdout = "".join(stdout_lines)
        stderr = ""

        # Parse results from stdout
        detected = "Vulnerability" in stdout or "HIGH" in stdout or "CRITICAL" in stdout or "[CONFIRM]" in stdout
        # FIX: Old check matched "Exploit proven: False" log lines as a positive.
        # Now we check for the actual success markers only.
        poc_pass  = "[POC-PASS]" in stdout or "Exploit proven: True" in stdout
        # Count confirmed findings
        findings_count = stdout.count("[CONFIRM]")

        return {
            "case_name":      case["case_name"],
            "chain":          case["chain"],
            "address":        case["target_contract_address"],
            "block":          case["fork_block_number"],
            "detected":       detected,
            "poc_pass":       poc_pass,
            "findings_count": findings_count,
            "elapsed_s":      round(elapsed, 1),
            "return_code":    proc.returncode,
            "stdout_tail":    stdout[-2000:],
            "stderr_tail":    stderr[-1000:],
            "error":          None,
            "timestamp":      datetime.utcnow().isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {
            "case_name":      case["case_name"],
            "chain":          case["chain"],
            "address":        case["target_contract_address"],
            "block":          case["fork_block_number"],
            "detected":       False,
            "poc_pass":       False,
            "findings_count": 0,
            "elapsed_s":      600,
            "return_code":    -1,
            "stdout_tail":    "",
            "stderr_tail":    "",
            "error":          "TIMEOUT",
            "timestamp":      datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {
            "case_name":      case["case_name"],
            "chain":          case["chain"],
            "address":        case["target_contract_address"],
            "block":          case["fork_block_number"],
            "detected":       False,
            "poc_pass":       False,
            "findings_count": 0,
            "elapsed_s":      0,
            "return_code":    -1,
            "stdout_tail":    "",
            "stderr_tail":    "",
            "error":          str(e),
            "timestamp":      datetime.utcnow().isoformat(),
        }


def run_case(case: dict, api_key: str | None) -> dict:
    chain   = case["chain"]
    address = case["target_contract_address"]
    name    = case["case_name"]

    print(f"\n{'='*60}")
    print(f"  SCONE case: {name}  |  chain={chain}  |  {address}")
    print(f"{'='*60}")

    # 1. Fetch source via Etherscan V2 (single key for all chains)
    sources = fetch_etherscan_source(address, chain, api_key)

    if not sources:
        print(f"  [SCONE] ⚠  No verified source found for {name} ({address})")
        result = {
            "case_name": name, "chain": chain, "address": address,
            "block": case["fork_block_number"],
            "detected": False, "poc_pass": False, "findings_count": 0,
            "elapsed_s": 0, "return_code": -1,
            "stdout_tail": "", "stderr_tail": "",
            "error": "NO_SOURCE",
            "timestamp": datetime.utcnow().isoformat(),
        }
        _append_result(result)
        return result

    print(f"  [SCONE] Fetched {len(sources)} source file(s)")

    # 2. Write to tmp dir
    with tempfile.TemporaryDirectory(prefix=f"scone_{name}_") as tmp:
        tmp_path = Path(tmp)
        for filename, code in sources.items():
            # Ensure subdirs exist
            dest = tmp_path / filename.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(code, encoding="utf-8")

        # 3. Run Critikal
        result = run_critikal_on_dir(tmp_path, case)

    # 4. Record result
    print(f"\n  [SCONE] Result: detected={result['detected']}  poc_pass={result['poc_pass']}  "
          f"findings={result['findings_count']}  elapsed={result['elapsed_s']}s")
    _append_result(result)
    return result


def _append_result(result: dict):
    with open(RESULTS_FILE, "a") as f:
        f.write(json.dumps(result) + "\n")


def print_summary(results: list[dict]):
    total    = len(results)
    detected = sum(1 for r in results if r["detected"])
    poc      = sum(1 for r in results if r["poc_pass"])
    errors   = sum(1 for r in results if r.get("error"))
    print(f"\n{'='*60}")
    print(f"  SCONE BENCHMARK SUMMARY  ({total} cases)")
    print(f"{'='*60}")
    print(f"  Detected:    {detected}/{total}  ({100*detected//total if total else 0}%)")
    print(f"  PoC proven:  {poc}/{total}      ({100*poc//total if total else 0}%)")
    print(f"  Errors:      {errors}")
    print(f"  Results:     {RESULTS_FILE}")


def main():
    ap = argparse.ArgumentParser(description="Run Critikal on SCONE benchmark cases")
    ap.add_argument("--case",  help="Run a single case by name (e.g. cream)")
    ap.add_argument("--chain", default=None, choices=["mainnet","bsc","base"],
                    help="Filter by chain")
    ap.add_argument("--limit", type=int, default=None, help="Max cases to run")
    ap.add_argument("--list",  action="store_true", help="List all available cases")
    ap.add_argument("--skip-existing", action="store_true",
                    help="Skip cases already in scone_results.jsonl")
    args = ap.parse_args()

    cases = load_cases()

    if args.list:
        for row in cases:
            flag = ""
            if args.chain and row["chain"] != args.chain:
                flag = " (filtered)"
            print(f"  {row['case_name']:30s}  {row['chain']:10s}  {row['target_contract_address']}{flag}")
        return

    # Read already-done cases
    done_cases: set[str] = set()
    if args.skip_existing and RESULTS_FILE.exists():
        with open(RESULTS_FILE) as f:
            for line in f:
                try:
                    done_cases.add(json.loads(line)["case_name"])
                except Exception:
                    pass

    # Filter
    if args.case:
        target_cases = [c for c in cases if c["case_name"] == args.case]
        if not target_cases:
            print(f"Case '{args.case}' not found. Use --list to see all cases.")
            sys.exit(1)
    else:
        target_cases = cases
        if args.chain:
            target_cases = [c for c in target_cases if c["chain"] == args.chain]
        if done_cases:
            target_cases = [c for c in target_cases if c["case_name"] not in done_cases]
        if args.limit:
            target_cases = target_cases[:args.limit]

    print(f"[SCONE] Running {len(target_cases)} case(s)")

    # Etherscan V2 — one key works for mainnet + BSC + Base
    api_key = (
        os.environ.get("ETHERSCAN_API_KEY")
        or os.environ.get("BSCSCAN_API_KEY")
        or os.environ.get("ETHEREUM_API_KEY")
    )

    if not api_key:
        print("[SCONE] WARNING: No API key found — set ETHERSCAN_API_KEY in .env")
    else:
        print(f"[SCONE] Using Etherscan V2 API key: {api_key[:8]}...  (covers ETH + BSC + Base)")

    results = []
    for case in target_cases:
        result = run_case(case, api_key)
        results.append(result)
        # pause between cases to respect rate limits (5 req/s free tier)
        time.sleep(1)

    print_summary(results)




if __name__ == "__main__":
    main()
