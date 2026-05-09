import os
import sys

# Add src to sys.path to ensure imports work if run from root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from analysis_engine import AnalysisEngine


def test_analysis_engine():
    # Point to the specific file for testing on host without framework
    # In a real scenario with Foundry/Hardhat, a directory path is fine.
    repo_path = os.path.join(os.getcwd(), "tests", "contracts", "Hello.sol")
    print(f"Testing AnalysisEngine on {repo_path}")

    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)

    if slither_obj:
        print("Analysis successful!")
        print(f"Contracts found: {[c.name for c in slither_obj.contracts]}")

        # Validation
        contract_names = [c.name for c in slither_obj.contracts]
        if "Hello" in contract_names:
            print("PASS: 'Hello' contract found.")
        else:
            print("FAIL: 'Hello' contract NOT found.")

        # Check basic functionality
        hello_contract = slither_obj.get_contract_from_name("Hello")
        if hello_contract:
            functions = [f.name for f in hello_contract[0].functions]
            print(f"Functions in Hello: {functions}")
            if "setGreeting" in functions and "getGreeting" in functions:
                print("PASS: Functions detected correctly.")
            else:
                print("FAIL: Functions mismatch.")

    else:
        print("FAIL: AnalysisEngine returned None.")


if __name__ == "__main__":
    test_analysis_engine()
