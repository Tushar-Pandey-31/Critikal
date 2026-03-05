import subprocess
import tempfile
import shutil
from dataclasses import dataclass
from pathlib import Path
import logging
import os
import stat

logger = logging.getLogger(__name__)

@dataclass
class Result:
    success: bool
    stdout: str
    stderr: str

class SandboxManager:
    """Manages an isolated temp environment for running Foundry tests."""

    def __init__(self, repo_path: str | None = None):
        self.tmp_dir: Path = Path(tempfile.mkdtemp())
        self.repo_path: Path | None = Path(repo_path) if repo_path else None

    def setup_foundry_project(self) -> None:
        print(f"  [Sandbox] setup_foundry_project  tmp={self.tmp_dir}  repo={self.repo_path}")
        if self.repo_path and self.repo_path.exists():
            print(f"  [Sandbox] Mode: REAL REPO  ({self.repo_path})")
            self._setup_from_real_repo()
        else:
            print(f"  [Sandbox] Mode: FORGE INIT  (no repo or repo path missing)")
            self._setup_forge_init()

    def _resolve_foundry_root(self, base: Path) -> Path:
        """BUG-009 fix: delegates to shared utility."""
        from src.utils.foundry_root import resolve_foundry_root
        resolved = resolve_foundry_root(base)
        if resolved != base:
            logger.info(f"[Sandbox] Foundry root resolved: {base} -> {resolved}")
        return resolved

    def _setup_from_real_repo(self) -> None:
        foundry_root = self._resolve_foundry_root(self.repo_path)
        print(f"  [Sandbox] Foundry root resolved: {foundry_root}")
        logger.info(f"[Sandbox] === SETUP START === tmp={self.tmp_dir} source={foundry_root}")

        # 1. Extract pristine remappings BEFORE the git submodules break in /tmp/
        remappings_content = ""
        if foundry_root and foundry_root.exists():
            try:
                proc = subprocess.run(
                    ["forge", "remappings"],
                    cwd=str(foundry_root),
                    capture_output=True,
                    text=True
                )
                if proc.returncode == 0:
                    remappings_content = proc.stdout
                    remap_count = len(remappings_content.splitlines())
                    print(f"  [Sandbox] Captured {remap_count} remappings from original repo")
                    logger.info(f"[Sandbox] Captured {remap_count} remappings from original repo.")
                else:
                    print(f"  [Sandbox] forge remappings failed (rc={proc.returncode}): {proc.stderr[:200]}")
            except Exception as e:
                print(f"  [Sandbox] WARNING: Failed to extract remappings: {e}")
                logger.warning(f"[Sandbox] Failed to extract remappings: {e}")

        # 2. Copy the repo (submodules will break, but we'll bypass that)
        print(f"  [Sandbox] Copying repo tree to {self.tmp_dir} (excluding out/cache/broadcast)...")
        logger.info(f"[Sandbox] Copying repo tree to {self.tmp_dir}...")
        shutil.copytree(
            str(foundry_root),
            str(self.tmp_dir),
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("out", "cache", "broadcast", "__pycache__")
        )
        print(f"  [Sandbox] Repo copy complete")
        logger.info("[Sandbox] copytree complete.")

        self._patch_foundry_toml()
        self._ensure_foundry_deps()
        self._try_restore_missing_deps()
        self._prune_broken_lib_deps()

        # 3. Write explicit remappings.txt to force Foundry to recognize lib/
        # BUG-003 fix: Always write live forge remappings when available.
        remap_file = self.tmp_dir / "remappings.txt"
        if remappings_content:
            remap_file.write_text(remappings_content)
            print(f"  [Sandbox] Wrote remappings.txt ({len(remappings_content.splitlines())} entries)")
            self._clean_remappings_for_pruned_libs(
                ["layerzero", "devtools", "LayerZero", "lz-evm"]
            )
        elif not remap_file.exists():
            remap_file.write_text("forge-std/=lib/forge-std/src/\nds-test/=lib/forge-std/lib/ds-test/src/\n")
            print(f"  [Sandbox] Wrote fallback remappings.txt (2 entries)")
        else:
            print(f"  [Sandbox] Using existing remappings.txt from repo")

        # Selectively clean test/ dir: remove only *.t.sol test files,
        # preserve mocks/helpers/fixtures that script/ or src/ may import.
        # Many repos store mock contracts in test/mock/ or test/helpers/ that
        # are referenced by non-test code (e.g. script/HelperConfig.s.sol).
        test_dir = self.tmp_dir / "test"
        if test_dir.exists():
            removed = 0
            for t_sol in list(test_dir.rglob("*.t.sol")):
                t_sol.unlink(missing_ok=True)
                removed += 1
            print(f"  [Sandbox] Cleaned {removed} existing test file(s), preserved mocks/helpers")
        else:
            test_dir.mkdir(parents=True, exist_ok=True)
            print(f"  [Sandbox] Created test/ directory")

        # Verify critical dependency
        forge_std_ok = (self.tmp_dir / "lib" / "forge-std" / "src" / "Test.sol").exists()
        print(f"  [Sandbox] forge-std/Test.sol present: {forge_std_ok}")
        logger.info(f"[Sandbox] Ready at {self.tmp_dir}, forge-std/Test.sol exists: {forge_std_ok}")

        if not forge_std_ok:
            src_lib = self.repo_path / "lib" if self.repo_path else None
            if src_lib and src_lib.exists():
                try:
                    contents = [p.name for p in src_lib.iterdir()]
                    print(f"  [Sandbox] CRITICAL: forge-std missing! Original lib/ contents: {contents}")
                    logger.warning(f"[Sandbox] CRITICAL: forge-std missing! Original lib/ contents: {contents}")
                except Exception:
                    print(f"  [Sandbox] CRITICAL: forge-std missing! Could not list original lib/")
                    logger.warning("[Sandbox] CRITICAL: forge-std missing! Could not list original lib/ contents.")
            else:
                print(f"  [Sandbox] CRITICAL: forge-std missing and original lib/ does not exist!")
                logger.warning("[Sandbox] CRITICAL: forge-std missing and original lib/ does not exist!")

        # List sandbox top-level contents for diagnostics
        try:
            top_level = sorted([p.name for p in self.tmp_dir.iterdir()])
            print(f"  [Sandbox] Sandbox root contents: {top_level}")
        except Exception:
            pass

    def _ensure_foundry_deps(self) -> None:
        """
        Ensures forge-std is present in the sandbox.
        Step 1: Copy whatever lib/ exists from original repo (may have solmate, ds-test, etc.)
        Step 2: Always check forge-std; install if missing (handles repos that don't include it).
        """
        # Step 1: Copy lib/ from original repo (may be partial — e.g. solmate has ds-test only)
        src_lib = self.repo_path / "lib" if self.repo_path else None
        if src_lib and src_lib.exists():
            print(f"  [Sandbox] Copying lib/ from original repo ({src_lib})...")
            logger.info(f"[Sandbox] Copying lib/ from {src_lib} ...")
            shutil.copytree(
                str(src_lib),
                str(self.tmp_dir / "lib"),
                dirs_exist_ok=True,
                symlinks=False
            )
            try:
                lib_contents = sorted([p.name for p in (self.tmp_dir / "lib").iterdir()])
                print(f"  [Sandbox] lib/ copied. Contents: {lib_contents}")
                logger.info(f"[Sandbox] lib/ copied. Contents: {lib_contents}")
            except Exception:
                print(f"  [Sandbox] lib/ copied (could not list contents)")
                logger.info("[Sandbox] lib/ copied (could not list contents).")
        else:
            print(f"  [Sandbox] No lib/ in original repo to copy")

        # Step 2: Always check forge-std and install if missing
        forge_std_test = self.tmp_dir / "lib" / "forge-std" / "src" / "Test.sol"
        if forge_std_test.exists():
            print(f"  [Sandbox] forge-std/Test.sol already present — skipping install")
            logger.info("[Sandbox] forge-std/Test.sol confirmed present.")
            return

        print(f"  [Sandbox] forge-std MISSING — installing via 'forge install'...")
        logger.info("[Sandbox] forge-std missing — installing via forge install...")
        if not (self.tmp_dir / ".git").exists():
            self.run("git init")
        result = self.run("forge install foundry-rs/forge-std --no-git --quiet")

        if forge_std_test.exists():
            print(f"  [Sandbox] forge-std/Test.sol confirmed after forge install")
            logger.info("[Sandbox] forge-std/Test.sol confirmed after forge install.")
        else:
            print(f"  [Sandbox] FAILED: forge-std still missing after install! stderr={result.stderr[:300] if result.stderr else 'none'}")
            logger.warning(
                f"[Sandbox] forge install finished but forge-std/Test.sol STILL missing! "
                f"stderr={result.stderr[:200] if result.stderr else 'none'}"
            )

    def _prune_broken_lib_deps(self) -> None:
        """
        After copying lib/, remove subdirectories whose own imports point at
        missing nested submodule paths. This prevents forge from failing to
        compile the entire project due to broken transitive deps.
        """
        lib_dir = self.tmp_dir / "lib"
        if not lib_dir.is_dir():
            return

        pruned: list[str] = []

        lz_protocol = lib_dir / "layerzero-v2" / "packages" / "layerzero-v2" / "evm" / "protocol"
        devtools = lib_dir / "devtools"

        if devtools.is_dir() and not lz_protocol.is_dir():
            print(f"  [Sandbox] Pruning lib/devtools — layerzero-v2 nested submodule missing")
            shutil.rmtree(str(devtools), ignore_errors=True)
            pruned.append("devtools")

        lz_alias = lib_dir / "LayerZero-v2"
        if lz_alias.is_dir() and not lz_protocol.is_dir():
            print(f"  [Sandbox] Pruning lib/LayerZero-v2 — nested submodule missing")
            shutil.rmtree(str(lz_alias), ignore_errors=True)
            pruned.append("LayerZero-v2")

        lz_v2 = lib_dir / "layerzero-v2"
        if lz_v2.is_dir() and not lz_protocol.is_dir():
            print(f"  [Sandbox] Pruning lib/layerzero-v2 — nested submodule missing")
            shutil.rmtree(str(lz_v2), ignore_errors=True)
            pruned.append("layerzero-v2")

        if pruned:
            self._clean_remappings_for_pruned_libs(
                ["layerzero", "devtools", "LayerZero", "lz-evm"]
            )

    def _clean_remappings_for_pruned_libs(self, pruned_prefixes: list[str]) -> None:
        """Remove remapping entries that reference pruned lib directories."""
        remappings_path = self.tmp_dir / "remappings.txt"
        if not remappings_path.exists():
            return
        lines = remappings_path.read_text().splitlines(keepends=True)
        cleaned = [l for l in lines if not any(p in l for p in pruned_prefixes)]
        if len(cleaned) != len(lines):
            remappings_path.write_text("".join(cleaned))
            print(f"  [Sandbox] Removed {len(lines) - len(cleaned)} broken remapping(s)")

    def _patch_foundry_toml(self) -> None:
        """Remove unknown profile sections from foundry.toml to prevent warnings."""
        import re as _re
        toml_path = self.tmp_dir / "foundry.toml"
        if not toml_path.exists():
            return
        content = toml_path.read_text()
        cleaned = _re.sub(
            r'\[profile\.dependencies\].*?(?=\[profile\.|$)', '', content, flags=_re.DOTALL
        )
        if cleaned != content:
            toml_path.write_text(cleaned)
            print(f"  [Sandbox] Patched foundry.toml — removed [profile.dependencies]")

    def _try_restore_missing_deps(self) -> None:
        """
        After repo copy, detect empty submodule dirs in lib/ and attempt to
        restore critical dependencies via forge install. This handles repos
        where git submodule clone timed out, leaving empty lib/ directories.
        """
        lib_dir = self.tmp_dir / "lib"
        if not lib_dir.is_dir():
            foundry_tomls = list(self.tmp_dir.rglob("foundry.toml"))
            for toml in foundry_tomls:
                candidate = toml.parent / "lib"
                if candidate.is_dir():
                    lib_dir = candidate
                    break
            else:
                return

        KNOWN_PACKAGES = {
            "openzeppelin-contracts": "OpenZeppelin/openzeppelin-contracts",
            "openzeppelin-contracts-upgradeable": "OpenZeppelin/openzeppelin-contracts-upgradeable",
            "forge-std": "foundry-rs/forge-std",
            "solmate": "transmissions11/solmate",
            "solady": "Vectorized/solady",
        }

        cwd_for_install = lib_dir.parent
        restored = 0

        for lib_name, forge_pkg in KNOWN_PACKAGES.items():
            lib_path = lib_dir / lib_name
            if not lib_path.is_dir():
                continue
            contents = [p.name for p in lib_path.iterdir() if p.name != ".git"]
            if len(contents) > 1:
                continue
            print(f"  [Sandbox] lib/{lib_name} is empty — attempting forge install {forge_pkg}")
            try:
                shutil.rmtree(str(lib_path), ignore_errors=True)
                result = subprocess.run(
                    ["forge", "install", forge_pkg, "--no-git", "--quiet"],
                    cwd=str(cwd_for_install),
                    capture_output=True, text=True, timeout=120,
                )
                if result.returncode == 0:
                    print(f"  [Sandbox] Restored lib/{lib_name} via forge install")
                    restored += 1
                else:
                    print(f"  [Sandbox] forge install {forge_pkg} failed: {result.stderr[:200]}")
            except FileNotFoundError:
                pass
            except subprocess.TimeoutExpired:
                print(f"  [Sandbox] forge install {forge_pkg} timed out")
            except Exception as e:
                print(f"  [Sandbox] forge install {forge_pkg} error: {e}")

        if restored:
            print(f"  [Sandbox] Restored {restored} missing dependencies")

        # Re-capture remappings from the foundry project now that deps exist
        if restored:
            try:
                proc = subprocess.run(
                    ["forge", "remappings"],
                    cwd=str(cwd_for_install),
                    capture_output=True, text=True, timeout=30,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    remap_file = self.tmp_dir / "remappings.txt"
                    remap_file.write_text(proc.stdout)
                    remap_count = len(proc.stdout.strip().splitlines())
                    print(f"  [Sandbox] Regenerated remappings.txt ({remap_count} entries)")
            except Exception:
                pass

    def _setup_forge_init(self) -> None:
        print(f"  [Sandbox] Running forge init (no repo mode)...")
        self.run("forge init --force --quiet")
        forge_std_ok = (self.tmp_dir / "lib" / "forge-std" / "src" / "Test.sol").exists()
        print(f"  [Sandbox] forge init complete. forge-std/Test.sol present: {forge_std_ok}")

    # ──────────────────────────────────────────────────────────────
    # ALL METHODS BELOW ARE UNCHANGED FROM YOUR ORIGINAL FILE
    # ──────────────────────────────────────────────────────────────

    def write_test_file(self, filename: str, content: str) -> None:
        file_path = self.tmp_dir / filename
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"  [Sandbox] Wrote test file: {file_path.relative_to(self.tmp_dir)}  ({len(content)} chars, {content.count(chr(10))+1} lines)")

    def read_source_file(self, relative_path: str) -> str | None:
        file_path = self.tmp_dir / relative_path
        if file_path.exists():
            try:
                return file_path.read_text(encoding='utf-8')
            except Exception as e:
                logger.warning(f"[Sandbox] Could not read {relative_path}: {e}")
        return None

    def find_contract_file(self, contract_name: str) -> str | None:
        search_dirs = ["src", "contracts", "."]
        for search_dir in search_dirs:
            base = self.tmp_dir / search_dir
            if not base.exists():
                continue
            for sol_file in base.rglob("*.sol"):
                try:
                    content = sol_file.read_text(encoding='utf-8', errors='replace')
                    if f"contract {contract_name}" in content:
                        return str(sol_file.relative_to(self.tmp_dir))
                except Exception:
                    continue
        return None

    def get_src_path(self) -> str:
        toml_file = self.tmp_dir / "foundry.toml"
        if toml_file.exists():
            content = toml_file.read_text()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("src ="):
                    val = line.split("=", 1)[1].strip().strip('"')
                    if val and (self.tmp_dir / val).exists():
                        return val
        return "src" if (self.tmp_dir / "src").exists() else "."

    def get_test_path(self) -> str:
        toml_file = self.tmp_dir / "foundry.toml"
        if toml_file.exists():
            content = toml_file.read_text()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("test ="):
                    val = line.split("=", 1)[1].strip().strip('"')
                    if val:
                        return val
        return "test"

    def get_remappings(self) -> dict[str, str]:
        remappings: dict[str, str] = {}
        remap_file = self.tmp_dir / "remappings.txt"
        if remap_file.exists():
            for line in remap_file.read_text().splitlines():
                line = line.strip()
                if "=" in line:
                    alias, target = line.split("=", 1)
                    remappings[alias.strip()] = target.strip()
            return remappings

        toml_file = self.tmp_dir / "foundry.toml"
        if toml_file.exists():
            from src.agents.workers.test_writer_worker import TestWriterWorker
            return TestWriterWorker._parse_toml_remappings(toml_file.read_text())
        return remappings

    def run(self, cmd: str) -> Result:
        import shlex
        import time as _time
        print(f"  [Sandbox] RUN: {cmd}")
        t0 = _time.time()
        try:
            proc = subprocess.run(
                shlex.split(cmd),
                cwd=str(self.tmp_dir),
                shell=False,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120
            )
            elapsed = _time.time() - t0
            result = Result(
                success=(proc.returncode == 0),
                stdout=proc.stdout,
                stderr=proc.stderr
            )
            status = "OK" if result.success else "FAIL"
            print(f"  [Sandbox] RUN result: {status}  rc={proc.returncode}  elapsed={elapsed:.1f}s  stdout={len(proc.stdout)} chars  stderr={len(proc.stderr)} chars")
            if not result.success and proc.stderr:
                stderr_preview = proc.stderr.strip().replace('\n', ' | ')[:300]
                print(f"  [Sandbox] stderr preview: {stderr_preview}")
            return result
        except subprocess.TimeoutExpired as e:
            elapsed = _time.time() - t0
            print(f"  [Sandbox] RUN TIMEOUT: {cmd}  after {elapsed:.1f}s")
            return Result(success=False, stdout="", stderr=f"Command timed out after {e.timeout} seconds.")
        except Exception as e:
            elapsed = _time.time() - t0
            print(f"  [Sandbox] RUN ERROR: {cmd}  {e}  after {elapsed:.1f}s")
            return Result(success=False, stdout="", stderr=str(e))

    def setup_bridge_mode_toml(self, deploy_paths: dict[str, str] | None = None,
                               target_contract: str | None = None,
                               target_source_path: str | None = None) -> tuple[dict[str, str], dict[str, dict]]:
        """
        Write a foundry.toml for bridge mode and pre-compile legacy contracts.

        Legacy (pre-0.6.9) contracts cannot be compiled by Foundry because it
        passes --allow-paths to solc, which old solc versions don't support.
        We compile them directly with the raw solc binary and embed the
        creation bytecode in the test scaffold (Foundry's vm.getCode()
        does not recognize manually placed artifacts in out/).

        target_source_path overrides deploy_paths resolution for the target
        contract (avoids name-collision misresolution).

        Returns (updated_deploy_paths, precompiled_data).
        precompiled_data maps contract_name -> dict with keys:
          bytecode, dep_bytecodes, ctor_inputs, deploy_path.
        """
        import json as _json

        # Bridge mode: legacy sources live in src/ but cannot be compiled by
        # modern Forge.  Move them aside so Forge never scans them, then
        # create an empty bridge_src/ for the foundry.toml `src` directive.
        src_dir = self.tmp_dir / "src"
        legacy_dir = self.tmp_dir / "legacy_src"
        if src_dir.exists() and any(src_dir.rglob("*.sol")):
            src_dir.rename(legacy_dir)
            print(f"  [Sandbox] Moved src/ → legacy_src/ to hide legacy files from Forge")
        elif not legacy_dir.exists():
            legacy_dir.mkdir(parents=True, exist_ok=True)

        bridge_src = self.tmp_dir / "bridge_src"
        bridge_src.mkdir(parents=True, exist_ok=True)

        updated_paths = dict(deploy_paths or {})
        precompiled_data: dict[str, dict] = {}

        if target_contract:
            if target_source_path:
                # Rewrite relative path to point at legacy_src/ if the file
                # was moved there (e.g. "src/Foo.sol" → "legacy_src/Foo.sol").
                if target_source_path.startswith("src/") or target_source_path.startswith("src\\"):
                    moved_path = "legacy_src/" + target_source_path[4:]
                    if (self.tmp_dir / moved_path).exists():
                        target_source_path = moved_path
                artifact_path = f"{target_source_path}:{target_contract}"
            elif deploy_paths:
                artifact_path = deploy_paths.get(target_contract)
            else:
                artifact_path = None

            if artifact_path:
                result = self._pre_compile_legacy_contract(artifact_path, target_contract)
                if result:
                    updated_paths[target_contract] = result["deploy_path"]
                    precompiled_data[target_contract] = result

        toml_content = """\
[profile.default]
src = "bridge_src"
test = "test"
out = "out"
libs = ["lib"]
ignored_error_codes = [8429, 2424, 3628, 5740]

[profile.default.fuzz]
runs = 10
"""
        toml_path = self.tmp_dir / "foundry.toml"
        toml_path.write_text(toml_content)
        print(f"  [Sandbox] Wrote bridge-mode foundry.toml (src=bridge_src, pre-compile mode)")
        return updated_paths, precompiled_data

    # ── Legacy pre-compilation helpers ──────────────────────────────

    def _pre_compile_legacy_contract(self, artifact_path: str, contract_name: str) -> dict | None:
        """
        Pre-compile a legacy contract using solc directly (bypasses Foundry's
        --allow-paths flag that old solc doesn't support).

        Returns dict with keys:
          deploy_path, bytecode, dep_bytecodes (dict name->hex),
          ctor_inputs (list of ABI input dicts).
        Or None on failure.
        """
        import json as _json, re as _re

        sol_rel, _, contract_label = artifact_path.partition(":")
        contract_label = contract_label or contract_name

        sol_file = self.tmp_dir / sol_rel
        if not sol_file.exists():
            logger.warning(f"[Sandbox] Pre-compile: source not found: {sol_rel}")
            return None

        pragma_version = self._detect_pragma_version(sol_file)
        if not pragma_version:
            logger.warning(f"[Sandbox] Pre-compile: no pragma found in {sol_rel}")
            return None

        solc_bin = self._find_solc_binary(pragma_version)
        if not solc_bin:
            print(f"  [Sandbox] Pre-compile: no solc binary for {pragma_version}, attempting install")
            solc_bin = self._install_solc(pragma_version)
            if not solc_bin:
                logger.warning(f"[Sandbox] Pre-compile: could not find/install solc {pragma_version}")
                return None

        try:
            proc = subprocess.run(
                [str(solc_bin), "--combined-json", "abi,bin", str(sol_file)],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as e:
            logger.warning(f"[Sandbox] solc execution failed: {e}")
            return None

        if proc.returncode != 0:
            print(f"  [Sandbox] solc compilation failed: {proc.stderr[:200]}")
            return None

        try:
            combined = _json.loads(proc.stdout)
        except _json.JSONDecodeError:
            logger.warning("[Sandbox] Pre-compile: could not parse solc output")
            return None

        target_key = None
        for key in combined.get("contracts", {}):
            if key.endswith(f":{contract_label}"):
                target_key = key
                break

        if not target_key:
            available = list(combined.get("contracts", {}).keys())
            logger.warning(f"[Sandbox] Pre-compile: contract {contract_label} not found. Available: {available}")
            return None

        cdata = combined["contracts"][target_key]
        abi = _json.loads(cdata["abi"]) if isinstance(cdata["abi"], str) else cdata["abi"]
        bytecode = cdata["bin"]
        if not bytecode.startswith("0x"):
            bytecode = "0x" + bytecode

        artifact_json = {
            "abi": abi,
            "bytecode": {"object": bytecode, "sourceMap": "", "linkReferences": {}},
            "deployedBytecode": {"object": "", "sourceMap": "", "linkReferences": {}},
            "methodIdentifiers": {},
            "rawMetadata": "",
            "metadata": {"compiler": {"version": pragma_version}},
            "id": 0,
        }

        out_dir = self.tmp_dir / "out" / sol_file.name
        out_dir.mkdir(parents=True, exist_ok=True)
        artifact_dest = out_dir / f"{contract_label}.json"
        artifact_dest.write_text(_json.dumps(artifact_json, indent=2))

        # Collect dependency bytecodes (other contracts in the same file)
        dep_bytecodes: dict[str, str] = {}
        for key, other_data in combined["contracts"].items():
            other_label = key.rsplit(":", 1)[-1]
            if other_label == contract_label:
                continue
            other_abi = _json.loads(other_data["abi"]) if isinstance(other_data["abi"], str) else other_data["abi"]
            other_bc = other_data["bin"]
            if not other_bc.startswith("0x"):
                other_bc = "0x" + other_bc
            other_artifact = {
                "abi": other_abi,
                "bytecode": {"object": other_bc, "sourceMap": "", "linkReferences": {}},
                "deployedBytecode": {"object": "", "sourceMap": "", "linkReferences": {}},
                "methodIdentifiers": {},
                "rawMetadata": "",
                "metadata": {"compiler": {"version": pragma_version}},
                "id": 0,
            }
            other_dest = out_dir / f"{other_label}.json"
            other_dest.write_text(_json.dumps(other_artifact, indent=2))
            other_bc_raw = other_bc[2:] if other_bc.startswith("0x") else other_bc
            if other_bc_raw:
                dep_bytecodes[other_label] = other_bc_raw

        # Extract constructor inputs from ABI
        ctor_inputs: list[dict] = []
        for entry in abi:
            if entry.get("type") == "constructor":
                ctor_inputs = entry.get("inputs", [])
                break

        # Extract hardcoded 20-byte addresses from source code
        try:
            source_text = sol_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            source_text = ""
        raw_addrs = set(_re.findall(r'(0x[0-9a-fA-F]{40})', source_text))
        hardcoded_addrs = [
            a for a in raw_addrs
            if a.lower().replace("0", "").replace("x", "")
        ]

        # Find address-setter functions in ABI (single address param,
        # name contains "set"/"log"/"init" — used for wiring deps)
        addr_setters: list[str] = []
        for entry in abi:
            if entry.get("type") != "function":
                continue
            inputs = entry.get("inputs", [])
            if len(inputs) == 1 and inputs[0].get("type") == "address":
                name = entry.get("name", "")
                if any(kw in name.lower() for kw in ("set", "log", "init")):
                    addr_setters.append(f"{name}(address)")

        deploy_path = f"{sol_file.name}:{contract_label}"
        bytecode_raw = bytecode[2:] if bytecode.startswith("0x") else bytecode
        n_deps = len(dep_bytecodes)
        n_ctor = len(ctor_inputs)
        n_hc = len(hardcoded_addrs)
        print(f"  [Sandbox] Pre-compiled {sol_rel} with solc {pragma_version} "
              f"({len(bytecode_raw)//2} bytes, {n_deps} deps, "
              f"{n_ctor} ctor params, {n_hc} hardcoded addrs)")

        return {
            "deploy_path": deploy_path,
            "bytecode": bytecode_raw,
            "dep_bytecodes": dep_bytecodes,
            "ctor_inputs": ctor_inputs,
            "hardcoded_addrs": hardcoded_addrs,
            "addr_setters": addr_setters,
        }

    def _detect_pragma_version(self, sol_file: Path) -> str | None:
        """Extract the minimum solc version from a pragma directive."""
        import re as _re
        try:
            content = sol_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None
        m = _re.search(r'pragma\s+solidity\s+[\^~>=<]*\s*(0\.\d+\.\d+)', content)
        return m.group(1) if m else None

    def _find_solc_binary(self, version: str) -> Path | None:
        """
        Find a compatible solc binary for the given version.
        Searches Foundry's SVM cache at ~/.local/share/svm/.
        For caret ranges (e.g. ^0.4.19), picks the highest installed
        version in the same minor range.
        """
        svm_dir = Path.home() / ".local" / "share" / "svm"
        if not svm_dir.is_dir():
            svm_dir = Path.home() / ".svm"
        if not svm_dir.is_dir():
            return None

        exact = svm_dir / version / f"solc-{version}"
        if exact.exists():
            return exact

        parts = version.split(".")
        if len(parts) != 3:
            return None
        major, minor, patch = parts
        min_patch = int(patch)

        candidates: list[tuple[int, Path]] = []
        for d in svm_dir.iterdir():
            if not d.is_dir():
                continue
            dparts = d.name.split(".")
            if len(dparts) != 3:
                continue
            if dparts[0] == major and dparts[1] == minor:
                try:
                    dp = int(dparts[2])
                except ValueError:
                    continue
                if dp >= min_patch:
                    solc = d / f"solc-{d.name}"
                    if solc.exists():
                        candidates.append((dp, solc))

        if candidates:
            candidates.sort(reverse=True)
            return candidates[0][1]
        return None

    def _install_solc(self, version: str) -> Path | None:
        """Attempt to install a solc version via svm or direct download."""
        svm_dir = Path.home() / ".local" / "share" / "svm"
        svm_dir.mkdir(parents=True, exist_ok=True)
        target_dir = svm_dir / version
        target_dir.mkdir(parents=True, exist_ok=True)
        target_bin = target_dir / f"solc-{version}"

        import platform as _platform
        system = _platform.system().lower()
        if system == "linux":
            url = f"https://github.com/ethereum/solidity/releases/download/v{version}/solc-static-linux"
        elif system == "darwin":
            url = f"https://github.com/ethereum/solidity/releases/download/v{version}/solc-macos"
        else:
            return None

        try:
            import urllib.request
            print(f"  [Sandbox] Downloading solc {version} from {url}...")
            urllib.request.urlretrieve(url, str(target_bin))
            target_bin.chmod(0o755)
            print(f"  [Sandbox] Installed solc {version}")
            return target_bin
        except Exception as e:
            logger.warning(f"[Sandbox] Failed to download solc {version}: {e}")
            return None

    def cleanup(self) -> None:
        print(f"  [Sandbox] Cleaning up {self.tmp_dir}")
        try:
            if self.tmp_dir.exists():
                def handle_remove_readonly(func, path, exc):
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                shutil.rmtree(self.tmp_dir, onerror=handle_remove_readonly)
                print(f"  [Sandbox] Cleanup complete")
        except Exception as e:
            print(f"  [Sandbox] Cleanup failed: {e}")
            logger.warning(f"Failed to cleanup temp dir {self.tmp_dir}: {e}")