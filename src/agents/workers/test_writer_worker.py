import asyncio
import os
import re
import logging
import shutil
import time
from pathlib import Path

logger = logging.getLogger(__name__)

from src.agents.base_worker import WorkerAgent, WorkerTask, WorkerOutput
from src.models.finding import Finding
from src.agents.workers.test_writer_sandbox import SandboxManager
from src.agents.workers.test_writer_prompts import TEST_WRITER_SYSTEM_PROMPT, TEST_WRITER_REAL_SOURCE_SYSTEM_PROMPT


class TestWriterWorker(WorkerAgent):
    MAX_ATTEMPTS = 6
    LLM_TIMEOUT = int(os.getenv("TEST_WRITER_LLM_TIMEOUT", "600"))  # 10 min default

    def __init__(self, llm_client, graph=None):
        self.llm_client = llm_client
        self.graph = graph

    def get_worker_type(self) -> str:
        return "test-writer"

    def _format_error_history(self, error_history: list[str]) -> str:
        if not error_history:
            return ""
        last_err = error_history[-1]
        import_fix_hint = ""
        if "src/src" in last_err or ("6275" in last_err and "not found" in last_err.lower()):
            import_fix_hint = "IMPORT FIX: Use project-root paths like \"src/core/X.sol\", NOT \"../src/core/X.sol\".\n\n"
        seen = set()
        key_errors = []
        for err in error_history[-3:]:
            lines = err.split("\n")
            for line in lines:
                line = line.strip()
                if not line or len(line) < 10:
                    continue
                if "Error (" in line or "ParserError" in line or "Compiler run failed" in line:
                    continue
                if "--> " in line or "|" in line:
                    if line not in seen:
                        seen.add(line)
                        key_errors.append(line)
                elif "error" in line.lower() or "Error" in line:
                    short = line[:120]
                    if short not in seen:
                        seen.add(short)
                        key_errors.append(line[:200])
            if len(key_errors) >= 15:
                break
        if not key_errors:
            return import_fix_hint + "\n\nPrevious attempts failed. Fix the errors from the last attempt.\n" + "\n---\n".join(error_history[-2:])
        return import_fix_hint + "\n\n=== FIX THESE ERRORS (from previous attempt) ===\n" + "\n".join(key_errors[-12:])

    def _extract_test_code(self, response: str) -> str:
        # Normalize line endings
        response = response.replace("\r\n", "\n")
        # Try fenced code blocks with language tag
        match = re.search(r"```(?:solidity|sol|Solidity)\s*\n(.*?)\n\s*```", response, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        # Try fenced code block without language tag
        match = re.search(r"```\s*\n(.*?)\n\s*```", response, re.DOTALL)
        if match:
            code = match.group(1).strip()
            if "pragma solidity" in code or "contract " in code:
                return code
        # Last resort: extract from pragma to last closing brace
        pragma_match = re.search(r"(pragma solidity.*)", response, re.DOTALL)
        if pragma_match:
            candidate = pragma_match.group(1).strip()
            # Find the last closing brace
            last_brace = candidate.rfind("}")
            if last_brace > 0:
                return candidate[:last_brace + 1].strip()
        # Raw response might be Solidity directly
        candidate = response.strip()
        solidity_markers = ("pragma solidity", "contract ", "function ", "import ")
        if any(marker in candidate for marker in solidity_markers):
            return candidate
        return ""

    def _has_exact_test_exploit(self, code: str) -> bool:
        return bool(re.search(r"\bfunction\s+test_exploit\s*\(", code))

    _AUTOCORRECT_IMPORT_RE = re.compile(
        r'import\s+"([^"]+)"\s*;|import\s+\{[^}]+\}\s+from\s+"([^"]+)"\s*;'
    )

    def _auto_correct_imports(
        self,
        test_code: str,
        sandbox: "SandboxManager",
        remappings: dict[str, str],
        collected_paths: list[str] | None = None,
    ) -> str:
        skip_prefixes = {"forge-std/", "ds-test/", "lib/"}
        skip_prefixes.update(alias for alias in remappings if alias.endswith("/"))
        corrections: list[tuple[str, str]] = []
        for m in self._AUTOCORRECT_IMPORT_RE.finditer(test_code):
            import_path = m.group(1) or m.group(2)
            if not import_path:
                continue
            if any(import_path.startswith(p) for p in skip_prefixes):
                continue
            candidate = sandbox.tmp_dir / import_path
            if candidate.is_file():
                continue
            filename = Path(import_path).name
            if collected_paths:
                matches_from_collected = [p for p in collected_paths if Path(p).name == filename]
                if matches_from_collected:
                    correct_path = matches_from_collected[0]
                    if correct_path != import_path:
                        corrections.append((import_path, correct_path))
                    continue
            matches = list(sandbox.tmp_dir.rglob(filename))
            valid = [f for f in matches if "lib" not in f.parts and "out" not in f.parts and "cache" not in f.parts]
            if not valid:
                continue
            best = valid[0]
            for v in valid:
                rel = str(v.relative_to(sandbox.tmp_dir)).replace("\\", "/")
                if rel.startswith("src/"):
                    best = v
                    break
            correct_path = str(best.relative_to(sandbox.tmp_dir)).replace("\\", "/")
            if correct_path != import_path:
                corrections.append((import_path, correct_path))
        for bad, good in corrections:
            test_code = test_code.replace(f'"{bad}"', f'"{good}"')
        if corrections:
            fixed = ", ".join(f"{b}->{g}" for b, g in corrections)
            logger.info(f"[TestWriter] Auto-corrected imports: {fixed}")
        return test_code

    _IMPORT_RE = re.compile(
        r'import\s+(?:"([^"]+)"|{[^}]+}\s+from\s+"([^"]+)")\s*;',
        re.MULTILINE
    )
    _MAX_DEP_FILES = 12
    _MAX_TOTAL_CHARS = 60_000
    _TARGET_FILE_CAP = 6000
    _INTERFACE_FILE_CAP = 4000
    _IMPL_FILE_CAP = 3000

    def _resolve_import_path(self, import_path: str, remappings: dict[str, str], repo: Path, from_file: Path | None = None) -> Path | None:
        path_str = import_path.strip()
        if not path_str:
            return None
        for alias, target in sorted(remappings.items(), key=lambda x: -len(x[0])):
            alias_stripped = alias.rstrip("/")
            if path_str.startswith(alias_stripped + "/") or path_str == alias_stripped:
                path_str = target.rstrip("/") + path_str[len(alias_stripped):]
                break
        if path_str.startswith("./") or path_str.startswith("../"):
            if not from_file or not from_file.parent:
                return None
            resolved = (from_file.parent / path_str).resolve()
            try:
                path_str = str(resolved.relative_to(repo.resolve())).replace("\\", "/")
            except ValueError:
                return None
        if path_str.startswith("lib/") or "/lib/" in path_str:
            return None
        candidate = repo / path_str
        if candidate.exists() and candidate.suffix == ".sol":
            return candidate
        return None

    def _parse_imports(self, content: str) -> list[str]:
        paths = []
        for m in self._IMPORT_RE.finditer(content):
            p1, p2 = m.group(1), m.group(2)
            p = (p1 or p2 or "").strip()
            if p and p not in paths:
                paths.append(p)
        return paths

    def _is_interface_file(self, content: str, path: str) -> bool:
        if "interface/" in path.replace("\\", "/"):
            return True
        return "interface " in content and "contract " not in content[:500]

    @staticmethod
    def _strip_solidity_comments(source: str) -> str:
        """
        Remove single-line (// ...) and multi-line (/* ... */) comments.
        Must happen before any regex analysis to avoid false positives from
        comment text like '// This is because abstract contract Foo...'.
        """
        # Remove /* ... */ blocks first (they can span lines)
        source = re.sub(r'/\*.*?\*/', ' ', source, flags=re.DOTALL)
        # Remove // ... to end of line
        source = re.sub(r'//[^\n]*', ' ', source)
        return source

    @staticmethod
    def _detect_pragma(sources: dict[str, str]) -> str | None:
        """
        Find the pragma solidity version used in the collected source files.
        Scans all files (not just the first) so we catch the target contract's
        pragma even when the first collected file is an interface with no pragma.

        Returns the raw version constraint string, e.g. '=0.7.6', '^0.8.17',
        or None if no pragma found.
        """
        pragma_re = re.compile(r'pragma\s+solidity\s+([^;]+);')
        for source in sources.values():
            m = pragma_re.search(source)
            if m:
                version_str = m.group(1).strip()
                # Skip very permissive ranges that don't pin a version
                if version_str not in ("", ">=0.5.0", ">=0.4.0"):
                    return version_str
        return None

    def _collect_repo_sources(self, finding: Finding, repo_path: str | None, remappings: dict[str, str], _lib_imports_out: set[str] | None = None) -> dict[str, str]:
        if not repo_path:
            return {}
        repo = Path(repo_path)
        if not repo.exists():
            return {}
        contract_name = finding.affected_contract
        target_path: Path | None = None
        for search_dir in ["src", "contracts", "."]:
            base = repo / search_dir
            if not base.exists():
                continue
            for sol_file in base.rglob("*.sol"):
                if "lib" in sol_file.parts:
                    continue
                try:
                    content = sol_file.read_text(encoding='utf-8', errors='replace')
                    if f"contract {contract_name}" in content or f"contract {contract_name} " in content:
                        target_path = sol_file
                        break
                except Exception:
                    continue
            if target_path:
                break
        if not target_path:
            return {}
        collected: dict[str, str] = {}
        to_visit: list[Path] = [target_path]
        seen: set[str] = set()
        total_chars = 0
        while to_visit and len(collected) < self._MAX_DEP_FILES and total_chars < self._MAX_TOTAL_CHARS:
            current = to_visit.pop(0)
            rel = str(current.relative_to(repo)).replace("\\", "/")
            if rel in seen:
                continue
            seen.add(rel)
            try:
                content = current.read_text(encoding='utf-8', errors='replace')
            except Exception:
                continue
            is_target = current == target_path
            is_interface = self._is_interface_file(content, rel)
            cap = self._TARGET_FILE_CAP if is_target else (self._INTERFACE_FILE_CAP if is_interface else self._IMPL_FILE_CAP)
            if len(content) > cap:
                content = content[:cap] + "\n... [truncated]"
            collected[rel] = content
            total_chars += len(content)
            for imp in self._parse_imports(content):
                resolved = self._resolve_import_path(imp, remappings, repo, from_file=current)
                if resolved:
                    rel_resolved = str(resolved.relative_to(repo)).replace("\\", "/")
                    if rel_resolved not in seen:
                        if "interface/" in rel_resolved:
                            to_visit.insert(0, resolved)
                        else:
                            to_visit.append(resolved)
                elif _lib_imports_out is not None:
                    _lib_imports_out.add(imp)
        return collected

    def _collect_minimal_sources(self, finding: Finding, repo_path: str | None, remappings: dict[str, str], _lib_imports_out: set[str] | None = None) -> dict[str, str]:
        """BUG-004 fix: delegate to _collect_repo_sources with reduced limits instead of duplicating 60 lines."""
        # Temporarily reduce limits for a minimal collection
        saved_max_files = self._MAX_DEP_FILES
        saved_max_chars = self._MAX_TOTAL_CHARS
        try:
            self._MAX_DEP_FILES = 6
            self._MAX_TOTAL_CHARS = 30_000
            return self._collect_repo_sources(finding, repo_path, remappings, _lib_imports_out=_lib_imports_out)
        finally:
            self._MAX_DEP_FILES = saved_max_files
            self._MAX_TOTAL_CHARS = saved_max_chars

    def _get_repo_file_manifest(self, repo_path: str | None) -> list[str]:
        if not repo_path:
            return []
        repo = Path(repo_path)
        if not repo.exists():
            return []
        paths: list[str] = []
        for d in ["src", "contracts", "."]:
            base = repo / d
            if not base.exists():
                continue
            for f in base.rglob("*.sol"):
                if "lib" in f.parts:
                    continue
                rel = str(f.relative_to(repo)).replace("\\", "/")
                if rel not in paths:
                    paths.append(rel)
        return sorted(paths)

    def _generate_import_cheatsheet(self, real_sources: dict[str, str], lib_imports: set[str] | None = None) -> str:
        lines: list[str] = ['import "forge-std/Test.sol";']
        seen: set[str] = {"forge-std/Test.sol"}
        for path in real_sources:
            if path not in seen:
                seen.add(path)
                lines.append(f'import "{path}";')
        if lib_imports:
            for imp in sorted(lib_imports):
                if imp not in seen:
                    seen.add(imp)
                    lines.append(f'import "{imp}";')
        return "\n".join(lines)

    @staticmethod
    def _parse_toml_remappings(content: str) -> dict[str, str]:
        # Try stdlib tomllib first (Python 3.11+), fall back to manual parsing
        try:
            import tomllib
            data = tomllib.loads(content)
            raw_remappings = data.get("profile", {}).get("default", {}).get("remappings", [])
            if not raw_remappings:
                raw_remappings = data.get("remappings", [])
            remappings: dict[str, str] = {}
            for entry in raw_remappings:
                if isinstance(entry, str) and "=" in entry:
                    alias, target = entry.split("=", 1)
                    if alias.strip():
                        remappings[alias.strip()] = target.strip()
            return remappings
        except (ImportError, Exception):
            pass

        # Fallback: manual line-by-line parsing for Python < 3.11
        remappings: dict[str, str] = {}
        in_remappings = False
        for line in content.splitlines():
            stripped = line.strip()
            if not in_remappings:
                if "remappings" in stripped and "=" in stripped:
                    in_remappings = True
                    after_eq = stripped.split("=", 1)[1]
                    for entry in after_eq.replace("[", "").replace("]", "").split(","):
                        entry = entry.strip().strip('"').strip("'").strip()
                        if "=" in entry:
                            alias, target = entry.split("=", 1)
                            if alias.strip():
                                remappings[alias.strip()] = target.strip()
                    if "]" in after_eq:
                        break
                continue
            if stripped == "]" or stripped.startswith("]"):
                break
            if stripped.startswith("["):
                break
            entry = stripped.strip('",').strip("'").strip()
            if "=" in entry:
                alias, target = entry.split("=", 1)
                if alias.strip():
                    remappings[alias.strip()] = target.strip()
        return remappings

    def _get_remappings_from_repo(self, repo_path: str | None) -> dict[str, str]:
        if not repo_path:
            return {}
        repo = Path(repo_path)
        remap_file = repo / "remappings.txt"
        if remap_file.exists():
            remappings: dict[str, str] = {}
            for line in remap_file.read_text().splitlines():
                line = line.strip()
                if "=" in line:
                    alias, target = line.split("=", 1)
                    remappings[alias.strip()] = target.strip()
            return remappings
        toml_file = repo / "foundry.toml"
        if toml_file.exists():
            return self._parse_toml_remappings(toml_file.read_text())
        return {}

    def _find_real_source(self, finding: Finding, repo_path: str | None) -> dict[str, str]:
        return self._collect_repo_sources(finding, repo_path, {})

    def _detect_repo_contract_conflicts(self, repo_path: str | None) -> dict:
        """
        Pre-analyzes the repo ONCE before the first LLM attempt.

        Detects:
          - Naming conflicts: same contract name in >1 file → Error (2333)
          - Abstract contracts: cannot instantiate with `new X()` → Error (4614)

        Comments are stripped before analysis to prevent false positives from
        prose like '// This is because abstract contract Foo handles X...'.
        The regex is anchored to line-start to avoid matching mid-line identifiers.
        """
        if not repo_path:
            return {
                "naming_conflicts": [], "abstract_contracts": [],
                "conflict_warnings": "", "abstract_warnings": "",
            }

        repo = Path(repo_path)
        name_to_files: dict[str, list[str]] = {}
        abstract_contracts: list[str] = []

        # Anchored to line start: only matches actual Solidity contract declarations.
        # Group 1: optional 'abstract ' keyword. Group 2: contract identifier.
        contract_decl_re = re.compile(
            r'^\s*(abstract\s+)?contract\s+([A-Za-z_]\w*)\b',
            re.MULTILINE
        )
        # Forge-std base names that legitimately appear in every project
        skip_names = {
            "Test", "Script", "console", "console2",
            "stdError", "stdMath", "StdAssertions", "StdChains",
            "StdCheats", "StdUtils", "Vm", "DSTest",
        }

        for search_dir in ["src", "contracts", "."]:
            base = repo / search_dir
            if not base.exists():
                continue
            for sol_file in base.rglob("*.sol"):
                if "lib" in sol_file.parts or "node_modules" in sol_file.parts:
                    continue
                try:
                    raw = sol_file.read_text(encoding="utf-8", errors="replace")
                    # Strip comments BEFORE regex matching — prevents false hits from
                    # NatSpec, inline notes, or commented-out declarations.
                    stripped = self._strip_solidity_comments(raw)
                    rel = str(sol_file.relative_to(repo)).replace("\\", "/")
                    for m in contract_decl_re.finditer(stripped):
                        is_abstract = bool(m.group(1))
                        name = m.group(2)
                        if name in skip_names:
                            continue
                        name_to_files.setdefault(name, []).append(rel)
                        if is_abstract and name not in abstract_contracts:
                            abstract_contracts.append(name)
                except Exception:
                    continue

        conflicts = {n: f for n, f in name_to_files.items() if len(f) > 1}

        conflict_warnings = ""
        if conflicts:
            lines = [
                "=== NAMING CONFLICT WARNINGS ===",
                "The following contract names are defined in MULTIPLE files in this repo.",
                "Importing more than one causes Error (2333): 'Identifier already declared'.",
                "ONLY import ONE file per contract name. Prefer the path in IMPORT CHEAT SHEET.",
                "",
            ]
            for name, files in conflicts.items():
                lines.append(f"  CONTRACT '{name}' defined in:")
                for f in files:
                    lines.append(f"    - {f}")
                lines.append(f"  → Import ONLY ONE of the above for '{name}'.")
            conflict_warnings = "\n".join(lines)

        abstract_warnings = ""
        if abstract_contracts:
            lines = [
                "=== ABSTRACT CONTRACT WARNINGS ===",
                "These contracts are abstract — `new X(...)` will cause Error (4614).",
                "Do NOT instantiate them directly. Options:",
                "  a) Find a concrete subclass in AVAILABLE CONTRACTS and deploy that instead.",
                "  b) Write a minimal concrete subclass at FILE LEVEL before ExploitTest.",
                "",
            ]
            for name in abstract_contracts:
                lines.append(f"  - {name}")
            abstract_warnings = "\n".join(lines)

        return {
            "naming_conflicts": list(conflicts.keys()),
            "abstract_contracts": abstract_contracts,
            "conflict_warnings": conflict_warnings,
            "abstract_warnings": abstract_warnings,
        }

    def _fetch_rag_context(self, finding: Finding) -> str:
        from src.knowledge.rag_system import search_security_knowledge
        queries = [
            f"{finding.vulnerability_class} exploit Foundry test pattern",
            f"Solidity {finding.vulnerability_class} vulnerability proof of concept",
            "Foundry vm.prank vm.deal cheatcodes exploit test",
        ]
        if finding.hypothesis:
            queries.append(f"{finding.hypothesis[:80]} exploit")
        all_results = []
        for q in queries[:3]:
            results = search_security_knowledge(q, k=3)
            all_results.extend(results)
        if not all_results:
            return ""
        seen = set()
        lines = []
        for r in all_results[:5]:
            content = r.get("content", "")[:600]
            if content and content not in seen:
                seen.add(content)
                src = r.get("source", "Unknown")
                lines.append(f"--- Source: {src}\n{content}\n")
        return "\n=== SECURITY KNOWLEDGE (use for correct Solidity patterns) ===\n" + "\n".join(lines)

    def _fetch_error_rag_context(self, error_history: list[str]) -> str:
        if not error_history:
            return ""
        from src.knowledge.rag_system import search_security_knowledge
        last_err = error_history[-1]
        codes = re.findall(r"Warning \((\d+)\)|Error \((\d+)\)|error (\d+):", last_err)
        codes = [c for t in codes for c in t if c]
        phrases = []
        if "virtual modifier" in last_err or "8429" in last_err:
            phrases.append("Solidity virtual modifier deprecated fix")
        if "memory-safe-assembly" in last_err or "2424" in last_err:
            phrases.append("Solidity memory-safe-assembly Natspec deprecated fix")
        if "import" in last_err.lower() and "not found" in last_err.lower():
            phrases.append("Solidity import path Foundry remapping")
        if "6275" in last_err or "src/src" in last_err or ("not found" in last_err and "import" in last_err.lower()):
            phrases.append("Solidity Foundry import path project root src/core not ../src")
        if "Source" in last_err and "not found" in last_err:
            phrases.append("Solidity import project-root-relative path")
        if "function" in last_err.lower() and "not found" in last_err.lower():
            phrases.append("Solidity function signature Foundry test")
        for code in codes[:2]:
            phrases.append(f"Solidity compiler error {code} fix")
        all_results = []
        for q in phrases[:3]:
            results = search_security_knowledge(q, k=2)
            all_results.extend(results)
        if not all_results:
            return ""
        seen = set()
        lines = []
        for r in all_results[:5]:
            content = r.get("content", "")[:500]
            if content and content not in seen:
                seen.add(content)
                src = r.get("source", "Unknown")
                lines.append(f"--- {src}\n{content}\n")
        return "\n=== ERROR FIX HINTS (from RAG — apply to fix the build) ===\n" + "\n".join(lines)

    def _build_prompt(
        self,
        finding: Finding,
        relevant_code: dict[str, str],
        error_history: list[str],
        real_sources: dict[str, str] | None = None,
        remappings: dict[str, str] | None = None,
        contract_signatures: dict[str, str] | None = None,
        repo_manifest: list[str] | None = None,
        skip_rag: bool = False,
        import_cheatsheet: str | None = None,
        repo_conflicts: dict | None = None,
        target_pragma: str | None = None,
    ) -> list[dict[str, str]]:

        has_real_source = bool(real_sources)
        system_prompt = TEST_WRITER_REAL_SOURCE_SYSTEM_PROMPT if has_real_source else TEST_WRITER_SYSTEM_PROMPT
        error_context = self._format_error_history(error_history)

        # Conflict/abstract warnings go first so LLM reads them before any source
        conflict_block = ""
        if repo_conflicts and has_real_source:
            if repo_conflicts.get("conflict_warnings"):
                conflict_block += "\n\n" + repo_conflicts["conflict_warnings"] + "\n"
            if repo_conflicts.get("abstract_warnings"):
                conflict_block += "\n" + repo_conflicts["abstract_warnings"] + "\n"

        source_section = conflict_block

        # Pragma warning — pinned version must match across all imported files
        if target_pragma and has_real_source:
            source_section += (
                f"\n=== PRAGMA VERSION (MANDATORY) ===\n"
                f"The target contract uses: pragma solidity {target_pragma};\n"
                f"Your test file MUST start with exactly: pragma solidity {target_pragma};\n"
                f"Do NOT use ^0.8.0, ^0.8.17, or any other version. "
                f"Mismatched pragmas cause 'Found incompatible versions' build failure.\n\n"
            )

        if has_real_source:
            if import_cheatsheet:
                source_section += "\n\n=== IMPORT CHEAT SHEET (copy these verbatim, do NOT invent paths) ===\n"
                source_section += import_cheatsheet + "\n"
                source_section += "\nONLY use imports listed above. NEVER import from out/, cache/, or artifacts/.\n"
                source_section += "Do NOT use ../src/... — that causes 'src/src/...' when test is in src/test/.\n\n"

            first_path = list(real_sources.keys())[0] if real_sources else "src/core/Contract.sol"
            pragma_line = f"pragma solidity {target_pragma};" if target_pragma else "pragma solidity ^0.8.17;"
            source_section += "\n=== STARTER TEMPLATE (use this structure) ===\n"
            source_section += f'// {pragma_line}\n'
            source_section += f'// import "forge-std/Test.sol";\n'
            source_section += f'// import "{first_path}";\n'
            source_section += f'// contract ExploitTest is Test {{\n'
            source_section += f'//     function setUp() public {{ /* deploy real contracts */ }}\n'
            source_section += f'//     function test_exploit() public {{ /* attack logic */ }}\n'
            source_section += f'// }}\n\n'

            if repo_manifest:
                source_section += "\n=== AVAILABLE CONTRACTS IN REPO (import these real contracts, never mock) ===\n"
                for p in repo_manifest[:30]:
                    source_section += f"  {p}\n"
                source_section += "\n"

            if contract_signatures:
                source_section += "\n=== CONTRACT SIGNATURES (use these exact signatures) ===\n"
                for fn_name, sig in sorted(contract_signatures.items()):
                    source_section += f"  {fn_name}: {sig}\n"
                source_section += "\n"

            source_section += "\n=== REAL CONTRACT SOURCE FILES ===\n"
            source_section += "These are the ACTUAL source files. Import and deploy these real contracts.\n\n"
            for rel_path, code in real_sources.items():
                source_section += f"// File: {rel_path}\n{code}\n\n"

            if remappings:
                source_section += "\n=== FOUNDRY REMAPPINGS ===\n"
                source_section += "Use these import aliases:\n"
                for alias, target in remappings.items():
                    source_section += f"  {alias} => {target}\n"

        elif relevant_code:
            source_section += "\n\n=== CODE SNIPPETS FROM KNOWLEDGE GRAPH ===\n"
            if contract_signatures:
                source_section += "=== CONTRACT SIGNATURES ===\n"
                for fn_name, sig in sorted(contract_signatures.items()):
                    source_section += f"  {fn_name}: {sig}\n"
                source_section += "\n"
            source_section += "(Note: These are extracted snippets, not full source files. Synthesize mock contracts as needed.)\n\n"
            for node_id, code in relevant_code.items():
                source_section += f"--- Snippet: {node_id} ---\n{code}\n\n"

        rag_context = "" if skip_rag else self._fetch_rag_context(finding)
        error_rag = "" if skip_rag else (self._fetch_error_rag_context(error_history) if error_history else "")

        user_content = (
            f"Vulnerability Class: {finding.vulnerability_class}\n"
            f"Affected Contract: {finding.affected_contract}\n"
            f"Affected Function: {finding.affected_function}\n"
            f"Hypothesis: {finding.hypothesis}\n"
            f"Attack Path: {' -> '.join(finding.attack_path)}\n"
            f"Impact: {finding.impact}\n"
            f"{source_section}"
            f"{rag_context}\n"
            f"{error_rag}\n"
            f"{error_context}\n\n"
            "Generate a complete Foundry test that proves this vulnerability."
        )

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ]

    async def run(self, task: WorkerTask) -> WorkerOutput:
        finding = task.context.get("finding")
        if isinstance(finding, list):
            finding = finding[0] if finding else None
        if not finding or not isinstance(finding, Finding):
            print(f"  [TestWriter] ERROR: Missing or invalid finding in task context")
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                confidence=0,
                raw_output={"error": "Missing or invalid finding"}
            )

        relevant_code = task.context.get("relevant_code", {})
        repo_path = task.context.get("repo_path")
        contract_signatures = task.context.get("contract_signatures", {}) or {}

        print(f"\n{'='*70}")
        print(f"  [TestWriter] === START === {finding.affected_contract}::{finding.affected_function}")
        print(f"  [TestWriter] Vulnerability: {finding.vulnerability_class}  |  Confidence: {finding.confidence}")
        print(f"  [TestWriter] Repo path: {repo_path}")
        print(f"  [TestWriter] Relevant code snippets: {len(relevant_code)}  |  Contract signatures: {len(contract_signatures)}")

        remappings = self._get_remappings_from_repo(repo_path)
        if remappings:
            print(f"  [TestWriter] Loaded {len(remappings)} remappings from repo")

        lib_imports: set[str] = set()
        real_sources_full = self._collect_repo_sources(finding, repo_path, remappings, _lib_imports_out=lib_imports)
        real_sources_minimal = self._collect_minimal_sources(finding, repo_path, remappings, _lib_imports_out=lib_imports)
        repo_manifest = self._get_repo_file_manifest(repo_path) if repo_path else []

        import_cheatsheet = self._generate_import_cheatsheet(
            real_sources_full or real_sources_minimal, lib_imports,
        ) if (real_sources_full or real_sources_minimal) else None

        if real_sources_full:
            total_chars = sum(len(v) for v in real_sources_full.values())
            print(f"  [TestWriter] Collected FULL sources: {len(real_sources_full)} files ({total_chars} chars)")
            for p in list(real_sources_full.keys())[:8]:
                print(f"    - {p}  ({len(real_sources_full[p])} chars)")
            print(f"  [TestWriter] Collected MINIMAL sources: {len(real_sources_minimal)} files")
            logger.info(f"[TestWriter] Found real source + deps for {finding.affected_contract}: {len(real_sources_full)} files (minimal: {len(real_sources_minimal)})")
        else:
            print(f"  [TestWriter] No real source found for {finding.affected_contract} — using MOCK mode")
            logger.info(f"[TestWriter] No real source found for {finding.affected_contract}, using mock mode")

        if lib_imports:
            print(f"  [TestWriter] Lib imports detected: {sorted(lib_imports)[:10]}")
        if repo_manifest:
            print(f"  [TestWriter] Repo manifest: {len(repo_manifest)} .sol files")

        # Detect pragma by scanning ALL collected sources (not just the first file).
        sources_to_check = real_sources_full or real_sources_minimal
        target_pragma = self._detect_pragma(sources_to_check) if sources_to_check else None
        if target_pragma:
            print(f"  [TestWriter] Detected pragma: {target_pragma}")
            logger.info(f"[TestWriter] Detected target pragma: {target_pragma}")
        else:
            print(f"  [TestWriter] No pragma detected — LLM will use default")
            logger.info(f"[TestWriter] No pragma detected — LLM will use default")

        # Pre-analyze repo for naming conflicts and abstract contracts.
        repo_conflicts = self._detect_repo_contract_conflicts(
            repo_path if real_sources_full else None
        )
        if repo_conflicts["naming_conflicts"]:
            print(f"  [TestWriter] Naming conflicts: {repo_conflicts['naming_conflicts']}")
            logger.info(f"[TestWriter] Naming conflicts detected: {repo_conflicts['naming_conflicts']}")
        if repo_conflicts["abstract_contracts"]:
            print(f"  [TestWriter] Abstract contracts: {repo_conflicts['abstract_contracts']}")
            logger.info(f"[TestWriter] Abstract contracts detected: {repo_conflicts['abstract_contracts']}")

        attempts = 0
        error_history: list[str] = []
        compiled = False
        exploit_success = False
        test_code_generated = None
        test_logs = ""

        use_repo = repo_path if real_sources_full else None
        sandbox = SandboxManager(repo_path=use_repo)
        try:
            sandbox.setup_foundry_project()

            # EXTRA SAFETY: force forge install if forge-std is still missing
            if not (sandbox.tmp_dir / "lib" / "forge-std" / "src" / "Test.sol").exists():
                print(f"  [TestWriter] forge-std still missing after setup — forcing _ensure_foundry_deps()")
                logger.info("[TestWriter] forge-std missing — forcing lib/ copy")
                sandbox._ensure_foundry_deps()

            print(f"  [TestWriter] Starting attempt loop (max={self.MAX_ATTEMPTS}, LLM timeout={self.LLM_TIMEOUT}s)")

            while attempts < self.MAX_ATTEMPTS:
                attempts += 1
                print(f"\n  [TestWriter] ── Attempt {attempts}/{self.MAX_ATTEMPTS} ──")
                sources_for_attempt = real_sources_full if attempts >= 3 else real_sources_minimal
                source_mode = "FULL" if attempts >= 3 else "MINIMAL"
                print(f"  [TestWriter] Source mode: {source_mode} ({len(sources_for_attempt) if sources_for_attempt else 0} files)")
                logger.info(f"[TestWriter] Attempt {attempts}/{self.MAX_ATTEMPTS} building prompt...")

                prompt = self._build_prompt(
                    finding,
                    relevant_code,
                    error_history,
                    real_sources=sources_for_attempt,
                    remappings=remappings,
                    contract_signatures=contract_signatures,
                    repo_manifest=repo_manifest,
                    skip_rag=(attempts == 1),
                    import_cheatsheet=import_cheatsheet,
                    repo_conflicts=repo_conflicts,
                    target_pragma=target_pragma,
                )
                prompt_chars = sum(len(m.get("content", "")) for m in prompt)
                print(f"  [TestWriter] Prompt built: {len(prompt)} messages, {prompt_chars} total chars (RAG={'skip' if attempts==1 else 'on'})")

                try:
                    print(f"  [TestWriter] Calling LLM at {time.strftime('%H:%M:%S')} (timeout={self.LLM_TIMEOUT}s)...")
                    logger.info(
                        f"[TestWriter] Attempt {attempts}/{self.MAX_ATTEMPTS} "
                        f"calling LLM for '{finding.affected_contract}::{finding.affected_function}' "
                        f"at {time.strftime('%H:%M:%S')} (timeout={self.LLM_TIMEOUT}s)..."
                    )
                    t_llm = time.time()
                    response = await asyncio.wait_for(
                        asyncio.to_thread(self.llm_client.invoke, prompt),
                        timeout=self.LLM_TIMEOUT
                    )
                    llm_elapsed = time.time() - t_llm
                    content = response.content if hasattr(response, "content") else str(response)
                    if isinstance(content, list):
                        content = "".join([c.get("text", "") if isinstance(c, dict) else str(c) for c in content])
                    print(f"  [TestWriter] LLM responded in {llm_elapsed:.1f}s ({len(content)} chars)")

                    test_code_generated = self._extract_test_code(content)
                    if not test_code_generated:
                        print(f"  [TestWriter] SKIP: No extractable Solidity code in LLM response")
                        print(f"  [TestWriter]   Response preview: {content[:150]}...")
                        logger.info(f"[TestWriter] Attempt {attempts}: LLM returned NO extractable Solidity code.")
                        logger.info(f"[TestWriter]   Response preview: {content[:200]}...")
                        error_history.append("No Solidity code returned by LLM")
                        continue

                    print(f"  [TestWriter] Extracted test code: {len(test_code_generated)} chars, {test_code_generated.count(chr(10))+1} lines")
                    funcs = re.findall(r'function\s+(\w+)\s*\(', test_code_generated)
                    print(f"  [TestWriter] Functions found: {funcs}")

                    if not self._has_exact_test_exploit(test_code_generated):
                        print(f"  [TestWriter] SKIP: Missing 'function test_exploit()' — retrying")
                        logger.info(f"[TestWriter] Attempt {attempts}: Missing 'function test_exploit()' in generated code.")
                        if funcs:
                            logger.info(f"[TestWriter]   Found functions: {funcs}")
                        error_history.append("Generated test must include function test_exploit() exactly.")
                        continue

                    test_code_generated = self._auto_correct_imports(
                        test_code_generated, sandbox, remappings,
                        collected_paths=list(sources_for_attempt.keys()) if sources_for_attempt else None,
                    )

                    test_path = sandbox.get_test_path()
                    test_file = f"{test_path}/ExploitTest.t.sol"
                    sandbox.write_test_file(test_file, test_code_generated)

                    # ── Compile & Test in one step ──────────────────
                    forge_cmd = (
                        "forge test --match-test test_exploit -vvv"
                        " --ignored-error-codes 8429 --ignored-error-codes 2424"
                    )
                    print(f"  [TestWriter] Running forge test...")
                    test_res = sandbox.run(forge_cmd)
                    test_logs = (test_res.stdout or "") + "\n" + (test_res.stderr or "")

                    # Distinguish compilation failure from test failure
                    is_compile_error = (
                        "Compiler run failed" in test_logs
                        or "Error (" in test_logs
                        or "ParserError" in test_logs
                    )

                    if not test_res.success and is_compile_error:
                        err = test_logs[:1200]
                        err_lines = [
                            ln for ln in err.splitlines()
                            if "Error" in ln or "error" in ln.lower()
                            or ln.strip().startswith("-->")
                            or ln.strip().startswith("|")
                        ]
                        short_err = "\n".join(err_lines[:15]) if err_lines else err[:400]
                        print(f"  [TestWriter] COMPILE FAILED (attempt {attempts}):")
                        for line in short_err.splitlines()[:10]:
                            print(f"    {line}")
                        logger.info(f"[TestWriter] Attempt {attempts} build error:\n{short_err}")
                        error_history.append(f"Build Failed:\n{short_err}")
                        compiled = False
                        out_dir = Path(sandbox.tmp_dir) / "out"
                        if out_dir.exists():
                            shutil.rmtree(out_dir, ignore_errors=True)
                        continue

                    compiled = True
                    passed_by_logs = "[PASS]" in test_logs or "exploit succeeded" in test_logs.lower()
                    exploit_success = test_res.success and passed_by_logs

                    print(f"  [TestWriter] COMPILED OK  |  forge_success={test_res.success}  |  [PASS] in logs={passed_by_logs}  |  exploit_success={exploit_success}")

                    if exploit_success:
                        print(f"  [TestWriter] EXPLOIT PROVEN on attempt {attempts}!")
                        # Show relevant test output
                        for line in test_logs.splitlines():
                            if "[PASS]" in line or "test_exploit" in line:
                                print(f"    {line.strip()}")
                        break

                    # Show why test failed even though it compiled
                    print(f"  [TestWriter] Test compiled but exploit FAILED")
                    fail_lines = [ln for ln in test_logs.splitlines() if "[FAIL]" in ln or "Error" in ln or "revert" in ln.lower()]
                    for line in fail_lines[:5]:
                        print(f"    {line.strip()}")
                    error_history.append(f"Test compiled but exploit check failed.\nLogs:\n{test_logs[:400]}")
                    logger.info(f"[TestWriter] Attempt {attempts}: Test compiled but exploit FAILED.")
                    logger.info(f"[TestWriter]   test_res.success={test_res.success}, passed_by_logs={passed_by_logs}")
                    if test_logs:
                        logger.info(f"[TestWriter]   Logs: {test_logs[:300]}...")

                except asyncio.TimeoutError:
                    msg = f"LLM call timed out after {self.LLM_TIMEOUT}s"
                    print(f"  [TestWriter] TIMEOUT: {msg}")
                    logger.info(f"[TestWriterWorker] {msg}")
                    error_history.append(msg)
                except Exception as e:
                    print(f"  [TestWriter] ERROR: {e}")
                    logger.info(f"[TestWriterWorker] LLM call failed: {e}")
                    error_history.append(str(e))

        finally:
            # BUG-005 fix: save exploit artifacts before cleanup on success
            if exploit_success and test_code_generated:
                try:
                    proven_dir = Path("proven_exploits")
                    proven_dir.mkdir(exist_ok=True)
                    task_slug = task.task_id.replace("/", "_").replace("::", "_")[:60]
                    artifact_path = proven_dir / f"{task_slug}.t.sol"
                    artifact_path.write_text(test_code_generated, encoding='utf-8')
                    print(f"  [TestWriter] Saved proven exploit artifact: {artifact_path}")
                except Exception as e:
                    print(f"  [TestWriter] Warning: could not save proven exploit artifact: {e}")
                    logger.info(f"[TestWriter] Warning: could not save proven exploit artifact: {e}")
            sandbox.cleanup()

        original_conf = getattr(finding, "confidence", 50)
        if compiled and exploit_success:
            adjustment = 60
        elif compiled:
            adjustment = 20
        else:
            adjustment = -40
        final_confidence = max(0, min(100, original_conf + adjustment))

        print(f"  [TestWriter] === RESULT === {finding.affected_contract}::{finding.affected_function}")
        print(f"  [TestWriter]   Attempts: {attempts}/{self.MAX_ATTEMPTS}")
        print(f"  [TestWriter]   Compiled: {compiled}  |  Exploit proven: {exploit_success}")
        print(f"  [TestWriter]   Confidence: {original_conf} -> {final_confidence} (adjustment={adjustment:+d})")
        print(f"  [TestWriter]   Used real source: {bool(real_sources_full)}")
        if error_history:
            print(f"  [TestWriter]   Last error: {error_history[-1][:150]}")
        print(f"{'='*70}\n")

        return WorkerOutput(
            worker_type=self.get_worker_type(),
            task_id=task.task_id,
            confidence=final_confidence,
            raw_output={
                "compiled": compiled,
                "exploit_success": exploit_success,
                "test_code": test_code_generated,
                "test_logs": test_logs,
                "attempts": attempts,
                "last_error": error_history[-1] if error_history else None,
                "used_real_source": bool(real_sources_full),
            }
        )