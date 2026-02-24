import asyncio
import os
import re
import shutil
from pathlib import Path

from src.agents.base_worker import WorkerAgent, WorkerTask, WorkerOutput
from src.models.finding import Finding
from src.agents.workers.test_writer_sandbox import SandboxManager
from src.agents.workers.test_writer_prompts import TEST_WRITER_SYSTEM_PROMPT, TEST_WRITER_REAL_SOURCE_SYSTEM_PROMPT


class TestWriterWorker(WorkerAgent):
    MAX_ATTEMPTS = 6
    LLM_TIMEOUT = int(os.getenv("TEST_WRITER_LLM_TIMEOUT", "180"))

    def __init__(self, llm_client, graph=None):
        self.llm_client = llm_client
        self.graph = graph

    def get_worker_type(self) -> str:
        return "test-writer"

    def _format_error_history(self, error_history: list[str]) -> str:
        """Structure compiler errors for retry — extract key error lines, dedupe, limit size."""
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
        match = re.search(r"```(?:solidity|sol)\n(.*?)\n```", response, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        match = re.search(r"```\n(.*?)\n```", response, re.DOTALL)
        if match:
            return match.group(1).strip()
        # If the model responds with prose/chatter without fences, force a retry.
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
        """Validate import paths and auto-correct wrong ones.

        Prefers matches from *collected_paths* (the real dependency tree we
        already resolved) over a broad rglob of the sandbox.  This avoids
        mapping ``out/ERC20.sol`` to a local copy when the protocol actually
        uses the solmate version via remapping.
        """
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

            # 1) Prefer a match from the collected dependency paths
            if collected_paths:
                matches_from_collected = [
                    p for p in collected_paths if Path(p).name == filename
                ]
                if matches_from_collected:
                    correct_path = matches_from_collected[0]
                    if correct_path != import_path:
                        corrections.append((import_path, correct_path))
                    continue

            # 2) Fallback: search the sandbox (exclude lib/, out/, cache/)
            matches = list(sandbox.tmp_dir.rglob(filename))
            valid = [
                f for f in matches
                if "lib" not in f.parts
                and "out" not in f.parts
                and "cache" not in f.parts
            ]
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
            print(f"[TestWriter] Auto-corrected imports: {fixed}")

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

    def _resolve_import_path(
        self,
        import_path: str,
        remappings: dict[str, str],
        repo: Path,
        from_file: Path | None = None,
    ) -> Path | None:
        """Resolve import path to repo-relative path. Exclude lib/ (external deps)."""
        path_str = import_path.strip()
        if not path_str:
            return None
        # Apply remappings: @src/=src/, etc. (longest alias first)
        for alias, target in sorted(remappings.items(), key=lambda x: -len(x[0])):
            alias_stripped = alias.rstrip("/")
            if path_str.startswith(alias_stripped + "/") or path_str == alias_stripped:
                path_str = target.rstrip("/") + path_str[len(alias_stripped):]
                break
        # Relative import: resolve from current file's directory
        if path_str.startswith("./") or path_str.startswith("../"):
            if not from_file or not from_file.parent:
                return None
            resolved = (from_file.parent / path_str).resolve()
            try:
                path_str = str(resolved.relative_to(repo.resolve())).replace("\\", "/")
            except ValueError:
                return None
        # Exclude lib (forge-std, openzeppelin)
        if path_str.startswith("lib/") or "/lib/" in path_str:
            return None
        candidate = repo / path_str
        if candidate.exists() and candidate.suffix == ".sol":
            return candidate
        return None

    def _parse_imports(self, content: str) -> list[str]:
        """Extract import paths from Solidity source."""
        paths = []
        for m in self._IMPORT_RE.finditer(content):
            p1, p2 = m.group(1), m.group(2)
            p = (p1 or p2 or "").strip()
            if p and p not in paths:
                paths.append(p)
        return paths

    def _is_interface_file(self, content: str, path: str) -> bool:
        """Heuristic: file is an interface if it declares interface or is in interface/ dir."""
        if "interface/" in path.replace("\\", "/"):
            return True
        return "interface " in content and "contract " not in content[:500]

    def _collect_repo_sources(
        self,
        finding: Finding,
        repo_path: str | None,
        remappings: dict[str, str],
        _lib_imports_out: set[str] | None = None,
    ) -> dict[str, str]:
        """
        Collect target contract + full transitive dependency tree from the repo.
        Returns dict of {relative_path: source_code}. Excludes lib/. No mocks.

        If *_lib_imports_out* is provided, any import that resolves to lib/
        (external dep via remapping) is added to the set using its original
        alias path (e.g. ``controller/core/IControllerFacade.sol``).
        """
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

            # Truncation
            is_target = current == target_path
            is_interface = self._is_interface_file(content, rel)
            if is_target:
                cap = self._TARGET_FILE_CAP
            elif is_interface:
                cap = self._INTERFACE_FILE_CAP
            else:
                cap = self._IMPL_FILE_CAP
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
                    # Import resolved to lib/ — record the original alias
                    _lib_imports_out.add(imp)

        return collected

    def _collect_minimal_sources(
        self,
        finding: Finding,
        repo_path: str | None,
        remappings: dict[str, str],
        _lib_imports_out: set[str] | None = None,
    ) -> dict[str, str]:
        """
        Minimal context for attempt 1: target contract + direct imports.
        Keeps prompt small for faster LLM response.

        If *_lib_imports_out* is provided, any import that resolves to lib/
        is added to the set using its original alias path.
        """
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
        seen: set[str] = set()
        to_visit: list[Path] = [target_path]
        total_chars = 0
        max_minimal_chars = 30_000

        while to_visit and total_chars < max_minimal_chars:
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

            if is_target:
                for imp in self._parse_imports(content):
                    resolved = self._resolve_import_path(imp, remappings, repo, from_file=current)
                    if resolved:
                        rel_resolved = str(resolved.relative_to(repo)).replace("\\", "/")
                        if rel_resolved not in seen:
                            to_visit.append(resolved)
                    elif _lib_imports_out is not None:
                        _lib_imports_out.add(imp)

        return collected

    def _get_repo_file_manifest(self, repo_path: str | None) -> list[str]:
        """List all .sol files in repo (src/, contracts/) excluding lib/."""
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

    def _generate_import_cheatsheet(
        self,
        real_sources: dict[str, str],
        lib_imports: set[str] | None = None,
    ) -> str:
        """Produce ready-to-use Solidity import statements.

        Combines the local source paths we collected with any external
        (remapped) import aliases discovered during dependency walking.
        The LLM should copy these verbatim instead of inventing paths.
        """
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
        """Parse remappings from foundry.toml content.  Handles both
        ``remappings = ["a/=b/", ...]`` (inline array) and multi-line arrays."""
        remappings: dict[str, str] = {}
        in_remappings = False
        for line in content.splitlines():
            stripped = line.strip()
            if not in_remappings:
                if "remappings" in stripped and "=" in stripped:
                    in_remappings = True
                    # Inline array on the same line: remappings = ["a/=b/", ...]
                    after_eq = stripped.split("=", 1)[1]
                    for entry in after_eq.replace("[", "").replace("]", "").split(","):
                        entry = entry.strip().strip('"').strip("'").strip()
                        if "=" in entry:
                            alias, target = entry.split("=", 1)
                            if alias.strip():
                                remappings[alias.strip()] = target.strip()
                    if "]" in after_eq:
                        break  # single-line array, done
                continue
            # inside multi-line array
            if stripped == "]" or stripped.startswith("]"):
                break
            if stripped.startswith("["):
                break  # next TOML section
            entry = stripped.strip('",').strip("'").strip()
            if "=" in entry:
                alias, target = entry.split("=", 1)
                if alias.strip():
                    remappings[alias.strip()] = target.strip()
        return remappings

    def _get_remappings_from_repo(self, repo_path: str | None) -> dict[str, str]:
        """Read Foundry remappings from repo (foundry.toml or remappings.txt)."""
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
        """Legacy: single-file lookup. Prefer _collect_repo_sources for full deps."""
        return self._collect_repo_sources(finding, repo_path, {})

    def _fetch_rag_context(self, finding: Finding) -> str:
        """Fetch RAG results for vulnerability-specific exploit patterns and Solidity best practices."""
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
        """Fetch RAG results for compiler error fixes — use on retry for maximum improvement."""
        if not error_history:
            return ""
        from src.knowledge.rag_system import search_security_knowledge

        last_err = error_history[-1]
        # Extract error codes (e.g. 8429, 2424) and key phrases
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
    ) -> list[dict[str, str]]:

        has_real_source = bool(real_sources)
        system_prompt = TEST_WRITER_REAL_SOURCE_SYSTEM_PROMPT if has_real_source else TEST_WRITER_SYSTEM_PROMPT

        error_context = self._format_error_history(error_history)

        source_section = ""
        if has_real_source:
            # Import cheat sheet — ready-to-paste lines the LLM must use
            if import_cheatsheet:
                source_section += "\n\n=== IMPORT CHEAT SHEET (copy these verbatim, do NOT invent paths) ===\n"
                source_section += import_cheatsheet + "\n"
                source_section += "\nONLY use imports listed above. NEVER import from out/, cache/, or artifacts/.\n"
                source_section += "Do NOT use ../src/... — that causes 'src/src/...' when test is in src/test/.\n\n"

            # Starter template
            first_path = list(real_sources.keys())[0] if real_sources else "src/core/Contract.sol"
            source_section += "\n=== STARTER TEMPLATE (use this structure) ===\n"
            source_section += f'// pragma solidity ^0.8.17;\n'
            source_section += f'// import "forge-std/Test.sol";\n'
            source_section += f'// import "{first_path}";  // <-- from IMPORT CHEAT SHEET above\n'
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
            source_section = "\n\n=== CODE SNIPPETS FROM KNOWLEDGE GRAPH ===\n"
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
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                confidence=0,
                raw_output={"error": "Missing or invalid finding"}
            )

        relevant_code = task.context.get("relevant_code", {})
        repo_path = task.context.get("repo_path")
        contract_signatures = task.context.get("contract_signatures", {}) or {}

        # Get remappings from repo (needed for import resolution)
        remappings = self._get_remappings_from_repo(repo_path)

        # Collect sources + track lib/ imports for the cheat sheet
        lib_imports: set[str] = set()
        real_sources_full = self._collect_repo_sources(
            finding, repo_path, remappings, _lib_imports_out=lib_imports,
        )
        real_sources_minimal = self._collect_minimal_sources(
            finding, repo_path, remappings, _lib_imports_out=lib_imports,
        )
        repo_manifest = self._get_repo_file_manifest(repo_path) if repo_path else []

        # Pre-generate import cheat sheet (local + remapped lib imports)
        import_cheatsheet = self._generate_import_cheatsheet(
            real_sources_full or real_sources_minimal, lib_imports,
        ) if (real_sources_full or real_sources_minimal) else None

        if real_sources_full:
            print(f"[TestWriter] Found real source + deps for {finding.affected_contract}: {len(real_sources_full)} files (minimal: {len(real_sources_minimal)})")
        else:
            print(f"[TestWriter] No real source found for {finding.affected_contract}, using mock mode")

        attempts = 0
        error_history = []
        compiled = False
        exploit_success = False
        test_code_generated = None
        test_logs = ""

        # ── ONE sandbox for ALL attempts — repo copied only once ──
        use_repo = repo_path if real_sources_full else None
        sandbox = SandboxManager(repo_path=use_repo)
        try:
            sandbox.setup_foundry_project()  # copy repo ONCE here

            while attempts < self.MAX_ATTEMPTS:
                attempts += 1
                print(f"[TestWriter] Attempt {attempts}/{self.MAX_ATTEMPTS} building prompt...", flush=True)
                sources_for_attempt = real_sources_full if attempts >= 3 else real_sources_minimal
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
                )

                try:
                    # Use sync invoke() via to_thread so REST transport is used (gRPC often ignores timeout).
                    # ainvoke uses gRPC and can hang; invoke with transport=rest respects timeout.
                    print(f"[TestWriter] Attempt {attempts} calling LLM (timeout={self.LLM_TIMEOUT}s)...", flush=True)
                    response = await asyncio.wait_for(
                        asyncio.to_thread(self.llm_client.invoke, prompt),
                        timeout=self.LLM_TIMEOUT
                    )

                    content = response.content if hasattr(response, "content") else str(response)

                    if isinstance(content, list):
                        content = "".join([c.get("text", "") if isinstance(c, dict) else str(c) for c in content])

                    test_code_generated = self._extract_test_code(content)

                    if not test_code_generated:
                        error_history.append("No Solidity code returned by LLM")
                        continue

                    if not self._has_exact_test_exploit(test_code_generated):
                        error_history.append("Generated test must include function test_exploit() exactly.")
                        continue

                    test_code_generated = self._auto_correct_imports(
                        test_code_generated, sandbox, remappings,
                        collected_paths=list(sources_for_attempt.keys()) if sources_for_attempt else None,
                    )

                    test_path = sandbox.get_test_path()
                    test_file = f"{test_path}/ExploitTest.t.sol"
                    sandbox.write_test_file(test_file, test_code_generated)

                    # Ignore deprecation warnings (8429=virtual modifier, 2424=memory-safe-assembly).
                    # Build only src/ to avoid scripts/ deploy errors; use separate flags (space = path).
                    src_path = sandbox.get_src_path()
                    build_res = sandbox.run(
                        f"forge build --force --ignored-error-codes 8429 --ignored-error-codes 2424 {src_path}"
                    )
                    if not build_res.success:
                        err = (build_res.stderr or build_res.stdout)[:1200]
                        print(f"[TestWriter] Attempt {attempts} build error:\n{err[:400]}...")
                        error_history.append(f"Build Failed:\n{err}")
                        compiled = False
                        # Clean Foundry output so stale out/X.sol/ dirs
                        # don't confuse auto-correction on the next attempt
                        out_dir = Path(sandbox.tmp_dir) / "out"
                        if out_dir.exists():
                            shutil.rmtree(out_dir, ignore_errors=True)
                        continue

                    compiled = True
                    test_res = sandbox.run("forge test --match-test test_exploit -vvv")
                    test_logs = (test_res.stdout or "") + "\n" + (test_res.stderr or "")
                    passed_by_logs = "[PASS]" in test_logs or "exploit succeeded" in test_logs.lower()
                    exploit_success = test_res.success and passed_by_logs

                    if exploit_success:
                        break

                    error_history.append(f"Test compiled but exploit check failed.\nLogs:\n{test_logs[:400]}")

                except asyncio.TimeoutError:
                    msg = f"LLM call timed out after {self.LLM_TIMEOUT}s"
                    print(f"[TestWriterWorker] {msg}")
                    error_history.append(msg)
                except Exception as e:
                    print(f"[TestWriterWorker] LLM call failed: {e}")
                    error_history.append(str(e))

        finally:
            sandbox.cleanup()

        # Confidence adjustment
        original_conf = getattr(finding, "confidence", 50)
        if compiled and exploit_success:
            adjustment = 60
        elif compiled:
            adjustment = 20
        else:
            adjustment = -40
        final_confidence = max(0, min(100, original_conf + adjustment))

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