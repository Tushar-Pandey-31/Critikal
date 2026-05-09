"""
Tool registry for the Critikal agent.

All tools — pipeline wrappers, generic file/shell tools, and graph queries —
are registered here. The query loop calls get_all_tools() to build the
tool list for the LLM.
"""

from src.agent.tool import Tool


def get_pipeline_tools() -> list[Tool]:
    """Tools that wrap existing Critikal pipeline stages."""
    from src.agent.tools.attack_tool import AttackAnalysisTool
    from src.agent.tools.chain_tool import ChainAnalysisTool
    from src.agent.tools.depth_tool import DepthAnalysisTool
    from src.agent.tools.fuzz_tool import FuzzGeneratorTool
    from src.agent.tools.gate_tool import GateFilterTool
    from src.agent.tools.graph_query_tool import (
        FunctionContextTool,
        ModifiersTool,
        StateMutatorsTool,
    )
    from src.agent.tools.hotspot_tool import HotspotTool
    from src.agent.tools.ingest_tool import IngestTool
    from src.agent.tools.jury_tool import JuryTool
    from src.agent.tools.rag_tool import RAGSearchTool
    from src.agent.tools.recon_tool import ReconTool
    from src.agent.tools.report_tool import ReportTool
    from src.agent.tools.semantic_tool import SemanticDiscoveryTool
    from src.agent.tools.testwriter_tool import TestWriterTool
    from src.agent.tools.threat_intel_tool import ThreatIntelTool

    return [
        IngestTool(),
        ReconTool(),
        HotspotTool(),
        ThreatIntelTool(),
        AttackAnalysisTool(),
        SemanticDiscoveryTool(),
        GateFilterTool(),
        JuryTool(),
        RAGSearchTool(),
        DepthAnalysisTool(),
        ChainAnalysisTool(),
        TestWriterTool(),
        FuzzGeneratorTool(),
        ReportTool(),
        FunctionContextTool(),
        StateMutatorsTool(),
        ModifiersTool(),
    ]


def get_generic_tools() -> list[Tool]:
    """Generic file/shell/web tools for the Critikal agent."""
    from src.agent.tools.bash_tool import BashTool
    from src.agent.tools.file_edit_tool import FileEditTool
    from src.agent.tools.file_read_tool import FileReadTool
    from src.agent.tools.file_write_tool import FileWriteTool
    from src.agent.tools.glob_tool import GlobTool
    from src.agent.tools.grep_tool import GrepTool
    from src.agent.tools.web_fetch_tool import WebFetchTool
    from src.agent.tools.web_search_tool import WebSearchTool

    return [
        BashTool(),
        FileReadTool(),
        FileWriteTool(),
        FileEditTool(),
        GrepTool(),
        GlobTool(),
        WebFetchTool(),
        WebSearchTool(),
    ]


def get_chain_tools() -> list[Tool]:
    """Foundry sandbox + on-chain deployment and interaction tools."""
    from src.agent.tools.deploy_tool import CastTool, DeployContractTool
    from src.agent.tools.sandbox_tool import SandboxRunTool

    return [
        SandboxRunTool(),
        DeployContractTool(),
        CastTool(),
    ]


def get_agent_tools() -> list[Tool]:
    """Meta-agent tools — sub-agent spawning, task management."""
    from src.agent.sub_agent import SpawnAgentTool

    return [
        SpawnAgentTool(),
    ]


def get_all_tools() -> list[Tool]:
    """All tools available to the agent."""
    return get_pipeline_tools() + get_generic_tools() + get_chain_tools() + get_agent_tools()
