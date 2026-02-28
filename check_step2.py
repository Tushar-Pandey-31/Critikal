import os
import networkx as nx

from src.repo_manager import RepoManager
from src.analysis_engine import AnalysisEngine
from src.graph_builder import GraphBuilder
from src.utils.graph_queries import GraphQueries

async def main():
    repo_url = "https://github.com/CreamFi/compound-protocol"
    repo_manager = RepoManager("./data/scratch")
    repo_path = repo_manager.clone_repo(repo_url)
    repo_manager.install_dependencies(repo_path)
    
    engine = AnalysisEngine()
    slither_obj, _ = engine.run_analysis_v2(repo_path)
    
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph
    
    gq = GraphQueries(graph)
    guarded = gq.get_guarded_initializers()
    print(f"Guarded initializers detected: {len(guarded)}")
    for g in guarded:
        print(f"  {g.get('function_id', g.get('name', 'Unknown'))}")

    # Cross-check the raw node fields for all initialize functions
    for fn_id, data in graph.nodes(data=True):
        if data.get("type") == "function" and "initialize" in fn_id.lower():
            print(f"\n{fn_id}")
            print(f"  has_initializer_guard : {data.get('has_initializer_guard')}")
            print(f"  safe_init_pattern     : {data.get('safe_init_pattern')}")
            print(f"  is_protected          : {data.get('is_protected')}")
            print(f"  is_unprotected_mutator: {data.get('is_unprotected_mutator')}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
