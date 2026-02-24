from src.agents.tools import search_security_knowledge

def test_tool():
    print("Testing 'search_security_knowledge' tool...")
    
    # Query something related to Solidity docs we ingested
    query = "What are the breaking changes in version 0.8.0?"
    print(f"Query: {query}")
    
    try:
        result = search_security_knowledge.invoke(query)
        print("\n--- Result ---")
        print(result[:1000] + "..." if len(result) > 1000 else result)
        
        if "Error" in result and "not available" in result:
             print("\n❌ RAG Tool failed to initialize.")
        elif "Security Knowledge Results" in result:
             print("\n✅ RAG Tool returned results.")
        else:
             print("\n⚠️ Unexpected result format.")
             
    except Exception as e:
        print(f"\n❌ Tool execution error: {e}")

if __name__ == "__main__":
    test_tool()
