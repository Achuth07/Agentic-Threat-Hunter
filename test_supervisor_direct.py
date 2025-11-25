import asyncio
from agent.hierarchical_agent import build_hierarchical_graph
from langchain_core.messages import HumanMessage

async def test_supervisor():
    # Mock functions for Splunk/Velo
    def mock_splunk(query):
        return "Mock Splunk result"
    
    def mock_velo(query):
        return "Mock Velo result"
    
    graph = build_hierarchical_graph(
        splunk_execute_fn=mock_splunk,
        velociraptor_fn=mock_velo,
        supervisor_model="qwen2.5-coder:7b",
        worker_model="qwen2.5-coder:7b"
    )
    
    initial_state = {
       "messages": [HumanMessage(content="Simulate T1003 using Atomic Red Team")],
        "next_agent": "",
        "instructions": "",
        "tool_output": None
    }
    
    print("Invoking graph...")
    try:
        result = await graph.ainvoke(initial_state)
        print("\n✓ SUCCESS")
        print(f"Final state: {result}")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_supervisor())
