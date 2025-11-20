import os
import json
from dotenv import load_dotenv
from agent.multitool_agent import build_multitool_graph

load_dotenv()

# Mock Velociraptor function
def mock_velo(vql: str) -> str:
    print(f"DEBUG: Executing VQL: {vql}")
    if "pslist" in vql:
        return json.dumps([{"Name": "test_process.exe", "Pid": 1234}])
    return json.dumps([])

# Mock Splunk function
def mock_splunk(spl: str) -> list[dict]:
    return []

def test_velo_execution():
    print("Starting Velociraptor Execution Test...")
    
    router_model = os.getenv("SUMMARY_MODEL", "llama3:8b")
    spl_model = os.getenv("OLLAMA_MODEL", "splunk_hunter")
    vql_model = os.getenv("VQL_MODEL", "velociraptor_hunter")
    coder_model = os.getenv("CODER_MODEL", "qwen2.5-coder:7b")

    graph = build_multitool_graph(
        splunk_execute_fn=mock_splunk,
        velociraptor_fn=mock_velo,
        router_model=router_model,
        spl_model=spl_model,
        vql_model=vql_model,
        coder_model=coder_model,
    )

    # Test query that should route to Velociraptor
    query = "list the system info of host achuth dell"
    # Note: "system info" might route to info(), but let's see. 
    # The user's query was "list the system info of host achuth dell".
    
    initial_state = {
        "user_query": query,
        "tool_choice": None, # Let router decide, or force it to test execution
        "retry_count": 0,
        "messages": [],
        "error": None
    }

    print(f"Invoking graph with query: {query}")
    
    final_state = initial_state.copy()
    import asyncio
    
    async def run_test():
        async for output in graph.astream(initial_state):
            for node_name, state_update in output.items():
                print(f"--- Node: {node_name} ---")
                final_state.update(state_update)
                if node_name == "generate_query":
                    print(f"Generated VQL: {state_update.get('vql_query')}")

    asyncio.run(run_test())
    
    print("Final State Keys:", final_state.keys())
    print("Tool Choice:", final_state.get("tool_choice"))
    print("VQL Query:", final_state.get("vql_query"))
    print("Results:", final_state.get("results"))
    print("Error:", final_state.get("error"))

    if final_state.get("tool_choice") == "run_velociraptor_query":
        print("SUCCESS: Velociraptor tool executed successfully (results may be empty due to mock).")
    else:
        print("FAILURE: Velociraptor tool did not execute as expected.")

if __name__ == "__main__":
    test_velo_execution()
