import asyncio
import os
import sys

# Add project root to path
sys.path.append(os.getcwd())

from agent.multitool_agent import build_multitool_graph

# Mock execution function
execution_attempts = 0

def mock_splunk_execute(spl: str):
    global execution_attempts
    execution_attempts += 1
    print(f"DEBUG: Executing SPL (Attempt {execution_attempts}): {spl}")
    
    if execution_attempts == 1:
        return "Error: Invalid syntax in SPL query."
    else:
        return [{"_time": "2023-10-27T10:00:00", "event": "Login success"}]

def mock_velociraptor_execute(vql: str):
    return "[]"

async def run_test():
    print("Starting Reflection Loop Test...")
    
    # Use existing models or defaults
    # We need real models for routing/generation to work, assuming Ollama is up.
    # If Ollama is not up, this might fail. But user has Ollama.
    router_model = os.getenv("SUMMARY_MODEL", "llama3:8b")
    spl_model = os.getenv("OLLAMA_MODEL", "splunk_hunter") 
    coder_model = os.getenv("CODER_MODEL", "qwen2.5-coder:7b")

    print(f"Using models: Router={router_model}, SPL={spl_model}, Coder={coder_model}")
    
    graph = build_multitool_graph(
        splunk_execute_fn=mock_splunk_execute,
        velociraptor_fn=mock_velociraptor_execute,
        router_model=router_model,
        spl_model=spl_model,
        coder_model=coder_model
    )
    
    user_query = "Show me failed logins in Splunk"
    
    print(f"User Query: {user_query}")
    
    async for event in graph.astream_events({"user_query": user_query}, version="v1"):
        kind = event["event"]
        name = event["name"]
        if kind == "on_chain_start" and name in ["reflect_node", "generate_query", "execute_tool", "validate_node"]:
            print(f"--- Entering Node: {name} ---")
        
        if kind == "on_chain_end" and name == "LangGraph":
            final_state = event["data"]["output"]
            print("\nFinal State:")
            print(f"Tool: {final_state.get('tool_choice')}")
            print(f"Results: {final_state.get('results')}")
            print(f"Error: {final_state.get('error')}")
            print(f"Retry Count: {final_state.get('retry_count')}")

    if execution_attempts >= 2:
        print("\nSUCCESS: Reflection loop triggered (retried execution).")
    else:
        print("\nFAILURE: Reflection loop did NOT trigger.")

if __name__ == "__main__":
    asyncio.run(run_test())
