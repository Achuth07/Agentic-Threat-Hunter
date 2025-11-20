import os
import sys
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Ensure we can import from the current directory
sys.path.append(os.getcwd())

from agent.multitool_agent import build_multitool_graph

def mock_splunk(query):
    return [{"result": "mock splunk result"}]

def mock_velociraptor(query):
    return '[{"result": "mock velociraptor result"}]'

def test_atomic_agent():
    # Build the graph
    graph = build_multitool_graph(
        splunk_execute_fn=mock_splunk,
        velociraptor_fn=mock_velociraptor,
        router_model="qwen2.5-coder:7b",
        spl_model="qwen2.5-coder:7b",
        vql_model="qwen2.5-coder:7b"
    )

    # Test 1: List tests
    print("\n--- Test 1: List Atomic Tests ---")
    query = "List available atomic red team tests"
    state = {"user_query": query, "messages": []}
    
    try:
        result = graph.invoke(state)
        print(f"Tool Choice: {result.get('tool_choice')}")
        print(f"Atomic Query: {result.get('atomic_query')}")
        print(f"Results: {str(result.get('results'))[:500]}...") # Truncate results
        print(f"Error: {result.get('error')}")
        
        if result.get("tool_choice") == "atomic_red_team" and (result.get("results") or result.get("error")):
            print("SUCCESS: Agent routed to atomic_red_team.")
        else:
            print("FAILURE: Agent did not route correctly or failed to get results.")
            
    except Exception as e:
        print(f"ERROR: {e}")

    # Test 2: Execute a specific test (Dry run or check if it generates correct JSON)
    print("\n--- Test 2: Execute T1033 ---")
    query = "Run Atomic Red Team test T1033"
    state = {"user_query": query, "messages": []}
    
    try:
        result = graph.invoke(state)
        print(f"Tool Choice: {result.get('tool_choice')}")
        print(f"Atomic Query: {result.get('atomic_query')}")
        # We might not want to actually run it if it takes time or changes state, 
        # but T1033 is usually safe.
        print(f"Results: {str(result.get('results'))[:500]}...")
        
        if result.get("tool_choice") == "atomic_red_team" and result.get("results"):
             print("SUCCESS: Agent routed to atomic_red_team and executed test.")
        else:
             print("FAILURE: Agent did not route correctly or failed to get results.")

    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    test_atomic_agent()
