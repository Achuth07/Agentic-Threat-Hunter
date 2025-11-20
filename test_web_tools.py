import asyncio
import os
from tools.web_tools import web_search, visit_page
from agent.multitool_agent import build_multitool_graph
from langchain_core.messages import HumanMessage

# Mock functions for Splunk and Velociraptor to avoid needing real connections
def mock_splunk(query):
    return [{"event": "mock splunk result"}]

def mock_velociraptor(query):
    return '{"rows": [{"pid": 123, "name": "test_process"}]}'

async def test_tools_direct():
    print("--- Testing Web Tools Directly ---")
    
    # Test web_search
    print("\n1. Testing web_search('latest cybersecurity news')...")
    try:
        res = web_search("latest cybersecurity news")
        print(f"Result length: {len(res)}")
        print(f"Snippet: {res[:200]}...")
    except Exception as e:
        print(f"web_search failed: {e}")

    # Test visit_page
    print("\n2. Testing visit_page('https://example.com')...")
    try:
        res = visit_page("https://example.com")
        print(f"Result length: {len(res)}")
        print(f"Snippet: {res[:200]}...")
    except Exception as e:
        print(f"visit_page failed: {e}")

async def test_agent_routing():
    print("\n--- Testing Agent Routing ---")
    
    # Build the graph
    graph = build_multitool_graph(
        splunk_execute_fn=mock_splunk,
        velociraptor_fn=mock_velociraptor,
        router_model="llama3:8b", # Use a fast model if available, or the one in env
        spl_model="llama3:8b",
        vql_model="llama3:8b",
        coder_model="qwen2.5-coder:7b"
    )
    
    # Test Case 1: Web Search
    print("\n1. Testing Agent with 'Who is the CEO of Google?' (Should route to web_search)")
    state = {
        "user_query": "Who is the CEO of Google?",
        "messages": [],
        "retry_count": 0
    }
    result = await graph.ainvoke(state)
    print(f"Tool Choice: {result.get('tool_choice')}")
    print(f"Web Query: {result.get('web_query')}")
    print(f"Results Snippet: {str(result.get('results'))[:200]}...")

    # Test Case 2: Visit Page
    print("\n2. Testing Agent with 'Summarize this page: https://example.com' (Should route to visit_page)")
    state = {
        "user_query": "Summarize this page: https://example.com",
        "messages": [],
        "retry_count": 0
    }
    result = await graph.ainvoke(state)
    print(f"Tool Choice: {result.get('tool_choice')}")
    print(f"Web URL: {result.get('web_url')}")
    print(f"Results Snippet: {str(result.get('results'))[:200]}...")

if __name__ == "__main__":
    asyncio.run(test_tools_direct())
    asyncio.run(test_agent_routing())
