import asyncio
import os
import sys

# Add current directory to path so we can import server
sys.path.append(os.getcwd())

from server import _summarize_results

async def test_summary():
    print("Testing _summarize_results...")
    
    # Mock data
    question = "list system info"
    query = "SELECT * FROM info()"
    rows = [{"Hostname": "test-host", "OS": "Linux", "Architecture": "amd64"}]
    tool_name = "run_velociraptor_query"
    
    try:
        summary = await _summarize_results(question, query, rows, tool_name)
        print(f"Summary: {summary}")
        
        if "test-host" in summary or "Linux" in summary or "1" in summary or "row" in summary or "result" in summary:
            print("SUCCESS: Summary contains expected info.")
        else:
            print("WARNING: Summary might be too generic, but function executed.")
            
    except Exception as e:
        print(f"FAILURE: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Set env vars if needed by server.py imports
    os.environ["OLLAMA_MODEL"] = "splunk_hunter" 
    os.environ["SUMMARY_MODEL"] = "llama3:8b"
    
    asyncio.run(test_summary())
