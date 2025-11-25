import asyncio
from agent.hierarchical_agent import build_red_team_agent
from langchain_core.messages import HumanMessage

async def test_red_team():
    print("Building RedTeam Agent...")
    agent = build_red_team_agent("qwen2.5-coder:7b")
    
    print("Invoking RedTeam Agent with 'Simulate T1003'...")
    messages = [HumanMessage(content="Simulate T1003 using Atomic Red Team")]
    
    async for event in agent.astream_events({"messages": messages}, version="v1"):
        kind = event["event"]
        name = event["name"]
        
        if kind == "on_chat_model_stream":
            pass # Too noisy
        elif kind in ["on_tool_start", "on_tool_end"]:
            print(f"\n[EVENT] {kind}: {name}")
            if kind == "on_tool_start":
                print(f"  Input: {event['data'].get('input')}")
            elif kind == "on_tool_end":
                print(f"  Output: {event['data'].get('output')}")
        elif kind == "on_chain_end" and name == "LangGraph":
             print(f"\n[EVENT] {kind}: {name}")
             print(f"  Output: {event['data'].get('output')}")

if __name__ == "__main__":
    asyncio.run(test_red_team())
