import asyncio
import websockets
import json
import sys

async def test_flow():
    uri = "ws://localhost:8005/ws"
    async with websockets.connect(uri) as websocket:
        print("Connected to WebSocket")
        
        # Send request
        request = {
            "type": "ask",
            "question": "Simulate T1003 using Atomic Red Team",
            "settings": {
                "defaultIndex": "main",
                "timePolicyMode": "normalize",
                "splModel": "splunk_hunter",
                "vqlModel": "velociraptor_hunter",
                "summaryModel": "llama3:8b"
            }
        }
        await websocket.send(json.dumps(request))
        print(f"Sent request: {request['question']}")
        
        while True:
            try:
                message = await websocket.recv()
                data = json.loads(message)
                
                msg_type = data.get("type")
                title = data.get("title")
                status = data.get("status")
                
                print(f"Received: Type={msg_type}, Title={title}, Status={status}")
                
                if msg_type == "approval_required":
                    print("Approval required! Sending approval...")
                    await websocket.send(json.dumps({"type": "approve"}))
                
                if msg_type == "final":
                    print("\n--- FINAL RESULT ---")
                    print(f"Summary: {data.get('summary')[:100]}...")
                    results = data.get("results", [])
                    print(f"Raw Results Count: {len(results)}")
                    if results:
                        print(f"First Result: {str(results[0])[:100]}...")
                    break
                    
                if msg_type == "error":
                    print(f"ERROR: {data.get('detail')}")
                    break
                    
            except websockets.exceptions.ConnectionClosed:
                print("Connection closed")
                break

if __name__ == "__main__":
    asyncio.run(test_flow())
