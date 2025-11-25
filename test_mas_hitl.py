import asyncio
import websockets
import json
import sys

async def test_mas_hitl():
    uri = "ws://localhost:8005/ws"
    print(f"Connecting to {uri}...")
    
    try:
        async with websockets.connect(uri) as websocket:
            print("✓ Connected")
            
            # 1. Send a request that should trigger Red Team (and thus HITL)
            query = "Simulate T1003 using Atomic Red Team"
            print(f"\nSending query: '{query}'")
            
            await websocket.send(json.dumps({
                "type": "ask",
                "question": query,
                "settings": {
                    "summaryModel": "qwen2.5-coder:7b", # Use smart model for supervisor
                    "splModel": "qwen2.5-coder:7b",
                    "vqlModel": "qwen2.5-coder:7b"
                }
            }))
            
            thread_id = None
            approval_received = False
            
            # 2. Listen for messages
            while True:
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=120)
                    data = json.loads(response)
                    
                    msg_type = data.get("type")
                    title = data.get("title", "")
                    detail = data.get("detail", "")
                    
                    if msg_type == "activity":
                        print(f"  [{data.get('status', 'info')}] {title}: {detail}")
                        
                    elif msg_type == "approval_required":
                        print(f"\n⚠️  APPROVAL REQUIRED: {detail}")
                        print(f"  Thread ID: {data.get('thread_id')}")
                        thread_id = data.get("thread_id")
                        approval_received = True
                        
                        # 3. Send Approval
                        print("  -> Sending APPROVAL...")
                        await websocket.send(json.dumps({
                            "type": "approve",
                            "thread_id": thread_id
                        }))
                        
                    elif msg_type == "final":
                        print("\n✓ FINAL RESULT RECEIVED")
                        print(f"  Summary: {data.get('summary')}")
                        break
                        
                    elif msg_type == "error":
                        print(f"\n❌ ERROR: {title} - {detail}")
                        break
                        
                except asyncio.TimeoutError:
                    print("\n❌ Timeout waiting for response")
                    break
            
            if approval_received:
                print("\n✓ HITL Test Passed: Approval requested and processed.")
            else:
                print("\n❌ HITL Test Failed: No approval request received.")

    except Exception as e:
        print(f"\n❌ Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_mas_hitl())
