#!/usr/bin/env python3
"""
Force an error to test the reflection loop.
This modifies the mock execution to always fail on first attempt.
"""
import asyncio
import json
import websockets

async def test_reflection_with_forced_error():
    uri = "ws://localhost:8005/ws"
    
    print("=" * 80)
    print("REFLECTION LOOP TEST - Forced Error Scenario")
    print("=" * 80)
    print(f"\nConnecting to {uri}...")
    
    try:
        async with websockets.connect(uri) as websocket:
            print("✓ Connected\n")
            
            # Use a query that will likely generate malformed SPL/VQL
            # to trigger the reflection loop
            test_query = "Show me all the things with syntax error @#$%"
            
            print(f"Sending intentionally problematic query:")
            print(f"  '{test_query}'")
            print("-" * 80)
            
            await websocket.send(test_query)
            
            saw_reflection = False
            activity_log = []
            
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=60.0)
                    data = json.loads(message)
                    
                    msg_type = data.get("type")
                    
                    if msg_type == "activity":
                        title = data.get("title", "")
                        detail = data.get("detail", "")
                        status = data.get("status", "")
                        
                        activity_log.append({
                            "title": title,
                            "detail": detail,
                            "status": status
                        })
                        
                        # Check for reflection
                        if "Self-Correction" in title or "reflect" in title.lower():
                            saw_reflection = True
                            print(f"\n🔄 *** REFLECTION TRIGGERED ***")
                            print(f"    {title}: {detail}")
                        else:
                            icon = "✓" if status == "done" else "⏳" if status == "running" else "⚠"
                            print(f"{icon} {title}")
                            if detail and len(detail) < 150:
                                print(f"  → {detail}")
                    
                    elif msg_type in ["final", "error"]:
                        print("\n" + "=" * 80)
                        print(f"RESULT: {msg_type.upper()}")
                        print("=" * 80)
                        
                        if msg_type == "error":
                            print(f"Error: {data.get('title', '')}")
                            print(f"Detail: {data.get('detail', '')}")
                        else:
                            print(f"Source: {data.get('source', '')}")
                            print(f"Count: {data.get('count', 0)}")
                            print(f"Summary: {data.get('summary', '')[:200]}")
                        
                        break
                
                except asyncio.TimeoutError:
                    print("\n⚠ Timeout")
                    break
                except websockets.exceptions.ConnectionClosed:
                    break
            
            print("\n" + "=" * 80)
            print("REFLECTION TEST RESULT")
            print("=" * 80)
            print(f"Reflection loop activated: {'YES ✓' if saw_reflection else 'NO ✗'}")
            print(f"Total activities: {len(activity_log)}")
            
            return 0 if saw_reflection else 1
    
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(test_reflection_with_forced_error()))
