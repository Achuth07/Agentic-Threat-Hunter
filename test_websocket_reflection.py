#!/usr/bin/env python3
"""
WebSocket-based test for the reflection loop.
This simulates a client connecting to the server and sending a query
that will trigger the reflection loop.
"""
import asyncio
import json
import websockets
import sys

async def test_reflection_loop():
    uri = "ws://localhost:8005/ws"
    
    print("=" * 80)
    print("REFLECTION LOOP TEST - WebSocket Client")
    print("=" * 80)
    print(f"\nConnecting to {uri}...")
    
    try:
        async with websockets.connect(uri) as websocket:
            print("✓ Connected to WebSocket server\n")
            
            # Send a query that should trigger Splunk (not VirusTotal)
            # We'll use a query that might generate invalid SPL to test reflection
            test_query = "Show me failed login attempts in the last hour"
            
            print(f"Sending query: '{test_query}'")
            print("-" * 80)
            
            # Send the query
            await websocket.send(test_query)
            
            # Track if we saw reflection
            saw_reflection = False
            saw_self_correction = False
            activity_count = 0
            
            # Receive and display all messages
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=60.0)
                    data = json.loads(message)
                    
                    msg_type = data.get("type")
                    
                    if msg_type == "activity":
                        activity_count += 1
                        title = data.get("title", "")
                        detail = data.get("detail", "")
                        status = data.get("status", "")
                        icon = data.get("icon", "")
                        
                        # Check for reflection indicators
                        if "Self-Correction" in title or "reflect" in title.lower():
                            saw_self_correction = True
                            print(f"\n🔄 [{activity_count}] *** REFLECTION DETECTED ***")
                            print(f"    Title: {title}")
                            print(f"    Detail: {detail}")
                            print(f"    Status: {status}")
                        else:
                            status_icon = "✓" if status == "done" else "⏳" if status == "running" else "⚠"
                            print(f"\n{status_icon} [{activity_count}] {title}")
                            if detail and len(detail) < 200:
                                print(f"    {detail}")
                            elif detail:
                                print(f"    {detail[:197]}...")
                    
                    elif msg_type == "final":
                        print("\n" + "=" * 80)
                        print("FINAL RESULTS")
                        print("=" * 80)
                        source = data.get("source", "unknown")
                        count = data.get("count", 0)
                        summary = data.get("summary", "")
                        
                        print(f"Source: {source}")
                        print(f"Result Count: {count}")
                        print(f"\nSummary:\n{summary}")
                        
                        if data.get("spl"):
                            print(f"\nFinal SPL Query:\n{data['spl']}")
                        if data.get("vql"):
                            print(f"\nFinal VQL Query:\n{data['vql']}")
                        
                        break
                    
                    elif msg_type == "error":
                        print("\n" + "=" * 80)
                        print("ERROR")
                        print("=" * 80)
                        print(f"Title: {data.get('title', '')}")
                        print(f"Detail: {data.get('detail', '')}")
                        break
                
                except asyncio.TimeoutError:
                    print("\n⚠ Timeout waiting for response")
                    break
                except websockets.exceptions.ConnectionClosed:
                    print("\n⚠ Connection closed by server")
                    break
            
            print("\n" + "=" * 80)
            print("TEST SUMMARY")
            print("=" * 80)
            print(f"Total activity messages: {activity_count}")
            print(f"Reflection loop triggered: {'YES ✓' if saw_self_correction else 'NO ✗'}")
            
            if saw_self_correction:
                print("\n✓ SUCCESS: Reflection loop was activated!")
                print("  The agent detected an error and attempted self-correction.")
                return 0
            else:
                print("\n⚠ INFO: No reflection detected in this query.")
                print("  This might mean:")
                print("  - The query executed successfully on first try")
                print("  - The query didn't trigger an error condition")
                return 0
    
    except ConnectionRefusedError:
        print(f"✗ ERROR: Could not connect to {uri}")
        print("  Make sure the server is running on port 8005")
        return 1
    except Exception as e:
        print(f"✗ ERROR: {type(e).__name__}: {e}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(test_reflection_loop())
    sys.exit(exit_code)
