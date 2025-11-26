from __future__ import annotations

import json
import operator
from typing import Annotated, Any, Dict, List, Literal, Optional, Sequence, TypedDict, Union

from langchain_core.messages import BaseMessage, FunctionMessage, HumanMessage, AIMessage, SystemMessage, ToolMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END, START
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver
from pydantic import BaseModel, Field

# Import tools
from tools.web_tools import web_search, visit_page
from tools.atomic_red_team import AtomicRedTeamTool
from tools.sigma_tool import SigmaTool
from starlette.concurrency import run_in_threadpool

# --- State Definition ---

class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    next_agent: str
    instructions: str
    # Shared scratchpad for tool outputs (optional, if we want structured passing)
    tool_output: Optional[Dict[str, Any]] 

# --- Supervisor Node ---

class SupervisorOutput(BaseModel):
    thought: str = Field(description="The reasoning behind the decision")
    next_agent: Literal["ThreatIntel", "Hunter", "RedTeam", "Detection", "FINISH"] = Field(
        description="The next agent to act, or FINISH if the user's request is satisfied"
    )
    instructions_for_agent: str = Field(
        description="Specific instructions for the selected agent. If FINISH, provide the final answer."
    )

def build_supervisor_node(model_name: str):
    system_prompt = """You are the Supervisor (Manager) of a cybersecurity threat hunting team.
Your goal is to orchestrate the following specialized agents to solve complex security tasks:

1. **ThreatIntel**: Research external threats, CVEs, actor TTPs, and reputation (VirusTotal).
2. **Hunter**: Search internal logs (Splunk) and endpoint state (Velociraptor). Use this for investigating specific indicators or hunting for activity.
3. **RedTeam**: Execute Atomic Red Team tests to simulate attacks. **PRIORITY**: If the user mentions "simulate", "atomic", "T1003", or "attack", YOU MUST CHOOSE THIS AGENT.
4. **Detection**: Search and manage Sigma detection rules.

**Rules**:
- You do not execute tools yourself. You delegate to agents.
- You can chain multiple agents. E.g., RedTeam -> Hunter.
- When you have enough information to answer the user, or if the task is complete, choose "FINISH".
- Provide clear, concise instructions to the agents.
- If the user asks a general question, use ThreatIntel or answer directly if you know (then FINISH).

**Routing Logic**:
- If the user asks to 'simulate', 'test', 'attack', or run a 'T-code' (like T1003), route to 'RedTeam'.
- If the user asks to 'search logs', 'find events', 'investigate', route to 'Hunter'.
- If the user asks to 'research', 'google', 'check virustotal', route to 'Intel'.
- If the user asks about 'sigma rules', 'detection coverage', route to 'Detection'.

**Output Format**:
You MUST output a valid JSON object matching this schema:
{{
  "thought": "Your reasoning here...",
  "next_agent": "AgentName" (or "FINISH"),
  "instructions_for_agent": "Instructions..."
}}
"""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        MessagesPlaceholder(variable_name="messages"),
        (
            "system",
            "Given the conversation above, who should act next? Return ONLY the JSON object."
        ),
    ])
    
    llm = ChatOllama(model=model_name, format="json")

    async def supervisor_node(state: AgentState) -> AgentState:
        messages = state["messages"]
        
        # Invoke LLM
        response = await llm.ainvoke(prompt.format_messages(messages=messages))
        content = response.content
        print(f"DEBUG: Supervisor Raw Output: {content}")
        
        # Parse JSON
        try:
            data = json.loads(content)
            # Validate with Pydantic (optional but good for strictness)
            # output = SupervisorOutput(**data) # strict mode
            next_agent = data.get("next_agent", "FINISH")
            instructions = data.get("instructions_for_agent", "")
            
            # Validate next_agent
            valid_agents = ["ThreatIntel", "Hunter", "RedTeam", "Detection", "FINISH"]
            if next_agent not in valid_agents:
                print(f"WARNING: Supervisor hallucinated invalid agent '{next_agent}'. Defaulting to FINISH.")
                next_agent = "FINISH"
        except Exception as e:
            # Fallback if JSON fails
            print(f"Supervisor JSON Parse Error: {e}. Content: {content}")
            next_agent = "FINISH"
            instructions = "Error parsing supervisor decision. Terminating."

        return {
            "next_agent": next_agent,
            "instructions": instructions
        }

    return supervisor_node

# --- Worker Node Helpers ---

def create_agent_node(agent_name: str, agent_graph):
    """Wraps a subgraph or chain as a node in the supervisor graph."""
    async def agent_node(state: AgentState) -> AgentState:
        # Pass the global history + instructions to the agent
        instructions = state.get("instructions", "")
        messages = list(state["messages"])
        
        # Inject instructions as a system message or user message for the worker
        if instructions:
            messages.append(HumanMessage(content=instructions))
            
        # Invoke the worker graph
        # Note: The worker graph should return a dictionary with 'messages'
        # We assume the worker graph handles its own state and returns a final message
        result = await agent_graph.ainvoke({"messages": messages})
        
        # Extract new messages generated by the worker
        # result["messages"] contains [global_history + instructions + new_worker_messages]
        # We want to return [new_worker_messages] to update the global state
        new_messages = result["messages"][len(messages):]
        
        if not new_messages:
            return {
                "messages": [AIMessage(content=f"**{agent_name}**: No response.")],
                "next_agent": "Supervisor"
            }

        # The last message is the summary/final response
        last_message = new_messages[-1]
        
        # Update the content of the last message to include the Agent Name prefix
        # We create a new AIMessage to avoid mutating the original if it's shared
        summary_content = f"**{agent_name}**: {last_message.content}"
        final_message = AIMessage(content=summary_content)
        
        # Replace the last message with our prefixed version
        return_messages = new_messages[:-1] + [final_message]
        
        return {
            "messages": return_messages,
            "next_agent": "Supervisor" # Return control to supervisor
        }
    
    return agent_node

# --- Threat Intel Agent ---

def build_intel_agent(model_name: str):
    """Creates the Threat Intel agent subgraph."""
    # Tools for Intel
    tools = [web_search, visit_page] # Add check_virustotal if wrapped as LangChain tool
    
    # Simple ReAct agent for Intel
    # We use a system prompt to encourage summarization
    system_prompt = """You are a Threat Intelligence Researcher.
Your goal is to find information about CVEs, Threat Actors, and IOCs.
Use the available tools to gather information.
IMPORTANT: After gathering information, you MUST summarize your findings in a clear, concise manner.
Do not just dump raw data. Explain what it means for the security posture.
"""
    graph = create_react_agent(ChatOllama(model=model_name), tools, prompt=system_prompt)
    return graph

# --- Red Team Agent (HITL) ---

def build_red_team_agent(model_name: str):
    """Creates the Red Team agent subgraph."""
    # Tools
    tools = [AtomicRedTeamTool()]
    
    # Custom Red Team Graph to handle model output quirks
    
    async def red_team_node(state: AgentState):
        messages = state["messages"]
        # Inject detailed system prompt if not present
        from langchain_core.messages import SystemMessage
        
        system_prompt_text = """You are a Red Team Operator.
Your goal is to execute Atomic Red Team tests to simulate attacks.
You have access to a tool called 'atomic_red_team'.
YOU MUST USE THIS TOOL to execute tests. DO NOT just describe what you would do.

1. First, identify the correct test (Technique ID) based on the user's request.
2. Call the 'atomic_red_team' tool with action='execute_test' and the technique_id.
   - Example: {"action": "execute_test", "technique_id": "T1003"}
   - YOU MUST PROVIDE 'action'. Valid actions: 'execute_test', 'list_tests'.
3. WAIT for the tool output.
4. Summarize the execution results IN DETAIL.
   - List EACH test command that was executed.
   - State whether it PASSED or FAILED.
   - Provide the return code and relevant output for each.
   - Do NOT just say "Total tests executed". Show the breakdown.
"""
        # Check if system prompt is already there (it might be passed from Supervisor instructions)
        # But we want to enforce OUR prompt.
        # We'll prepend it as a SystemMessage.
        
        # Filter out old system messages if any to avoid confusion
        filtered_messages = [m for m in messages if not isinstance(m, SystemMessage)]
        
        final_messages = [SystemMessage(content=system_prompt_text)] + filtered_messages
        
        llm = ChatOllama(model=model_name).bind_tools(tools)
        response = await llm.ainvoke(final_messages)
        return {"messages": [response]}

    async def tool_node(state: AgentState):
        messages = state["messages"]
        last_message = messages[-1]
        
        # Check for standard tool calls
        if last_message.tool_calls:
            tool_call = last_message.tool_calls[0]
            tool = AtomicRedTeamTool()
            args = tool_call["args"]
            
            # Fix args mapping
            # The tool expects 'query' string if called directly via _run, 
            # but invoke() with dict args maps to _run arguments? 
            # Actually BaseTool.invoke(dict) passes dict to _run if _run expects dict?
            # No, BaseTool.invoke handles parsing.
            # AtomicRedTeamTool._run takes 'query: str'.
            # If we pass a dict to invoke, it might fail if not handled.
            # Let's construct the JSON string manually to be safe.
            
            # import json  <-- Removed to fix UnboundLocalError
            
            with open("/home/achuth/agentic-hunter/debug_redteam.log", "a") as f:
                f.write(f"DEBUG: Standard Tool Call Args: {args}\n")

            if "query" in args and isinstance(args["query"], str):
                 # If the model correctly put the JSON string in 'query' arg
                 query_str = args["query"]
                 try:
                     # Try to parse and fix missing action in the JSON string
                     query_json = json.loads(query_str)
                     if isinstance(query_json, dict):
                          action = query_json.get("action")
                          # Handle None, "None", or missing action, or invalid action string
                          if (not action or str(action) == "None" or action not in ["execute_test", "list_tests"]) and "technique_id" in query_json:
                              query_json["action"] = "execute_test"
                              query_str = json.dumps(query_json)
                 except:
                     pass # If not JSON or parse error, pass as is
                     
                 result = await run_in_threadpool(tool.invoke, query_str)
            else:
                # If model outputted decomposed args
                action = args.get("query") or args.get("action")
                
                # Robustness: If action is missing/invalid but technique_id is present, assume execute_test
                # Handle None, "None", or missing action
                
                with open("/home/achuth/agentic-hunter/debug_redteam.log", "a") as f:
                    f.write(f"DEBUG: Decomposed Args: {args}, Action: {action}\n")

                if (not action or str(action).strip() == "None" or action not in ["execute_test", "list_tests"]) and "technique_id" in args:
                    action = "execute_test"
                    args["action"] = action
                    with open("/home/achuth/agentic-hunter/debug_redteam.log", "a") as f:
                        f.write(f"DEBUG: Injected action (decomposed). New action: {action}\n")
                
                if action in ["execute_test", "list_tests"]:
                    # Ensure 'action' key has a valid value (handle both missing and None)
                    # Ensure 'action' key has a valid value (handle both missing and None)
                    current_action = args.get("action")
                    if not current_action or str(current_action) == "None":
                        args["action"] = action
                    
                    # Reconstruct JSON
                    json_input = json.dumps(args)
                    result = await run_in_threadpool(tool.invoke, json_input)
                else:
                    # Fallback
                    result = await run_in_threadpool(tool.invoke, json.dumps(args))
            
            return {"messages": [ToolMessage(tool_call_id=tool_call["id"], content=str(result))]}
        
        # Check for JSON in content (Hallucinated tool call)
        content = last_message.content.strip()
        # Strip markdown code blocks if present
        if content.startswith("```json"):
            content = content[7:]
        elif content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        if content.startswith("{") and ("atomic_red_team" in content or "technique_id" in content):
            try:
                # Parse the JSON to get args
                # The tool expects a string input (JSON string)
                # We can just pass the content directly if it's valid JSON
                
                tool = AtomicRedTeamTool()
                
                # Parse and fix missing action
                # Parse and fix missing action
                try:
                    args = json.loads(content)
                    if isinstance(args, dict):
                        # Handle nested arguments (e.g. {"name": "...", "arguments": {...}})
                        if "arguments" in args and isinstance(args["arguments"], dict):
                            args = args["arguments"]
                        
                        action = args.get("action")
                        # Handle None, "None", or missing action
                        if (not action or str(action) == "None") and "technique_id" in args:
                            args["action"] = "execute_test"
                        
                        # Update content with the (potentially extracted and fixed) args
                        content = json.dumps(args)
                except:
                    pass # If parse fails, pass content as is
                
                # We pass the JSON string directly
                result = await run_in_threadpool(tool.invoke, content)
                
                # Return HumanMessage for hallucinated calls so the agent sees it as a result to summarize
                return {"messages": [HumanMessage(content=f"Tool Execution Result: {result}")]}
                
                # Return HumanMessage for hallucinated calls so the agent sees it as a result to summarize
                return {"messages": [HumanMessage(content=f"Tool Execution Result: {result}")]}
            except Exception as e:
                print(f"Failed to parse hallucinated tool call: {e}")
    
        return {"messages": []}

    def should_continue(state: AgentState):
        messages = state["messages"]
        last_message = messages[-1]
        if last_message.tool_calls:
            return "tools"
        
        # Check for hallucinated tool calls
        content = last_message.content.strip()
        if content.startswith("```json"):
            content = content[7:]
        elif content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()
        
        if content.startswith("{") and ("atomic_red_team" in content or "technique_id" in content):
            return "tools"
            
        return END

    workflow = StateGraph(AgentState)
    workflow.add_node("agent", red_team_node)
    workflow.add_node("tools", tool_node)
    
    workflow.add_conditional_edges("agent", should_continue, ["tools", END])
    workflow.add_edge("tools", "agent")
    
    workflow.set_entry_point("agent")
    
    return workflow.compile()

# --- Detection Agent ---

def build_detection_agent(model_name: str):
    """Creates the Detection Engineer agent subgraph."""
    # Tools
    tools = [SigmaTool()]
    
    system_prompt = """You are a Detection Engineer.
Your goal is to find or create detection rules (Sigma, SPL, VQL).
1. Search for relevant Sigma rules.
2. Convert them to SPL or VQL if requested.
3. Provide the rule content or query to the user.
"""
    graph = create_react_agent(ChatOllama(model=model_name), tools, prompt=system_prompt)
    return graph

# --- Hunter Agent ---

def build_hunter_agent(model_name: str, splunk_fn, velociraptor_fn):
    """
    Creates the Hunter agent with custom graph to handle tool call quirks.
    """
    
    # Wrap the raw functions as LangChain tools
    from langchain_core.tools import tool
    from langchain_core.messages import ToolMessage, AIMessage

    class SplunkTool(BaseModel):
        query: str = Field(description="The SPL query to execute")

    @tool("execute_splunk_search", args_schema=SplunkTool)
    def execute_splunk_search(query: str):
        """Execute a Splunk SPL query to find historical logs."""
        return splunk_fn(query)

    class VeloTool(BaseModel):
        query: str = Field(description="The VQL query to execute")

    @tool("run_velociraptor_query", args_schema=VeloTool)
    def run_velociraptor_query(query: str):
        """Execute a Velociraptor VQL query for live endpoint forensics."""
        return velociraptor_fn(query)

    tools = [execute_splunk_search, run_velociraptor_query]

    async def hunter_node(state: AgentState):
        messages = state["messages"]
        llm = ChatOllama(model=model_name).bind_tools(tools)
        response = await llm.ainvoke(messages)
        return {"messages": [response]}

    async def tool_node(state: AgentState):
        messages = state["messages"]
        last_message = messages[-1]
        
        # Check for standard tool calls
        if last_message.tool_calls:
            results = []
            for tool_call in last_message.tool_calls:
                t_name = tool_call["name"]
                t_args = tool_call["args"]
                
                result = "Error: Unknown tool"
                if t_name == "execute_splunk_search":
                    q = t_args.get("query")
                    if q: result = splunk_fn(q)
                    else: result = "Error: Missing query"
                elif t_name == "run_velociraptor_query":
                    q = t_args.get("query")
                    if q: result = velociraptor_fn(q)
                    else: result = "Error: Missing query"
                
                results.append(ToolMessage(tool_call_id=tool_call["id"], content=str(result)))
            return {"messages": results}

        # Check for JSON in content (Hallucinated tool call)
        content = last_message.content.strip()
        # Strip markdown code blocks if present
        if content.startswith("```json"):
            content = content[7:]
        elif content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        if content.startswith("{") and ("execute_splunk_search" in content or "run_velociraptor_query" in content):
            try:
                import json
                data = json.loads(content)
                name = data.get("name")
                args = data.get("arguments", {})
                
                result = "Error: Unknown tool"
                if name == "execute_splunk_search":
                    q = args.get("query")
                    if q: result = splunk_fn(q)
                    else: result = "Error: Missing query"
                elif name == "run_velociraptor_query":
                    q = args.get("query")
                    if q: result = velociraptor_fn(q)
                    else: result = "Error: Missing query"
                
                # Return HumanMessage for hallucinated calls so the agent sees it as a result to summarize
                return {"messages": [HumanMessage(content=f"Tool Execution Result: {result}")]}
            except Exception as e:
                print(f"Failed to parse hallucinated tool call: {e}")
        
        return {"messages": []}

    def should_continue(state: AgentState):
        messages = state["messages"]
        last_message = messages[-1]
        if last_message.tool_calls:
            return "tools"
        
        # Check for hallucinated tool calls
        content = last_message.content.strip()
        if content.startswith("```json"):
            content = content[7:]
        elif content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()
        
        if content.startswith("{") and ("execute_splunk_search" in content or "run_velociraptor_query" in content):
            return "tools"
            
        return END

    workflow = StateGraph(AgentState)
    workflow.add_node("agent", hunter_node)
    workflow.add_node("tools", tool_node)
    
    workflow.add_conditional_edges("agent", should_continue, ["tools", END])
    workflow.add_edge("tools", "agent")
    
    workflow.set_entry_point("agent")
    
    return workflow.compile()


# --- Main Graph Construction ---

def build_hierarchical_graph(
    splunk_execute_fn: Any,
    velociraptor_fn: Any,
    supervisor_model: str,
    worker_model: str,
):
    # Build Worker Agents
    intel_agent = build_intel_agent(worker_model)
    red_team_agent = build_red_team_agent(worker_model)
    detection_agent = build_detection_agent(worker_model)
    
    # Hunter needs the execution functions
    # We need to ensure these functions are compatible with the tool wrappers
    # For now, we assume they are synchronous or we wrap them.
    # If they are async, we might need `async_tool`.
    hunter_agent = build_hunter_agent(worker_model, splunk_execute_fn, velociraptor_fn)

    # Build Supervisor
    supervisor_node = build_supervisor_node(supervisor_model)

    # Create Graph
    graph = StateGraph(AgentState)
    
    print(f"DEBUG: intel_agent type: {type(intel_agent)}")
    intel_node = create_agent_node("ThreatIntel", intel_agent)
    print(f"DEBUG: intel_node type: {type(intel_node)}")

    graph.add_node("Supervisor", supervisor_node)
    graph.add_node("ThreatIntel", intel_node)
    graph.add_node("Hunter", create_agent_node("Hunter", hunter_agent))
    graph.add_node("RedTeam", create_agent_node("RedTeam", red_team_agent))
    graph.add_node("Detection", create_agent_node("Detection", detection_agent))

    # Edges
    graph.add_edge(START, "Supervisor")
    
    # Conditional Edges from Supervisor
    def route_supervisor(state: AgentState):
        next_node = state["next_agent"]
        if next_node == "FINISH":
            return END
        return next_node

    graph.add_conditional_edges(
        "Supervisor",
        route_supervisor,
        {
            "ThreatIntel": "ThreatIntel",
            "Hunter": "Hunter",
            "RedTeam": "RedTeam",
            "Detection": "Detection",
            END: END
        }
    )

    # Workers always return to Supervisor
    graph.add_edge("ThreatIntel", "Supervisor")
    graph.add_edge("Hunter", "Supervisor")
    graph.add_edge("RedTeam", "Supervisor")
    graph.add_edge("Detection", "Supervisor")

    # Compile with Interrupts for HITL
    # We want to interrupt BEFORE the RedTeam agent executes.
    # Since "RedTeam" node wraps the agent, interrupting before "RedTeam" means 
    # the supervisor has decided to call it, but it hasn't run yet.
    # This gives the user a chance to approve "next_agent": "RedTeam".
    
    # IMPORTANT: interrupt_before requires a checkpointer
    checkpointer = MemorySaver()
    return graph.compile(interrupt_before=["RedTeam"], checkpointer=checkpointer)


