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
        
        # Extract the last message from the worker's result
        last_message = result["messages"][-1]
        
        # Wrap it to indicate origin (optional, or just append)
        # We can prepend "AgentName:" to the content if needed for clarity
        content = f"**{agent_name}**: {last_message.content}"
        return {
            "messages": [AIMessage(content=content)],
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
        llm = ChatOllama(model=model_name).bind_tools(tools)
        response = await llm.ainvoke(messages)
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
            
            import json
            if "query" in args and isinstance(args["query"], str):
                 # If the model correctly put the JSON string in 'query' arg
                 result = tool.invoke(args["query"])
            else:
                # If model outputted decomposed args
                action = args.get("query") or args.get("action")
                if action in ["execute_test", "list_tests"]:
                    real_args = {"action": action}
                    if "technique_id" in args:
                        real_args["technique_id"] = args["technique_id"]
                    if "test_number" in args:
                        real_args["test_number"] = args["test_number"]
                    result = tool.invoke(json.dumps(real_args))
                else:
                    # Fallback
                    result = tool.invoke(json.dumps(args))
            
            return {"messages": [ToolMessage(tool_call_id=tool_call["id"], content=str(result))]}
        
        # Check for JSON in content (Hallucinated tool call)
        content = last_message.content
        if content.strip().startswith("{") and "atomic_red_team" in content:
            try:
                import json
                data = json.loads(content)
                if data.get("name") == "atomic_red_team":
                    args = data.get("arguments", {})
                    tool = AtomicRedTeamTool()
                    # Check if 'query' is already the JSON string we need
                    if "query" in args and isinstance(args["query"], str):
                        try:
                            # Verify it's valid JSON and has action
                            inner = json.loads(args["query"])
                            if "action" in inner:
                                result = tool.invoke(args["query"])
                                return {"messages": [AIMessage(content=f"Tool Execution Result: {result}")]}
                        except:
                            pass

                    action = args.get("query") or args.get("action")
                    
                    if action in ["execute_test", "list_tests"]:
                        real_args = {"action": action}
                        if "technique_id" in args:
                            real_args["technique_id"] = args["technique_id"]
                        if "test_number" in args:
                            real_args["test_number"] = args["test_number"]
                        result = tool.invoke(json.dumps(real_args))
                    else:
                        result = tool.invoke(json.dumps(args))
                        
                    # We need a tool_call_id for ToolMessage, but we don't have one.
                    # So we return an AIMessage with the result, or inject a ToolMessage with a fake ID?
                    # If we return ToolMessage, the previous message must be an AIMessage with tool_calls.
                    # But the previous message didn't have tool_calls.
                    # So we should probably return an AIMessage representing the tool output, 
                    # or just append the result to the conversation as a SystemMessage or similar.
                    # Let's return an AIMessage with the result to simulate the agent seeing it.
                    return {"messages": [AIMessage(content=f"Tool Execution Result: {result}")]}
            except Exception as e:
                print(f"Failed to parse hallucinated tool call: {e}")
        
        return {"messages": []}

    workflow = StateGraph(AgentState)
    workflow.add_node("agent", red_team_node)
    workflow.add_node("tools", tool_node)
    
    workflow.add_edge("agent", "tools")
    workflow.add_edge("tools", END)
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
# --- Hunter Agent ---

def build_hunter_agent(model_name: str, splunk_fn, velociraptor_fn):
    """
    Creates the Hunter agent.
    For simplicity in this hierarchical setup, we will use a ReAct agent that has access 
    to the Splunk and Velociraptor tools.
    
    Note: To strictly preserve the 'Reflection Loop' logic from the previous iteration,
    we would need to nest that entire StateGraph here. 
    However, a ReAct agent with a good system prompt is often sufficient and easier to manage 
    as a sub-agent. Let's try ReAct first.
    """
    
    # Wrap the raw functions as LangChain tools
    from langchain_core.tools import tool

    @tool
    def search_splunk(query: str) -> str:
        """Execute a Splunk SPL search. Input is the SPL string."""
        # We need to handle the async/sync nature of the passed function
        # For ReAct, it expects synchronous tools or async tools.
        # We'll assume the executor handles the bridging or we use a wrapper.
        # Since we are inside an async node, we can call async functions if the tool supports it.
        # But standard LangChain tools are often sync.
        # Let's assume the passed 'splunk_fn' can be called.
        # If it's async, we might need a bridge.
        # For now, let's define this as a placeholder and handle the execution in the tool definition.
        pass 

    # Actually, we should pass the actual tool instances or wrappers.
    # Let's create simple wrappers.
    
    class SplunkTool(BaseModel):
        query: str = Field(description="The SPL query to execute")

    @tool("execute_splunk_search", args_schema=SplunkTool)
    def execute_splunk_search(query: str):
        """Execute a Splunk SPL query to find historical logs."""
        # This will be patched at runtime or we need to pass the callable properly.
        # A cleaner way is to pass the tools list to this builder.
        return splunk_fn(query)

    class VeloTool(BaseModel):
        query: str = Field(description="The VQL query to execute")

    @tool("run_velociraptor_query", args_schema=VeloTool)
    def run_velociraptor_query(query: str):
        """Execute a Velociraptor VQL query for live endpoint forensics."""
        return velociraptor_fn(query)

    tools = [execute_splunk_search, run_velociraptor_query]

    system_prompt = """You are a Threat Hunter.
Your goal is to find evidence of malicious activity in Splunk logs or on endpoints via Velociraptor.
1. Generate a valid SPL or VQL query based on the instructions.
2. Execute the query.
3. If it fails, analyze the error and retry.
4. Summarize your findings (e.g., "Found 5 failed logins for user X").
"""
    graph = create_react_agent(ChatOllama(model=model_name), tools, prompt=system_prompt)
    return graph


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



