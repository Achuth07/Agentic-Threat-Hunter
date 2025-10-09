import os
import json
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
import splunklib.client as client
import splunklib.results as results
from splunklib.binding import HTTPError, AuthenticationError

# Load environment variables from the.env file
load_dotenv()

# --- READ SPLUNK CREDENTIALS FROM ENVIRONMENT ---
SPLUNK_HOST = "localhost"
SPLUNK_PORT = 8089
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD")

# --- TOOL DEFINITION ---
@tool
def execute_splunk_search(spl_query: str) -> str:
    """
    Executes a given Splunk Search Processing Language (SPL) query
    and returns the results in JSON format. The input must be a complete 
    and valid SPL query string.
    """
    print(f"\n--- AGENT IS USING SPLUNK TOOL ---\nQuery: {spl_query}\n----------------------------------\n")
    try:
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD
        )
        kwargs = {"output_mode": "json"}
        reader = service.jobs.export(spl_query, **kwargs)
        search_results = []
        for result in results.JSONResultsReader(reader):
            search_results.append(result)

        if not search_results:
            return "Search executed successfully, but returned no results."

        formatted_results = json.dumps(search_results, indent=2)
        return formatted_results

    except AuthenticationError as e:
        return f"Splunk Authentication Error: {str(e)}"
    except HTTPError as e:
        error_details = ""
        try:
            error_details = e.body.read().decode("utf-8")
        except Exception:
            error_details = str(e)
        return f"Splunk API Error: {e.status} {e.reason}. Details: {error_details}"
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"

# --- AGENT SETUP ---
if __name__ == "__main__":
    # 1. Define the prompt template
    # This tells the LLM its role and how to behave.
    prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a Splunk search assistant. 
    Your job is to output only valid Splunk SPL queries — no explanations, code blocks, or backticks.
    For example:
    User: "Find login failures"
    You: search index=auth sourcetype=secure action=failure | stats count"""),
    ("human", "{question}")
    ])

    # 2. Initialize the LLM
    llm = ChatOllama(model="llama3:8b")

    # 3. Create the agent chain
    # This chains the components together: Prompt -> LLM -> Output Parser -> Splunk Tool
    agent_chain = prompt | llm | StrOutputParser() | execute_splunk_search

    # 4. Define the user's question
    user_question = "How many internal logs were there in the last 5 minutes?"
    print(f"User Question: {user_question}\n")

    # 5. Invoke the agent
    # The agent will now run the full sequence.
    final_result = agent_chain.invoke({"question": user_question})

    # 6. Print the final result
    print("\n--- FINAL RESULT ---")
    try:
        final_json = json.loads(final_result)
        print(json.dumps(final_json, indent=2))
    except json.JSONDecodeError:
        print(final_result)