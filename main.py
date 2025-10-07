import os
from dotenv import load_dotenv
from langchain_core.tools import tool
import splunklib.client as client
import splunklib.results as results
from splunklib.binding import HTTPError, AuthenticationError

# Load environment variables from the.env file
load_dotenv()

@tool
def execute_splunk_search(spl_query: str) -> str:
    """
    Executes a given Splunk Search Processing Language (SPL) query
    and returns the results. The input must be a complete and valid
    SPL query string.
    """
    print(f"\n--- Executing Splunk Search ---\nQuery: {spl_query}\n-----------------------------\n")
    try:
        # The client.connect() function will automatically use the.splunkrc file
        # for connection details if it exists in the home directory.
        service = client.connect()

        # Run a "oneshot" search. This is a synchronous search that waits for completion.
        kwargs_oneshot = {"exec_mode": "oneshot"}
        reader = service.jobs.export(spl_query, **kwargs_oneshot)

        # Parse the results
        search_results = []
        for result in results.ResultsReader(reader):
            search_results.append(dict(result))

        if not search_results:
            return "Search executed successfully, but returned no results."

        # Format the results into a readable string for the LLM
        formatted_results = "Search Results:\n"
        for i, result in enumerate(search_results[:5]): # Return max 5 results
            formatted_results += f"--- Result {i+1} ---\n"
            for key, value in result.items():
                formatted_results += f"  {key}: {value}\n"
        
        if len(search_results) > 5:
            formatted_results += f"\n... and {len(search_results) - 5} more results."

        return formatted_results

    except AuthenticationError as e:
        # Specific catch for login failures
        error_message = f"Splunk Authentication Error: Login failed. Please verify the username and password in your ~/.splunkrc file. Details: {str(e)}"
        print(f"Error: {error_message}")
        return error_message
    except HTTPError as e:
        # Catch other Splunk API errors, often due to invalid SPL
        error_message = f"Splunk API Error: {e.status} {e.reason}. Details: {e.message}"
        print(f"Error: {error_message}")
        return error_message
    except Exception as e:
        # Catch any other unexpected errors (like connection issues)
        error_message = f"An unexpected error occurred: {str(e)}"
        print(f"Error: {error_message}")
        return error_message

# --- Simple test for the tool ---
if __name__ == "__main__":
    print("Testing Splunk tool directly...")
    # This is a basic Splunk query that looks at internal logs.
    # It should always return some data on a healthy Splunk instance.
    test_query = 'search index=_internal | head 5'
    tool_response = execute_splunk_search.invoke({"spl_query": test_query})
    print("\nTool Response:")
    print(tool_response)