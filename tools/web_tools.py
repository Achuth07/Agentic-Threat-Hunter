import os
import requests
from tavily import TavilyClient
from langchain_community.document_loaders import WebBaseLoader

def web_search(query: str) -> str:
    """
    Perform a web search using Tavily AI (primary) or Jina AI (fallback).
    Useful for finding general information, news, or documentation.
    """
    # 1. Try Tavily AI (if API key is present)
    tavily_key = os.getenv("TAVILY_API_KEY")
    print(f"DEBUG: Tavily Key Present: {bool(tavily_key)}")
    if tavily_key:
        try:
            client = TavilyClient(api_key=tavily_key)
            # search_depth="advanced" gives better results for research
            response = client.search(query, search_depth="advanced", max_results=5)
            results = response.get("results", [])
            if results:
                return "\n\n".join([f"Title: {r['title']}\nURL: {r['url']}\nSnippet: {r['content']}" for r in results])
        except Exception as e:
            print(f"Tavily search failed: {e}. Falling back to Jina AI.")

    # 2. Fallback to Jina AI Reader (Search Mode)
    # Jina Reader can search by prepending https://s.jina.ai/ to the query
    try:
        # URL encode the query
        import urllib.parse
        encoded_query = urllib.parse.quote(query)
        jina_url = f"https://s.jina.ai/{encoded_query}"
        
        # Use requests to get the content
        headers = {"User-Agent": "AgenticThreatHunter/1.0"}
        response = requests.get(jina_url, headers=headers, timeout=10)
        if response.status_code == 200:
            return f"Source: Jina AI Search\n\n{response.text[:8000]}"
        else:
            return f"Jina AI search failed with status {response.status_code}"
    except Exception as e:
        return f"Error performing web search (Tavily & Jina failed): {str(e)}"

def visit_page(url: str) -> str:
    """
    Visit a web page and extract its text content.
    Useful for reading documentation, articles, or threat reports found via search.
    """
    try:
        loader = WebBaseLoader(url)
        docs = loader.load()
        # Combine content from all loaded documents (usually just one)
        content = "\n\n".join([d.page_content for d in docs])
        # Limit content length to avoid overflowing context window
        return content[:8000]
    except Exception as e:
        return f"Error visiting page {url}: {str(e)}"
