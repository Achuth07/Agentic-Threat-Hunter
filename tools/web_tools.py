import os
from duckduckgo_search import DDGS
from langchain_community.document_loaders import WebBaseLoader

def web_search(query: str) -> str:
    """
    Perform a web search using DuckDuckGo.
    Useful for finding general information, news, or documentation.
    """
    try:
        results = DDGS().text(query, max_results=5)
        if not results:
            return "No results found."
        return "\n\n".join([f"Title: {r['title']}\nURL: {r['href']}\nSnippet: {r['body']}" for r in results])
    except Exception as e:
        return f"Error performing web search: {str(e)}"

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
