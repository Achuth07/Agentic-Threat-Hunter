from langchain_community.chat_models import ChatOllama
from langchain_core.messages import HumanMessage

# Initialize the connection to the local Ollama model
llm = ChatOllama(model="llama3:8b")

print("LLM Initialized. Sending test message...")

# Create a simple message
messages = [HumanMessage(content="Hello! How are you?")]

# Get a response from the model
response = llm.invoke(messages)

print("\nLLM Response:")
print(response.content)
