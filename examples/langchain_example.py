"""Minimal LangChain example using the security proxy."""
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="llama3",
    api_key="dummy-key",  # required param but not validated by proxy
    base_url="http://localhost:8000/v1",
)

if __name__ == "__main__":
    print(llm.invoke("Hello from LangChain!"))
