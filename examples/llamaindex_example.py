"""Minimal LlamaIndex example using the security proxy."""
from llama_index.core import Settings
from llama_index.llms.openai import OpenAI

Settings.llm = OpenAI(
    model="llama3",
    api_base="http://localhost:8000/v1",
    api_key="dummy-key",
)

if __name__ == "__main__":
    response = Settings.llm.chat("Hello from LlamaIndex!")
    print(response)
