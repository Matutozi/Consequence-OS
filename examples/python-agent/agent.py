"""An agent calling tools through ConsequenceOS, with the official MCP Python SDK.

The only differences from calling the tool server directly: the URL is
ConsequenceOS's /mcp, and the agent sends its ConsequenceOS API key. The
results then tell the agent what happened:

- allowed: the tool's normal result (ConsequenceOS attached a receipt on the way);
- blocked by policy: an error result starting "Blocked by ConsequenceOS";
- held for a human: an error result starting "Approval pending", with an
  approval ID and a status link. Retry the same call once it's approved.

Run it against `make mock` and `make run` (or `make up`):

    pip install -r requirements.txt
    CONSEQUENCE_KEY_SUPPORT_BOT=dev-support-bot-key python agent.py
"""

import asyncio
import os

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

URL = os.environ.get("CONSEQUENCE_URL", "http://127.0.0.1:8080/mcp")
API_KEY = os.environ["CONSEQUENCE_KEY_SUPPORT_BOT"]


def text_of(result) -> str:
    return " ".join(c.text for c in result.content if c.type == "text")


def outcome(result) -> str:
    """Sort a tool result into what ConsequenceOS did with the call."""
    text = text_of(result)
    if not result.is_error:
        return "allowed"
    if text.startswith("Approval pending"):
        return "held for a human"
    if text.startswith("Blocked by ConsequenceOS"):
        return "blocked by policy"
    return "tool error"


async def main() -> None:
    # The API key goes in the Authorization header of every request.
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {API_KEY}"})
    async with http, Client(streamable_http_client(URL, http_client=http)) as client:
        tools = await client.list_tools()
        print("tools:", ", ".join(t.name for t in tools.tools))

        for amount in (20, 5000):
            result = await client.call_tool("payments.refund", {"charge_id": "ch_123", "amount": amount})
            print(f"\nrefund of ${amount}: {outcome(result)}\n  {text_of(result)}")


if __name__ == "__main__":
    asyncio.run(main())
