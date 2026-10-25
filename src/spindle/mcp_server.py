from __future__ import annotations

import logging
import os
import sys
from typing import Optional

from mcp.server.mcpserver import Context, MCPServer
from spindle.config import config
from spindle.gateway import check_approval as gw_check_approval
from spindle.gateway import permissions as gw_permissions
from spindle.gateway import read as gw_read
from spindle.gateway import search as gw_search
from spindle.gateway import send_email as gw_send_email

# NEVER write logs to stdout! All stdout is reserved for JSON-RPC MCP messages.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(config.log_path, encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ],
)
logger = logging.getLogger("spindle.mcp")

server = MCPServer("spindle")


def get_agent_from_context(ctx: Optional[Context] = None) -> str:
    """Resolves agent identity per-call from MCP request headers, falling back to SPINDLE_AGENT."""
    if ctx is not None:
        try:
            headers = ctx.headers
            if headers:
                auth = headers.get("authorization") or headers.get("Authorization")
                if auth:
                    from spindle.cloud import get_authenticated_agent_from_key

                    agent = get_authenticated_agent_from_key(auth)
                    if agent:
                        return agent
        except Exception:
            pass
    return os.environ.get("SPINDLE_AGENT", config.agent)


@server.tool(
    description=(
        "Search the user's inbox. Standard Gmail operators like newer_than:7d are accepted. "
        "Returns a summary of matching messages. Results are filtered by the user's Spindle "
        "privacy policy; withheld items are listed with reasons."
    )
)
def search_email(
    query: str = "",
    max_results: Optional[int] = None,
    ctx: Optional[Context] = None,
) -> str:
    agent = get_agent_from_context(ctx)
    logger.info("search_email called by agent '%s' with query='%s'", agent, query)
    return gw_search(agent=agent, query=query, max_results=max_results)


@server.tool(
    description=(
        "Read the full contents of one email by ID. Results are filtered by the user's "
        "Spindle privacy policy; withheld items are listed with reasons."
    )
)
def read_email(email_id: str, ctx: Optional[Context] = None) -> str:
    agent = get_agent_from_context(ctx)
    logger.info("read_email called by agent '%s' for email_id='%s'", agent, email_id)
    return gw_read(agent=agent, email_id=email_id)


@server.tool(
    description="Check the status of a pending approval request previously returned by search_email or read_email."
)
def check_approval(request_id: int, ctx: Optional[Context] = None) -> str:
    agent = get_agent_from_context(ctx)
    logger.info("check_approval called by agent '%s' for request_id=%d", agent, request_id)
    return gw_check_approval(agent=agent, request_id=request_id)


@server.tool(
    description="Send an email to specified recipients. Governed by Spindle privacy policies, recipient allowlists, secret exfiltration scanning, and rate limits."
)
def send_email(to: list[str], subject: str, body: str, ctx: Optional[Context] = None) -> str:
    agent = get_agent_from_context(ctx)
    logger.info("send_email called by agent '%s' to=%s subject='%s'", agent, to, subject)
    return gw_send_email(agent=agent, to=to, subject=subject, body=body)


@server.tool(
    description="List the privacy policies and category access rules that govern this agent."
)
def my_permissions(ctx: Optional[Context] = None) -> str:
    agent = get_agent_from_context(ctx)
    logger.info("my_permissions called by agent '%s'", agent)
    return gw_permissions(agent=agent)


def main() -> None:
    agent = os.environ.get("SPINDLE_AGENT", config.agent)
    llm_type = "local" if config.llm_is_local() else "cloud"
    logger.info(
        "Starting Spindle MCP server over stdio for agent '%s' (LLM endpoint: %s [%s], model: %s)...",
        agent,
        config.llm_base_url,
        llm_type,
        config.llm_model,
    )
    server.run("stdio")


if __name__ == "__main__":
    main()
