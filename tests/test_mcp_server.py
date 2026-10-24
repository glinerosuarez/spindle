import os
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from spindle.config import config


@pytest.mark.anyio
async def test_mcp_server_work_agent():
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "spindle-mcp"],
        env={
            **os.environ,
            "SPINDLE_HOME": str(config.home),
            "LLM_ENABLED": "false",
            "SPINDLE_AGENT": "work-agent",
            "SPINDLE_APPROVAL_TIMEOUT": "1",
        },
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. List tools
            tool_resp = await session.list_tools()
            tool_names = [t.name for t in tool_resp.tools]
            assert "search_email" in tool_names
            assert "read_email" in tool_names
            assert "check_approval" in tool_names
            assert "my_permissions" in tool_names

            # 2. Call permissions
            perm_res = await session.call_tool("my_permissions", {})
            perm_text = perm_res.content[0].text
            assert "Spindle Privacy Policy for agent 'work-agent'" in perm_text
            assert "travel: allow" in perm_text

            # 3. Call search_email
            search_res = await session.call_tool("search_email", {"query": ""})
            search_text = search_res.content[0].text
            assert "Withheld by policy:" in search_text
            assert "Quarantined:" in search_text
            assert "Pending approval:" in search_text
            assert "[e08]" in search_text

            # 4. Call read_email
            read_res = await session.call_tool("read_email", {"email_id": "e08"})
            read_text = read_res.content[0].text
            assert "Email [e08]" in read_text


@pytest.mark.anyio
async def test_mcp_server_unprotected():
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "spindle-mcp"],
        env={
            **os.environ,
            "SPINDLE_HOME": str(config.home),
            "LLM_ENABLED": "false",
            "SPINDLE_AGENT": "unprotected",
        },
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            search_res = await session.call_tool("search_email", {"query": ""})
            search_text = search_res.content[0].text
            assert 'unfiltered passthrough access for agent "unprotected"' in search_text
            assert "482913" in search_text
