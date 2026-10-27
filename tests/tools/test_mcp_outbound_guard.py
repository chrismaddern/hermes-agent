"""Outbound destination guard on the MCP SDK's HTTP client stack."""

import socket

import httpx2
import pytest

from tools.mcp_tool_errors import _make_redirect_header_stripper
from tools.url_safety import SSRFConnectionBlocked


def _resolver(answers):
    def resolve(host, port, *args, **kwargs):
        ip = answers[host]
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    return resolve


@pytest.mark.asyncio
async def test_mcp_redirect_to_private_destination_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({
        "mcp.public.test": "93.184.216.34",
        "metadata.internal.test": "169.254.169.254",
    }))

    async def handler(request):
        return httpx2.Response(302, headers={"location": "http://metadata.internal.test/latest"})

    transport = httpx2.MockTransport(handler)
    transport.__dict__["_hermes_ssrf_guarded"] = True  # no sockets; request hooks are the boundary
    build_client = _make_redirect_header_stripper(
        httpx2, httpx2.URL("https://mcp.public.test/mcp"))
    async with build_client(transport=transport, follow_redirects=True) as client:
        with pytest.raises(SSRFConnectionBlocked, match="cloud metadata|private/internal"):
            await client.get("https://mcp.public.test/mcp")


@pytest.mark.asyncio
async def test_mcp_public_redirect_remains_unattended(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({
        "mcp.public.test": "93.184.216.34",
        "auth.public.test": "1.1.1.1",
    }))
    seen = []

    async def handler(request):
        seen.append(str(request.url))
        if request.url.host == "mcp.public.test":
            return httpx2.Response(302, headers={"location": "https://auth.public.test/mcp"})
        return httpx2.Response(200, json={"ok": True})

    transport = httpx2.MockTransport(handler)
    transport.__dict__["_hermes_ssrf_guarded"] = True  # no sockets; request hooks are the boundary
    build_client = _make_redirect_header_stripper(
        httpx2, httpx2.URL("https://mcp.public.test/mcp"))
    async with build_client(transport=transport, follow_redirects=True) as client:
        response = await client.get("https://mcp.public.test/mcp")

    assert response.status_code == 200
    assert seen == ["https://mcp.public.test/mcp", "https://auth.public.test/mcp"]


@pytest.mark.asyncio
async def test_mcp_dns_rebinding_is_blocked_at_connect(monkeypatch):
    answers = iter(("93.184.216.34", "127.0.0.1"))

    def resolve(_host, port, *_args, **_kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (next(answers), port),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    build_client = _make_redirect_header_stripper(
        httpx2, httpx2.URL("https://mcp.public.test/mcp")
    )
    async with build_client(trust_env=False) as client:
        with pytest.raises(SSRFConnectionBlocked, match="during connect"):
            await client.get("https://mcp.public.test/mcp")
