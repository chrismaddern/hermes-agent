"""Keepalive httpx clients share one HTTPTransport per (verify, proxy) identity.

Every AIAgent (and every delegated child) gets its own ``httpx.Client`` — the
#10933 contract that closing one client must never poison the next. What is
shared underneath is the connection pool + SSL context, so a fan-out of N
children no longer holds N TLS socket sets to the same provider.
"""

import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import certifi
import httpx
import pytest

from agent import process_bootstrap
from agent.agent_runtime_helpers import _iter_pool_sockets, force_close_tcp_sockets
from agent.process_bootstrap import build_keepalive_http_client
from tools.url_safety import SSRFConnectionBlocked, _reset_allow_private_cache


@pytest.fixture
def no_proxy_env(monkeypatch):
    for name in (
        "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
        "https_proxy", "http_proxy", "all_proxy", "NO_PROXY", "no_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    process_bootstrap.close_shared_transports()
    yield
    process_bootstrap.close_shared_transports()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive so pooled connections persist

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@pytest.fixture
def local_server(monkeypatch):
    monkeypatch.setenv("HERMES_ALLOW_PRIVATE_URLS", "true")
    _reset_allow_private_cache()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        _reset_allow_private_cache()


def _inner(client, scheme="https://"):
    mount = next(t for pat, t in client._mounts.items() if str(pat.pattern) == scheme)
    return mount._inner


def test_same_identity_clients_share_transport_but_not_client(no_proxy_env):
    a = build_keepalive_http_client("https://api.example.com/v1")
    b = build_keepalive_http_client("https://api.example.com/v1")
    assert isinstance(a, httpx.Client) and isinstance(b, httpx.Client)
    assert a is not b
    assert _inner(a) is _inner(b)
    assert _inner(a, "http://") is _inner(b, "http://")
    # The per-client view is distinct, so each client has its own close state.
    assert a._mounts is not b._mounts
    a.close()
    b.close()


def test_model_client_blocks_private_destination_before_proxy_or_socket(no_proxy_env, monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )
    client = build_keepalive_http_client("https://model.example/v1")
    try:
        with pytest.raises(SSRFConnectionBlocked, match="private/internal"):
            client.get("https://model.example/v1/models")
    finally:
        client.close()


def test_model_client_blocks_dns_rebinding_at_connect(no_proxy_env, monkeypatch):
    answers = iter(("93.184.216.34", "127.0.0.1"))

    def resolve(_host, port, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (next(answers), port))]

    monkeypatch.setattr("socket.getaddrinfo", resolve)
    client = build_keepalive_http_client("https://model.example/v1")
    try:
        with pytest.raises(SSRFConnectionBlocked, match="during connect"):
            client.get("https://model.example/v1/models")
    finally:
        client.close()


def test_model_client_allows_public_destination(no_proxy_env, monkeypatch):
    import httpcore
    from httpcore._backends.sync import SyncBackend

    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    attempts = []

    def stop_before_network(
        _backend, host, port, timeout=None, local_address=None, socket_options=None
    ):
        attempts.append((host, port))
        raise httpcore.ConnectError("public destination reached the dial boundary")

    monkeypatch.setattr(SyncBackend, "connect_tcp", stop_before_network)
    client = build_keepalive_http_client("https://model.example/v1")
    try:
        with pytest.raises(httpx.ConnectError, match="dial boundary"):
            client.get("https://model.example/v1/models")
    finally:
        client.close()
    assert attempts == [("93.184.216.34", 443)]


def test_model_client_guard_installation_failure_is_not_an_unguarded_fallback(
    no_proxy_env, monkeypatch
):
    def refuse_guard(*_args, **_kwargs):
        raise SSRFConnectionBlocked("guard unavailable")

    monkeypatch.setattr(
        "tools.url_safety.install_ssrf_guard_on_transport", refuse_guard
    )

    with pytest.raises(SSRFConnectionBlocked, match="guard unavailable"):
        build_keepalive_http_client("https://model.example/v1")


def test_model_client_proxy_path_still_rejects_private_target(no_proxy_env, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("10.0.0.8", 443))],
    )
    client = build_keepalive_http_client("https://model.example/v1")
    try:
        with pytest.raises(SSRFConnectionBlocked, match="private/internal"):
            for hook in client._event_hooks["request"]:
                hook(httpx.Request("GET", "https://model.example/v1/models"))
    finally:
        client.close()


def test_model_client_proxy_dns_failure_fails_closed(no_proxy_env, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        socket.gaierror("direct DNS unavailable")))
    client = build_keepalive_http_client("https://model.example/v1")
    try:
        with pytest.raises(SSRFConnectionBlocked, match="DNS resolution failed"):
            for hook in client._event_hooks["request"]:
                hook(httpx.Request("GET", "https://model.example/v1/models"))
    finally:
        client.close()


def test_private_url_opt_out_does_not_share_a_guarded_pool(no_proxy_env, monkeypatch):
    monkeypatch.setenv("HERMES_ALLOW_PRIVATE_URLS", "true")
    _reset_allow_private_cache()
    permissive = build_keepalive_http_client("https://model.example/v1")

    monkeypatch.setenv("HERMES_ALLOW_PRIVATE_URLS", "false")
    _reset_allow_private_cache()
    guarded = build_keepalive_http_client("https://model.example/v1")
    try:
        assert _inner(permissive) is not _inner(guarded)
    finally:
        permissive.close()
        guarded.close()


def test_closing_one_client_leaves_sibling_functional(no_proxy_env, local_server):
    a = build_keepalive_http_client(local_server)
    b = build_keepalive_http_client(local_server)
    assert _inner(a, "http://") is _inner(b, "http://")
    assert a.get(local_server + "/x").status_code == 200
    a.close()
    assert a.is_closed
    # #10933 shape: the shared pool must still serve the surviving client and
    # any successor client built after the close.
    assert b.get(local_server + "/y").status_code == 200
    c = build_keepalive_http_client(local_server)
    assert _inner(c, "http://") is _inner(b, "http://")
    assert c.get(local_server + "/z").status_code == 200
    with pytest.raises(RuntimeError):
        a.get(local_server + "/closed")
    b.close()
    c.close()


def test_pool_survives_client_close(no_proxy_env, local_server):
    a = build_keepalive_http_client(local_server)
    a.get(local_server + "/warm")
    pool = _inner(a, "http://")._pool
    before = len(pool.connections)
    assert before >= 1
    a.close()
    assert len(pool.connections) == before, "client close must not drain the shared pool"


def test_different_verify_or_proxy_get_different_transports(no_proxy_env, monkeypatch):
    default = build_keepalive_http_client("https://api.example.com/v1")
    insecure = build_keepalive_http_client("https://api.example.com/v1", verify=False)
    ctx = ssl.create_default_context(cafile=certifi.where())
    with_ctx = build_keepalive_http_client("https://api.example.com/v1", verify=ctx)
    with_ctx2 = build_keepalive_http_client("https://api.example.com/v1", verify=ctx)
    codex = build_keepalive_http_client("https://chatgpt.com/backend-api/codex")
    assert _inner(default) is not _inner(insecure)
    assert _inner(default) is not _inner(with_ctx)
    assert _inner(with_ctx) is _inner(with_ctx2)
    assert _inner(with_ctx)._pool._ssl_context is ctx
    assert _inner(insecure)._pool._ssl_context.check_hostname is False
    # Codex cloud gets the happy-eyeballs backend, so it can't share a pool.
    assert _inner(codex) is not _inner(default)
    assert isinstance(
        _inner(codex)._pool._network_backend._backend,
        process_bootstrap._HappyEyeballsSyncBackend,
    )
    for c in (default, insecure, with_ctx, with_ctx2, codex):
        c.close()

    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
    proxied = build_keepalive_http_client("https://api.example.com/v1")
    # Proxy clients keep httpx's own per-client proxy transport (unshared).
    assert all(
        type(t).__name__ != "_SharedTransport" for t in proxied._mounts.values() if t
    )
    proxied.close()




def test_force_close_only_touches_owning_clients_inflight_sockets(no_proxy_env, local_server):
    """A stranger-thread abort on client A must not shut down client B's
    idle/in-flight connections that live on the same shared pool."""
    a = build_keepalive_http_client(local_server)
    b = build_keepalive_http_client(local_server)
    b.get(local_server + "/warm")  # idle keepalive connection on the shared pool
    pool = _inner(a, "http://")._pool
    assert pool.connections
    # A has nothing in flight: nothing of A's may be touched.
    assert list(_iter_pool_sockets(a)) == []
    assert force_close_tcp_sockets(a) == 0
    # B's idle connection is still healthy.
    assert b.get(local_server + "/again").status_code == 200

    # Now hold a B stream open and confirm A's abort still sees zero sockets
    # while B's abort sees exactly its own.
    with b.stream("GET", local_server + "/stream") as resp:
        assert resp.status_code == 200
        assert list(_iter_pool_sockets(a)) == []
        assert len(list(_iter_pool_sockets(b))) == 1
    a.close()
    b.close()


def test_shared_transport_cache_is_bounded(no_proxy_env, monkeypatch):
    monkeypatch.setattr(process_bootstrap, "_SHARED_TRANSPORTS_MAX", 2)
    clients = [
        build_keepalive_http_client("https://api.example.com/v1", verify=False),
        build_keepalive_http_client("https://api.example.com/v1"),
    ]
    assert len(process_bootstrap._SHARED_TRANSPORTS) == 2
    ctx = ssl.create_default_context()
    extra = build_keepalive_http_client("https://api.example.com/v1", verify=ctx)
    assert len(process_bootstrap._SHARED_TRANSPORTS) == 2
    # Past the cap the caller still gets a working (private) transport.
    assert _inner(extra)._pool._ssl_context is ctx
    for c in clients + [extra]:
        c.close()
    assert process_bootstrap.close_shared_transports() == 2
