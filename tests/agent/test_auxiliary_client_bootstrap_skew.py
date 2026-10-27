"""A version-skewed auxiliary client must fail closed when its guarded HTTP
client builder is unavailable.

Desktop installs can run a runtime whose agent/process_bootstrap.py predates
the helper while newer callers (cron scheduler → auxiliary_client) expect it.
The import remains lazy so module loading survives, but constructing a model
client may never fall back to an unguarded SDK transport.
"""

import builtins
import importlib
import agent.auxiliary_client as aux
import pytest


def test_missing_bootstrap_helper_fails_closed(monkeypatch):
    """ImportError from process_bootstrap must not produce an unguarded client."""
    real_import = builtins.__import__

    def _fail_bootstrap(name, *args, **kwargs):
        if name == "agent.process_bootstrap":
            raise ImportError(
                "cannot import name 'build_keepalive_http_client' "
                "from 'agent.process_bootstrap'"
            )
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fail_bootstrap)
    with pytest.raises(ImportError, match="build_keepalive_http_client"):
        aux._openai_http_client_kwargs("https://api.example.com/v1")


def test_healthy_bootstrap_still_injects_keepalive_client():
    """With the helper present, the keepalive http_client is injected."""
    result = aux._openai_http_client_kwargs("https://api.example.com/v1")
    assert "http_client" in result
    assert result["http_client"] is not None
    result["http_client"].close()


def test_vertex_auxiliary_client_uses_guarded_http_transport(monkeypatch):
    openai = importlib.import_module("openai")
    captured = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    for name in (
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(openai, "OpenAI", FakeOpenAI)
    monkeypatch.setattr("agent.vertex_adapter.has_vertex_credentials", lambda: True)
    monkeypatch.setattr(
        "agent.vertex_adapter.get_vertex_config",
        lambda: ("test-token", "https://vertex.example/v1"),
    )

    client, model = aux._build_vertex_client("vertex", "gemini-test")

    assert isinstance(client, FakeOpenAI)
    assert model == "gemini-test"
    http_client = captured["http_client"]
    try:
        backend = http_client._transport._pool._network_backend
        assert type(backend).__name__ == "_SSRFGuardedNetworkBackend"
    finally:
        http_client.close()
