"""Outbound connection guard coverage for the native Bedrock transports."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from tools.url_safety import SSRFConnectionBlocked, _reset_allow_private_cache


_PROXY_ENV_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
)


def _private_dns(_host, port, *_args, **_kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]


def test_boto3_runtime_client_blocks_private_endpoint_before_socket_dial(monkeypatch):
    pytest.importorskip("boto3")
    from agent import bedrock_adapter

    bedrock_adapter.reset_client_cache()
    for name in _PROXY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "http://private.test:8765")
    monkeypatch.setattr(socket, "getaddrinfo", _private_dns)

    def unexpected_dial(*_args, **_kwargs):
        pytest.fail("private Bedrock endpoint reached the socket dialer")

    with patch("urllib3.util.connection.create_connection", unexpected_dial):
        client = bedrock_adapter._get_bedrock_runtime_client("us-east-1")
        with pytest.raises(SSRFConnectionBlocked, match="private/internal"):
            client.invoke_model(modelId="amazon.titan-text-lite-v1", body=b"{}")


def test_boto3_runtime_client_rejects_reuse_after_policy_change(monkeypatch):
    pytest.importorskip("boto3")
    from agent import bedrock_adapter

    bedrock_adapter.reset_client_cache()
    for name in _PROXY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "http://private.test:8765")
    monkeypatch.setenv("HERMES_ALLOW_PRIVATE_URLS", "true")
    _reset_allow_private_cache()
    client = bedrock_adapter._get_bedrock_runtime_client("us-east-1")

    monkeypatch.setenv("HERMES_ALLOW_PRIVATE_URLS", "false")
    _reset_allow_private_cache()
    try:
        with pytest.raises(SSRFConnectionBlocked, match="policy changed"):
            client.invoke_model(modelId="amazon.titan-text-lite-v1", body=b"{}")
    finally:
        _reset_allow_private_cache()


def test_boto3_runtime_client_dials_only_the_validated_public_ip(monkeypatch):
    pytest.importorskip("boto3")
    from agent import bedrock_adapter

    class StopAtDial(BaseException):
        pass

    bedrock_adapter.reset_client_cache()
    for name in _PROXY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "http://public.test:8765")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
        ],
    )
    attempts = []

    def stop_at_dial(address, *_args, **_kwargs):
        attempts.append(address)
        raise StopAtDial

    with patch("urllib3.util.connection.create_connection", stop_at_dial):
        client = bedrock_adapter._get_bedrock_runtime_client("us-east-1")
        with pytest.raises(StopAtDial):
            client.invoke_model(modelId="amazon.titan-text-lite-v1", body=b"{}")

    assert attempts == [("93.184.216.34", 8765)]


def test_boto3_runtime_client_tries_the_next_validated_ip(monkeypatch):
    pytest.importorskip("boto3")
    from agent import bedrock_adapter

    class StopAtSecondDial(BaseException):
        pass

    bedrock_adapter.reset_client_cache()
    for name in _PROXY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "http://public.test:8765")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port)),
        ],
    )
    attempts = []

    def dial(address, *_args, **_kwargs):
        attempts.append(address)
        if len(attempts) == 1:
            raise OSError("first public address is unavailable")
        raise StopAtSecondDial

    with patch("urllib3.util.connection.create_connection", dial):
        client = bedrock_adapter._get_bedrock_runtime_client("us-east-1")
        with pytest.raises(StopAtSecondDial):
            client.invoke_model(modelId="amazon.titan-text-lite-v1", body=b"{}")

    assert attempts == [("93.184.216.34", 8765), ("1.1.1.1", 8765)]


def test_boto3_runtime_client_revalidates_dns_at_socket_connect(monkeypatch):
    pytest.importorskip("boto3")
    from agent import bedrock_adapter

    bedrock_adapter.reset_client_cache()
    for name in _PROXY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "http://rebind.test:8765")
    answers = iter(("93.184.216.34", "127.0.0.1"))

    def resolve(_host, port, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (next(answers), port))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)

    def unexpected_dial(*_args, **_kwargs):
        pytest.fail("rebound private Bedrock endpoint reached the socket dialer")

    with patch("urllib3.util.connection.create_connection", unexpected_dial):
        client = bedrock_adapter._get_bedrock_runtime_client("us-east-1")
        with pytest.raises(Exception) as exc_info:
            client.invoke_model(modelId="amazon.titan-text-lite-v1", body=b"{}")

    error = exc_info.value
    chain = []
    while error is not None and error not in chain:
        chain.append(error)
        error = error.__cause__ or error.__context__
    assert any(
        isinstance(item, SSRFConnectionBlocked) and "private/internal" in str(item)
        for item in chain
    )


def test_anthropic_bedrock_receives_guarded_sdk_http_client(monkeypatch):
    from agent import anthropic_adapter

    fake_sdk = MagicMock()
    fake_sdk.AnthropicBedrock = MagicMock(return_value=MagicMock())
    monkeypatch.setattr(anthropic_adapter, "_anthropic_sdk", fake_sdk)
    monkeypatch.setattr(
        "agent.bedrock_adapter.scoped_aws_session_kwargs", dict
    )

    anthropic_adapter.build_anthropic_bedrock_client("us-west-2")

    kwargs = fake_sdk.AnthropicBedrock.call_args.kwargs
    assert "http_client" in kwargs
    assert kwargs["http_client"]._event_hooks["request"]
    kwargs["http_client"].close()
