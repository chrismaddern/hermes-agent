"""Connect-time outbound guard for botocore's urllib3 transport.

Botocore owns its HTTP stack, so the shared httpx guard cannot protect native Bedrock
Converse/control-plane clients. This adapter replaces only the connection/pool boundary:
request signing, retries, streaming, TLS verification, and proxy configuration stay owned by
botocore. Direct sockets dial a freshly validated IP, HTTPS proxy CONNECT targets are pinned to
that IP while TLS SNI remains the original hostname, and forwarding-proxy request targets are
rewritten at the final write boundary.
"""

from contextvars import ContextVar
from types import MethodType
from typing import Any
from urllib.parse import urlsplit, urlunsplit


_Target = tuple[str, int, str]
_current_target: ContextVar[_Target | None] = ContextVar(
    "hermes_bedrock_outbound_target", default=None
)
_pool_classes: dict[str, Any] | None = None


def _target_from_url(url: str) -> _Target:
    from tools.url_safety import SSRFConnectionBlocked, _resolved_http_connect_ips

    try:
        parsed = urlsplit(str(url))
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        port = parsed.port if parsed.port is not None else {"http": 80, "https": 443}.get(scheme)
    except ValueError as exc:
        raise SSRFConnectionBlocked(f"Blocked malformed Bedrock endpoint URL: {url!r}") from exc
    if not host or port is None:
        raise SSRFConnectionBlocked("Blocked Bedrock request with no network destination")
    _resolved_http_connect_ips(host, port, scheme)
    return host, port, scheme


def _require_current_target() -> _Target:
    from tools.url_safety import SSRFConnectionBlocked

    target = _current_target.get()
    if target is None:
        raise SSRFConnectionBlocked("Blocked Bedrock connection without a validated request target")
    return target


def _same_host(left: str, right: str) -> bool:
    return (left or "").strip().lower().rstrip(".") == (right or "").strip().lower().rstrip(".")


def _render_ip_authority(ip: str, port: int, scheme: str) -> str:
    rendered = f"[{ip}]" if ":" in ip else ip
    default = {"http": 80, "https": 443}.get(scheme)
    return rendered if port == default else f"{rendered}:{port}"


def _guarded_pool_classes() -> dict[str, Any]:
    global _pool_classes
    if _pool_classes is not None:
        return _pool_classes

    from botocore.awsrequest import (
        AWSHTTPConnection,
        AWSHTTPSConnection,
        AWSHTTPConnectionPool,
        AWSHTTPSConnectionPool,
    )
    from tools.url_safety import SSRFConnectionBlocked, _resolved_http_connect_ips

    class _GuardedConnectionMixin:
        def _new_conn(self):
            host, port, scheme = _require_current_target()
            # A tunneling proxy socket connects to the operator-configured proxy first. The target
            # itself is re-resolved and pinned in _tunnel immediately before CONNECT is written.
            if getattr(self, "_tunnel_host", None) is not None:
                return super()._new_conn()
            dns_host = getattr(self, "_dns_host", "")
            if not _same_host(dns_host, host) or int(getattr(self, "port", 0) or 0) != port:
                # Forwarding proxies connect to their own configured host. Their absolute-form
                # target is pinned by request() below.
                if getattr(self, "proxy", None) is not None:
                    return super()._new_conn()
                raise SSRFConnectionBlocked("Blocked Bedrock socket whose destination changed after validation")

            last_error: Exception | None = None
            original_host = dns_host
            for ip in _resolved_http_connect_ips(host, port, scheme):
                try:
                    self._dns_host = ip
                    return super()._new_conn()
                except OSError as exc:
                    last_error = exc
                finally:
                    self._dns_host = original_host
            if last_error is not None:
                raise last_error
            raise SSRFConnectionBlocked("Blocked Bedrock connection with no validated destination IP")

        def request(self, method, url, body=None, headers=None, *args, **kwargs):
            parsed = urlsplit(str(url))
            if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
                host, port, scheme = _require_current_target()
                if not _same_host(parsed.hostname, host):
                    raise SSRFConnectionBlocked("Blocked Bedrock proxy request whose destination changed")
                ip = _resolved_http_connect_ips(host, port, scheme)[0]
                url = urlunsplit(
                    (parsed.scheme, _render_ip_authority(ip, port, scheme), parsed.path, parsed.query, parsed.fragment)
                )
            return super().request(method, url, body=body, headers=headers, *args, **kwargs)

    class _GuardedHTTPConnection(_GuardedConnectionMixin, AWSHTTPConnection):
        pass

    class _GuardedHTTPSConnection(_GuardedConnectionMixin, AWSHTTPSConnection):
        def _tunnel(self):
            from tools.url_safety import SSRFConnectionBlocked, _resolved_http_connect_ips

            host, port, scheme = _require_current_target()
            original_host = getattr(self, "_tunnel_host", None)
            original_port = getattr(self, "_tunnel_port", None)
            if not original_host or not _same_host(original_host, host) or original_port != port:
                raise SSRFConnectionBlocked("Blocked Bedrock proxy tunnel whose destination changed")
            self._tunnel_host = _resolved_http_connect_ips(host, port, scheme)[0]
            try:
                return super()._tunnel()
            finally:
                # urllib3 reads this after _tunnel() to choose target TLS SNI/certificate identity.
                self._tunnel_host = original_host

    class _GuardedHTTPConnectionPool(AWSHTTPConnectionPool):
        ConnectionCls = _GuardedHTTPConnection

    class _GuardedHTTPSConnectionPool(AWSHTTPSConnectionPool):
        ConnectionCls = _GuardedHTTPSConnection

    _pool_classes = {"http": _GuardedHTTPConnectionPool, "https": _GuardedHTTPSConnectionPool}
    return _pool_classes


def install_botocore_outbound_guard(client: Any) -> Any:
    """Install the native Bedrock connection guard on a newly-created botocore client."""
    from tools.url_safety import SSRFConnectionBlocked

    endpoint = getattr(client, "_endpoint", None)
    session = getattr(endpoint, "http_session", None)
    manager = getattr(session, "_manager", None)
    if session is None or manager is None or not callable(getattr(session, "send", None)):
        raise SSRFConnectionBlocked("Botocore transport cannot be made SSRF-safe")
    if getattr(session, "_hermes_ssrf_guarded", False):
        return client

    pool_classes = _guarded_pool_classes()
    managers = [manager, *(getattr(session, "_proxy_managers", {}) or {}).values()]
    for owned_manager in managers:
        clear = getattr(owned_manager, "clear", None)
        if not callable(clear) or not hasattr(owned_manager, "pool_classes_by_scheme"):
            raise SSRFConnectionBlocked("Botocore connection manager cannot be made SSRF-safe")
        clear()
        owned_manager.pool_classes_by_scheme = pool_classes
    session._pool_classes_by_scheme = pool_classes

    original_send = session.send

    def guarded_send(_session, request):
        token = _current_target.set(_target_from_url(request.url))
        try:
            return original_send(request)
        finally:
            _current_target.reset(token)

    session.send = MethodType(guarded_send, session)
    session._hermes_ssrf_guarded = True
    return client
