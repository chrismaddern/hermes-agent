"""URL safety checks — blocks requests to private/internal network addresses (SSRF).

``security.allow_private_urls: true`` disables private-IP blocking (DNS that resolves public
names to private ranges); cloud metadata hostnames/IPs are **always** blocked. A local TUN proxy
that answers DNS with a fake-ip block (Mihomo/Clash fake-ip, Surge enhanced) declares that block
in ``security.fake_ip_ranges`` so its sentinel answers are dialable instead of looking private;
the list is empty by default, so the sentinel stays blocked for everyone else. DNS rebinding
(TOCTOU) is closed for Hermes-owned httpx paths by ``create_ssrf_safe_[async_]client()``, which
re-apply the policy at TCP connect and dial the validated IP while preserving Host/SNI. Redirect
bypass is mitigated by response hooks re-validating each target (``redirect_target_from_response``).
"""

import importlib
import ipaddress
import logging
import os
import socket
import asyncio
import re
from contextlib import contextmanager
from typing import Any, Optional
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlparse, urlsplit, urlunsplit

from hermes_constants import get_hermes_home_override
from utils import is_truthy_value

logger = logging.getLogger(__name__)

# Proxy env vars: when set, the runtime should delegate DNS to the proxy.
_PROXY_ENV_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
_HTTP_SCHEMES = frozenset({"http", "https"})
_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _proxy_is_configured() -> bool:
    return any(os.environ.get(v) for v in _PROXY_ENV_VARS)


def normalize_url_for_request(url: str) -> str:
    """ASCII-safe HTTP URL for Hermes-owned URL tools (IRI -> URI, e.g. ``https://wttr.in/Köln``).
    Preserves URL syntax and existing percent escapes while IDNA-encoding the host and
    percent-encoding non-ASCII path/query/fragment text. URL tool inputs only — never shell commands."""
    if not isinstance(url, str):
        return url
    raw = url.strip()
    if not raw:
        return raw

    # Repair model-emitted whitespace between scheme separator and authority
    # (``https:// docs.example``); that position is never meaningful in HTTP URLs.
    raw = re.sub(r"^([A-Za-z][A-Za-z0-9+.-]*://)\s+", r"\1", raw)
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return raw
    if parsed.scheme.lower() not in _HTTP_SCHEMES:
        return raw
    netloc, hostname = parsed.netloc, parsed.hostname
    if hostname:
        try:
            ascii_host = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            ascii_host = hostname
        if ascii_host != hostname:
            netloc = netloc.replace(hostname, ascii_host, 1)
    safe = "/%:@!$&'()*+,;="
    return urlunsplit((parsed.scheme, netloc, quote(parsed.path, safe=safe),
                       quote(parsed.query, safe=safe + "?"), quote(parsed.fragment, safe=safe + "?")))


# Unambiguously credential-bearing query param names. Deliberately narrow: bare
# English words that double as page facets (``code``, ``key``, ``auth``,
# ``session``, ``sig``) are EXCLUDED so ordinary browsing is not blocked.
_SENSITIVE_QUERY_PARAM_NAMES = frozenset({
    "access_token", "api_key", "apikey", "auth_token", "authorization", "awsaccesskeyid",
    "client_secret", "credential", "credentials", "jwt", "password", "passwd", "secret",
    "session_id", "signature", "token", "x_amz_security_token", "x_amz_signature",
    "x-amz-security-token", "x-amz-signature"})


def sensitive_query_param_name(url: str) -> Optional[str]:
    """First credential-named query parameter in ``url`` (with a value), if any. Checked before
    handing URLs to third-party fetch/browser backends: catches opaque magic links, OAuth codes,
    signed-URL signatures and custom ``?token=...`` values that prefix-based redaction misses."""
    if not isinstance(url, str) or "?" not in url:
        return None
    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        return None
    if parsed.scheme.lower() not in _HTTP_SCHEMES or not parsed.query:
        return None
    return next((key for key, value in parse_qsl(parsed.query, keep_blank_values=True)
                 if value and unquote(key).lower() in _SENSITIVE_QUERY_PARAM_NAMES), None)


# Cloud metadata hostnames — always blocked regardless of DNS or config toggle.
_BLOCKED_HOSTNAMES = frozenset({"metadata.google.internal", "metadata.goog"})

# Cloud metadata / credential endpoints (the #1 SSRF target) — always blocked, also in
# IPv4-mapped IPv6 form (resolvers may return ``::ffff:x.x.x.x``; ipaddress treats those as distinct).
_METADATA_V4 = (
    "169.254.169.254",  # AWS/GCP/Azure/DO/Oracle metadata
    "169.254.170.2",    # AWS ECS task metadata (task IAM creds)
    "169.254.170.23",   # AWS EKS Pod Identity credentials
    "169.254.169.253",  # Azure IMDS wire server
    "168.63.129.16",    # Azure WireServer / host-agent endpoint
    "100.100.100.200",  # Alibaba Cloud metadata
    "192.0.0.192",      # Oracle Cloud legacy metadata
)
_ALWAYS_BLOCKED_IPS = frozenset(
    {ipaddress.ip_address(ip) for ip in _METADATA_V4}
    | {ipaddress.ip_address("::ffff:" + ip) for ip in _METADATA_V4}
    | {
        ipaddress.ip_address("fd00:ec2::254"),  # AWS metadata (IPv6)
        ipaddress.ip_address("fd00:ec2::23"),   # AWS EKS Pod Identity (IPv6)
        ipaddress.ip_address("fd20:ce::254"),   # Google Cloud metadata (IPv6)
    }
)
# Entire link-local range (no legit agent target), plus its IPv4-mapped form.
_ALWAYS_BLOCKED_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("169.254.0.0/16", "::ffff:169.254.0.0/112"))

# Narrow compatibility exceptions for exact HTTPS host + address-range pairs.
# QQ media legitimately resolves to benchmark-space addresses behind local proxy infra; the
# hostname alone is not trusted, so poisoned loopback/RFC1918 answers remain blocked.
_TRUSTED_PRIVATE_IP_NETWORKS = {
    "multimedia.nt.qq.com.cn": (ipaddress.ip_network("198.18.0.0/15"),),
}
_MAX_SSRF_CONNECT_IPS = 8

# 100.64.0.0/10 (CGNAT, RFC 6598) is neither is_private nor is_global in
# ipaddress — must be blocked explicitly (Tailscale/WireGuard, cloud internal nets).
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

# RFC 2765 IPv4-translated wrapper ``::ffff:0:a.b.c.d`` — the second form resolvers may use to
# answer an IPv4 name (on the reporting macOS host, fake-IP TUN DNS returns it alongside the
# plain address). ``ip.ipv4_mapped`` does not read it; ``_embedded_ipv4`` handles it explicitly.
_IPV4_TRANSLATED_NETWORK = ipaddress.ip_network("::ffff:0:0:0/96")
_IPV4_COMPATIBLE_NETWORK = ipaddress.ip_network("::/96")
_NAT64_WELL_KNOWN_NETWORK = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_USE_NETWORK = ipaddress.ip_network("64:ff9b:1::/48")

# Address classes a ``security.fake_ip_ranges`` declaration can never excuse: a local proxy owns
# none of them, and a declaration is trusted like ``allow_private_urls`` for whatever it names,
# so an entry overlapping one of these (including 0.0.0.0/0 and ::/0) would make real internal
# hosts dialable. Such entries are dropped with a warning instead.
_FAKE_IP_UNDECLARABLE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/32", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # unspecified/loopback/RFC 1918
    "169.254.0.0/16", "100.64.0.0/10",  # link-local, CGNAT
    "::/128", "::1/128", "fc00::/7", "fe80::/10",  # unspecified, loopback, ULA, link-local
))

# Global toggle cache (process lifetime; see _global_allow_private_urls).
_allow_private_resolved, _cached_allow_private = False, False
_fake_ip_resolved, _cached_fake_ip_ranges = False, ()


def _global_allow_private_urls() -> bool:
    """True when the user has opted out of private-IP blocking. Priority: ``HERMES_ALLOW_PRIVATE_URLS``
    env, ``security.allow_private_urls``, legacy ``browser.allow_private_urls``. Profile-scoped turns
    (``get_hermes_home_override()`` set) bypass the process-global cache — a multiplex gateway serves
    several profiles in one process; the first profile's opt-out must not disable blocking for later ones."""
    global _allow_private_resolved, _cached_allow_private
    if get_hermes_home_override() is not None:
        return _resolve_allow_private_urls()
    if not _allow_private_resolved:
        _allow_private_resolved, _cached_allow_private = True, _resolve_allow_private_urls()
    return _cached_allow_private


def _resolve_allow_private_urls() -> bool:
    """Resolve the effective private-URL toggle from the active config scope."""
    env_val = os.getenv("HERMES_ALLOW_PRIVATE_URLS", "").strip().lower()
    if env_val in {"true", "1", "yes"}:
        return True
    if env_val in {"false", "0", "no"}:
        return False  # explicit false does not fall through to config
    try:
        from hermes_cli.config import read_raw_config
        cfg = read_raw_config()
        for section in ("security", "browser"):  # preferred, then legacy
            block = cfg.get(section, {})
            if isinstance(block, dict) and is_truthy_value(block.get("allow_private_urls"), default=False):
                return True
    except Exception:
        pass  # config unavailable (tests, early import) — keep default
    return False


def _reset_allow_private_cache() -> None:
    """Reset the cached toggle and the cached fake-ip ranges — only for tests."""
    global _allow_private_resolved, _cached_allow_private, _fake_ip_resolved, _cached_fake_ip_ranges
    _allow_private_resolved = _cached_allow_private = _fake_ip_resolved = False
    _cached_fake_ip_ranges = ()


def _resolve_fake_ip_ranges() -> tuple:
    """CIDR blocks this host's local proxy answers DNS with (``security.fake_ip_ranges``).

    A TUN proxy in fake-ip mode answers every non-filtered name with an address from its own
    block; that answer is the proxy's sentinel, not an internal host's, so treating it as a
    private target blocks every outbound fetch on such a host (web_extract, platform attachment
    downloads, the browser relay). Empty by default: no host gets the exemption unless it
    declares one, and the sentinel range keeps the ordinary private-address verdict otherwise.
    """
    try:
        from hermes_cli.config import read_raw_config
        block = read_raw_config().get("security", {})
        raw = block.get("fake_ip_ranges") if isinstance(block, dict) else None
    except Exception:
        return ()  # config unavailable (tests, early import) — keep the secure default
    entries = [raw] if isinstance(raw, str) else raw if isinstance(raw, (list, tuple)) else ()
    networks = []
    for entry in entries:
        try:
            net = ipaddress.ip_network(str(entry).strip(), strict=False)
        except ValueError:
            logger.warning("Ignoring unparseable security.fake_ip_ranges entry: %r", entry)
            continue
        clash = next((r for r in _FAKE_IP_UNDECLARABLE_NETWORKS if r.version == net.version and net.overlaps(r)), None)
        if clash is not None:
            logger.warning("Ignoring security.fake_ip_ranges entry %r: it overlaps %s, which stays blocked", entry, clash)
            continue
        networks.append(net)
    return tuple(networks)


def _global_fake_ip_ranges() -> tuple:
    """Process-lifetime cache with the same profile-scope bypass as ``_global_allow_private_urls``:
    a multiplex gateway must not apply the first profile's declaration to later ones."""
    global _fake_ip_resolved, _cached_fake_ip_ranges
    if get_hermes_home_override() is not None:
        return _resolve_fake_ip_ranges()
    if not _fake_ip_resolved:
        _fake_ip_resolved, _cached_fake_ip_ranges = True, _resolve_fake_ip_ranges()
    return _cached_fake_ip_ranges


def ssrf_policy_fingerprint() -> tuple[bool, tuple[str, ...]]:
    """Hashable identity for connection pools governed by the active outbound policy.

    A pool opened while private destinations are allowed must never be reused after the active
    profile/policy becomes guarded: an already-open socket does not cross the connect boundary again.
    """
    return _global_allow_private_urls(), tuple(str(net) for net in _global_fake_ip_ranges())


def _normalize_hostname(host: Optional[str]) -> str:
    return (host or "").strip().lower().rstrip(".")


def _parse_ip(hostname: str) -> Optional[_IPAddress]:
    """IP object for a literal-IP hostname, else None."""
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def _iter_resolved_ips(addr_info: Any):
    """Yield ``(raw, ip_str, ip)`` per getaddrinfo answer. ``ip_str`` has any IPv6 scope ID
    (``%eth0``) stripped; ``ip`` is None when still unparseable — each caller decides skip/fail/raise."""
    for _family, _, _, _, sockaddr in addr_info:
        raw = sockaddr[0]
        ip_str = raw.split("%")[0]
        yield raw, ip_str, _parse_ip(ip_str)


def _getaddrinfo(hostname: str, port: Optional[int] = None):
    return socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)


def _embedded_ipv4s(ip: _IPAddress) -> tuple[ipaddress.IPv4Address, ...]:
    """IPv4 destinations carried by an IPv6 transition address.

    A global-looking IPv6 literal can still route to IPv4 loopback/private space through NAT64,
    6to4, Teredo, or the older compatible/translated forms. Classify the carried destinations too;
    otherwise ``64:ff9b::7f00:1`` is a loopback bypass despite the outer address being global.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return ()
    if ip.ipv4_mapped is not None:
        return (ip.ipv4_mapped,)
    transition_networks = (
        _IPV4_TRANSLATED_NETWORK,
        _NAT64_WELL_KNOWN_NETWORK,
        _NAT64_LOCAL_USE_NETWORK,
    )
    if any(ip in network for network in transition_networks):
        return (ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF),)
    if ip in _IPV4_COMPATIBLE_NETWORK and int(ip) > 0xFFFF:
        return (ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF),)
    if ip.sixtofour is not None:
        return (ip.sixtofour,)
    if ip.teredo is not None:
        return tuple(ip.teredo)
    return ()


def _embedded_ipv4(ip: _IPAddress) -> _IPAddress:
    """First carried IPv4 destination, or *ip* when this is not a transition address."""
    embedded = _embedded_ipv4s(ip)
    return embedded[0] if embedded else ip


def _is_always_blocked_ip(ip: _IPAddress) -> bool:
    candidates = (ip, *_embedded_ipv4s(ip))
    return any(
        candidate in _ALWAYS_BLOCKED_IPS
        or any(candidate in net for net in _ALWAYS_BLOCKED_NETWORKS)
        for candidate in candidates
    )


def _is_declared_fake_ip(ip: _IPAddress) -> bool:
    """True when *ip* falls in a block declared in ``security.fake_ip_ranges``. The dial still goes
    to the local proxy, which resolves and connects to the real target, so a declared block grants
    no reach an attacker lacks through the proxy's own DNS; undeclared ranges keep the private verdict."""
    ranges = _global_fake_ip_ranges()
    candidates = (ip, *_embedded_ipv4s(ip))
    declared = tuple(
        any(candidate.version == net.version and candidate in net for net in ranges)
        for candidate in candidates
    )
    if not any(declared):
        return False

    def blocked(candidate: _IPAddress) -> bool:
        return not candidate.is_global or candidate.is_multicast or candidate in _CGNAT_NETWORK

    # A declaration may name a benchmark-space fake answer (including its translated wrapper),
    # but it may never use a declared transition range to excuse an undeclared embedded private IP.
    return all(not blocked(candidate) or is_declared for candidate, is_declared in zip(candidates, declared))


def _is_blocked_ip(ip: _IPAddress) -> bool:
    """Return True if the IP should be blocked for SSRF protection."""
    def blocked(candidate: _IPAddress) -> bool:
        return not candidate.is_global or candidate.is_multicast or candidate in _CGNAT_NETWORK

    return blocked(ip) or any(blocked(candidate) for candidate in _embedded_ipv4s(ip))


def is_always_blocked_url(url: str) -> bool:
    """True when the URL targets the always-blocked floor (cloud metadata) — only the sentinel
    hostnames/IPs, regardless of backend, routing, or ``allow_private_urls``. For callers that
    deliberately bypass the full check (e.g. hybrid cloud browser routing private URLs to a local
    sidecar) but must still enforce the floor. False for ordinary private/loopback URLs, DNS
    failures and parse errors (the caller's ordinary fail-closed path handles those)."""
    try:
        hostname = _normalize_hostname(urlparse(url).hostname)
        if not hostname:
            return False
        if hostname in _BLOCKED_HOSTNAMES:
            logger.warning("Blocked request to internal hostname (always-blocked floor): %s", hostname)
            return True
        ip = _parse_ip(hostname)
        if ip is not None:
            if _is_always_blocked_ip(ip):
                logger.warning("Blocked request to cloud metadata address (always-blocked floor): %s", hostname)
                return True
            return False
        try:
            addr_info = _getaddrinfo(hostname)
        except socket.gaierror:
            return False  # DNS failure is not part of the floor; caller's path handles it
        for raw, ip_str, resolved in _iter_resolved_ips(addr_info):
            if resolved is None:
                logger.warning("Unparseable IP address %r for hostname %s — skipping address", raw, hostname)
                continue
            if _is_always_blocked_ip(resolved):
                logger.warning(
                    "Blocked request to cloud metadata address (always-blocked floor): %s -> %s", hostname, ip_str
                )
                return True
        return False
    except Exception as exc:
        # Parse/unexpected errors are not "always blocked"; caller decides fail-open/closed.
        logger.debug("is_always_blocked_url error for %s: %s", url, exc)
        return False


def _allows_private_ip_resolution(hostname: str, scheme: str, ip: _IPAddress) -> bool:
    """Return True only for a trusted HTTPS hostname's documented private address range."""
    if scheme != "https":
        return False
    networks = _TRUSTED_PRIVATE_IP_NETWORKS.get(hostname, ())
    return any(
        candidate.version == network.version and candidate in network
        for candidate in (ip, *_embedded_ipv4s(ip))
        for network in networks
    )


def _resolved_ip_block_reason(ip: _IPAddress, allow_private: bool) -> Optional[str]:
    """Why a resolved answer must be rejected, or None if it may be dialed. The metadata floor
    ignores ``allow_private``; ordinary private/internal classes are blocked only when it is False."""
    if _is_always_blocked_ip(ip):
        return "cloud metadata address"
    if not allow_private and _is_blocked_ip(ip) and not _is_declared_fake_ip(ip):
        return "private/internal address"
    return None


def is_safe_url(url: str, *, proxy_configured: Optional[bool] = None) -> bool:
    """True if the URL target is not a private/internal address. Resolves the hostname and checks
    every answer; fails closed on DNS errors and unexpected exceptions. ``allow_private_urls``
    skips private-IP blocking, but cloud metadata endpoints remain blocked regardless."""
    try:
        parsed = urlparse(url)
        hostname = _normalize_hostname(parsed.hostname)
        scheme = (parsed.scheme or "").strip().lower()
        if scheme not in _HTTP_SCHEMES:
            logger.warning("Blocked request — unsupported URL scheme: %s", scheme or "<empty>")
            return False
        if not hostname:
            return False
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            logger.warning("Blocked request — invalid destination port: %s", port)
            return False

        # Metadata hostnames are blocked BEFORE consulting the toggle.
        if hostname in _BLOCKED_HOSTNAMES:
            logger.warning("Blocked request to internal hostname: %s", hostname)
            return False
        allow_all_private = _global_allow_private_urls()
        allowed_trusted_private = False
        try:
            addr_info = _getaddrinfo(hostname)
        except socket.gaierror:
            # Sandbox/proxy environments may block direct DNS; when a proxy is
            # configured, delegate resolution to it (metadata hostnames were already
            # rejected above). Literal IPs need no DNS, so a failure on one is not a
            # proxy symptom — keep them fail-closed.
            proxy_active = _proxy_is_configured() if proxy_configured is None else proxy_configured
            if _parse_ip(hostname) is None and proxy_active:
                logger.debug(
                    "DNS resolution failed for %s — proxy configured, allowing through for proxy-side resolution",
                    hostname)
                return True
            logger.warning("Blocked request — DNS resolution failed for: %s", hostname)
            return False
        for raw, ip_str, ip in _iter_resolved_ips(addr_info):
            if ip is None:
                logger.warning("Blocked request — unparseable IP address %r for hostname %s", raw, hostname)
                return False
            allow_trusted_private = _allows_private_ip_resolution(hostname, scheme, ip)
            reason = _resolved_ip_block_reason(ip, allow_all_private or allow_trusted_private)
            if reason is not None:
                logger.warning("Blocked request to %s: %s -> %s", reason, hostname, ip_str)
                return False
            allowed_trusted_private = allowed_trusted_private or allow_trusted_private
        if allow_all_private:
            logger.debug("Allowing private/internal resolution (security.allow_private_urls=true): %s", hostname)
        elif allowed_trusted_private:
            logger.debug("Allowing trusted hostname despite private/internal resolution: %s", hostname)
        return True
    except Exception as exc:
        # Fail closed: parsing edge cases must not become SSRF bypass vectors.
        logger.warning("Blocked request — URL safety check error for %s: %s", url, exc)
        return False


async def async_is_safe_url(url: str) -> bool:
    """:func:`is_safe_url` with the blocking DNS work off the event loop."""
    return await asyncio.to_thread(is_safe_url, url)


class SSRFConnectionBlocked(ValueError):
    """Raised when connect-time DNS resolution violates the URL safety policy."""


def _resolved_http_connect_ips(host: str, port: int, scheme: str) -> list[str]:
    """Resolve and validate *host* at TCP-connect time; return dialable IP strings. Closes the
    DNS-rebinding gap between pre-flight validation and connect for direct httpx clients. The
    result is capped at ``_MAX_SSRF_CONNECT_IPS``, but EVERY answer is validated."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise SSRFConnectionBlocked(f"Blocked request with invalid destination port: {port!r}")
    if scheme not in _HTTP_SCHEMES:
        raise SSRFConnectionBlocked(f"Blocked request with unsupported URL scheme: {scheme!r}")
    hostname = _normalize_hostname(host)
    if not hostname:
        raise SSRFConnectionBlocked("Blocked request with empty hostname")
    if hostname in _BLOCKED_HOSTNAMES:
        raise SSRFConnectionBlocked(f"Blocked request to internal hostname: {hostname}")
    allow_all_private = _global_allow_private_urls()
    try:
        addr_info = _getaddrinfo(hostname, port)
    except socket.gaierror as exc:
        raise SSRFConnectionBlocked(f"Blocked request - DNS resolution failed for: {hostname}") from exc
    safe_ips: list[str] = []
    for raw, ip_str, ip in _iter_resolved_ips(addr_info):
        if ip is None:
            raise SSRFConnectionBlocked(
                f"Blocked request - unparseable IP address {raw!r} for hostname {hostname}"
            ) from ValueError(f"{ip_str!r} does not appear to be an IPv4 or IPv6 address")
        reason = _resolved_ip_block_reason(
            ip, allow_all_private or _allows_private_ip_resolution(hostname, scheme, ip)
        )
        if reason is not None:
            raise SSRFConnectionBlocked(f"Blocked request to {reason} during connect: {hostname} -> {ip_str}")
        if ip_str not in safe_ips and len(safe_ips) < _MAX_SSRF_CONNECT_IPS:
            safe_ips.append(ip_str)
    if not safe_ips:
        raise SSRFConnectionBlocked(f"Blocked request - DNS returned no results for: {hostname}")
    return safe_ips


class _SSRFGuardedBackendBase:
    """httpcore backend that re-resolves + validates at connect time and dials a vetted IP.
    Host/SNI stay on the original hostname; Unix sockets are refused outright. Candidate IPs are
    tried in order and the last connect error is re-raised so callers see the real failure."""

    def __init__(self, backend: Any, schemes_by_origin_var: Any):
        self._backend = backend
        self._schemes_by_origin_var = schemes_by_origin_var

    def _connect_ips(self, host: str, port: int) -> list[str]:
        scheme = self._schemes_by_origin_var.get({}).get((host, port)) or ("https" if port == 443 else "http")
        return _resolved_http_connect_ips(host, port, scheme)

    @staticmethod
    def _connect_errors() -> tuple[type[Exception], ...]:
        errors: list[type[Exception]] = [OSError]
        for module_name in ("httpcore", "httpcore2"):
            try:
                module = importlib.import_module(module_name)
            except ImportError:
                continue
            errors.extend((module.ConnectError, module.ConnectTimeout))
        return tuple(errors)

    @staticmethod
    def _no_usable_ips(host: str, last_exc: Exception | None) -> Exception:
        if last_exc is not None:
            return last_exc
        return SSRFConnectionBlocked(f"Blocked request - DNS returned no usable IPs for: {host}")

    def connect_unix_socket(self, path: str, timeout: float | None = None, socket_options: Any = None) -> Any:
        raise SSRFConnectionBlocked("Blocked Unix socket connection in SSRF-safe transport")


def _proxy_origin_pin(schemes_by_origin_var: Any) -> tuple[str, int, str, str]:
    origins = schemes_by_origin_var.get({})
    if len(origins) != 1:
        raise SSRFConnectionBlocked("Blocked proxy connection without one validated target origin")
    ((host, port), scheme), = origins.items()
    return host, port, scheme, _resolved_http_connect_ips(host, port, scheme)[0]


def _wire_hostname(host: str) -> str:
    # Keep a DNS root-label suffix: httpx preserves it in CONNECT and absolute-form
    # proxy requests, and stripping it here would make the pinned-authority rewrite miss.
    normalized = (host or "").strip().lower()
    try:
        return ipaddress.ip_address(normalized).compressed
    except ValueError:
        return normalized.encode("idna").decode("ascii")


def _authority(host: str, port: int) -> bytes:
    host = _wire_hostname(host)
    rendered = f"[{host}]" if ":" in host else host
    return f"{rendered}:{port}".encode("ascii")


def _rewrite_proxy_request(buffer: bytes, host: str, port: int, scheme: str, ip: str) -> bytes:
    """Pin an HTTP CONNECT/absolute-form or SOCKS5 destination to a validated IP.

    HTTP Host and TLS SNI remain the original hostname; only the proxy routing authority changes,
    so the proxy never performs a second, attacker-controlled DNS lookup.
    """
    old_authority, new_authority = _authority(host, port), _authority(ip, port)
    if buffer.startswith(b"CONNECT " + old_authority + b" "):
        buffer = buffer.replace(b"CONNECT " + old_authority + b" ", b"CONNECT " + new_authority + b" ", 1)
        return re.sub(
            rb"(?im)^(Host:[ \t]*)" + re.escape(old_authority) + rb"([ \t]*)(\r?)$",
            lambda match: match.group(1) + new_authority + match.group(2) + match.group(3),
            buffer,
            count=1,
        )
    if buffer.startswith(b"CONNECT "):
        raise SSRFConnectionBlocked("Blocked proxy CONNECT with an unpinned destination authority")

    line_end = buffer.find(b"\r\n")
    if line_end > 0:
        first_line = buffer[:line_end]
        parts = first_line.split(b" ", 2)
        if len(parts) == 3:
            prefix = scheme.encode("ascii") + b"://"
            wire_host = _wire_hostname(host)
            host_only = (f"[{wire_host}]" if ":" in wire_host else wire_host).encode("ascii")
            ip_only = (f"[{ip}]" if ":" in ip else ip).encode("ascii")
            for old, new in ((old_authority, new_authority), (host_only, ip_only)):
                if parts[1].startswith(prefix + old + b"/") or parts[1] == prefix + old:
                    parts[1] = prefix + new + parts[1][len(prefix + old):]
                    return b" ".join(parts) + buffer[line_end:]
            if parts[1].startswith((b"http://", b"https://")):
                raise SSRFConnectionBlocked(
                    "Blocked absolute-form proxy request with an unpinned destination authority"
                )

    # SOCKS5 CONNECT with a domain-name target (RFC 1928, ATYP=3).
    if len(buffer) >= 7 and buffer[:4] == b"\x05\x01\x00\x03":
        size = buffer[4]
        end = 5 + size
        if len(buffer) >= end + 2 and _normalize_hostname(
                buffer[5:end].decode("ascii", "ignore")) == _normalize_hostname(_wire_hostname(host)):
            packed = ipaddress.ip_address(ip).packed
            atyp = b"\x01" if len(packed) == 4 else b"\x04"
            return buffer[:3] + atyp + packed + buffer[end:]
        if len(buffer) >= end + 2:
            raise SSRFConnectionBlocked("Blocked SOCKS request with an unpinned destination authority")
    return buffer


class _PinnedProxyStream:
    def __init__(self, stream: Any, host: str, port: int, scheme: str, ip: str):
        self._stream, self._pin = stream, (host, port, scheme, ip)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._stream.read(max_bytes, timeout=timeout)

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._stream.write(_rewrite_proxy_request(buffer, *self._pin), timeout=timeout)

    def close(self) -> None:
        self._stream.close()

    def start_tls(self, ssl_context: Any, server_hostname: str | None = None,
                  timeout: float | None = None) -> Any:
        stream = self._stream.start_tls(
            ssl_context=ssl_context, server_hostname=server_hostname, timeout=timeout)
        return type(self)(stream, *self._pin)

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class _PinnedAsyncProxyStream:
    def __init__(self, stream: Any, host: str, port: int, scheme: str, ip: str):
        self._stream, self._pin = stream, (host, port, scheme, ip)

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._stream.read(max_bytes, timeout=timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._stream.write(_rewrite_proxy_request(buffer, *self._pin), timeout=timeout)

    async def aclose(self) -> None:
        await self._stream.aclose()

    async def start_tls(self, ssl_context: Any, server_hostname: str | None = None,
                        timeout: float | None = None) -> Any:
        stream = await self._stream.start_tls(
            ssl_context=ssl_context, server_hostname=server_hostname, timeout=timeout)
        return type(self)(stream, *self._pin)

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class _SSRFGuardedProxyNetworkBackend(_SSRFGuardedBackendBase):
    def __init__(self, schemes_by_origin_var: Any, backend: Any):
        super().__init__(backend, schemes_by_origin_var)

    def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                    local_address: str | None = None, socket_options: Any = None) -> Any:
        pin = _proxy_origin_pin(self._schemes_by_origin_var)
        stream = self._backend.connect_tcp(
            host, port, timeout=timeout, local_address=local_address, socket_options=socket_options)
        return _PinnedProxyStream(stream, *pin)

    def sleep(self, seconds: float) -> None:
        self._backend.sleep(seconds)


class _SSRFGuardedAsyncProxyNetworkBackend(_SSRFGuardedBackendBase):
    def __init__(self, schemes_by_origin_var: Any, backend: Any):
        super().__init__(backend, schemes_by_origin_var)

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                          local_address: str | None = None, socket_options: Any = None) -> Any:
        pin = await asyncio.to_thread(_proxy_origin_pin, self._schemes_by_origin_var)
        stream = await self._backend.connect_tcp(
            host, port, timeout=timeout, local_address=local_address, socket_options=socket_options)
        return _PinnedAsyncProxyStream(stream, *pin)

    async def connect_unix_socket(self, path: str, timeout: float | None = None,
                                  socket_options: Any = None) -> Any:
        raise SSRFConnectionBlocked("Blocked Unix socket proxy connection in SSRF-safe transport")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class _SSRFGuardedAsyncNetworkBackend(_SSRFGuardedBackendBase):
    def __init__(self, schemes_by_origin_var: Any, backend: Any = None):
        if backend is None:
            from httpcore._backends.auto import AutoBackend
            backend = AutoBackend()
        super().__init__(backend, schemes_by_origin_var)

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                          local_address: str | None = None, socket_options: Any = None) -> Any:
        last_exc: Exception | None = None
        for ip in await asyncio.to_thread(self._connect_ips, host, port):
            try:
                return await self._backend.connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options)
            except self._connect_errors() as exc:
                last_exc = exc
        raise self._no_usable_ips(host, last_exc)

    async def connect_unix_socket(self, path: str, timeout: float | None = None, socket_options: Any = None) -> Any:
        raise SSRFConnectionBlocked("Blocked Unix socket connection in SSRF-safe transport")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class _SSRFGuardedNetworkBackend(_SSRFGuardedBackendBase):
    def __init__(self, schemes_by_origin_var: Any, backend: Any = None):
        if backend is None:
            from httpcore._backends.sync import SyncBackend
            backend = SyncBackend()
        super().__init__(backend, schemes_by_origin_var)

    def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                    local_address: str | None = None, socket_options: Any = None) -> Any:
        last_exc: Exception | None = None
        for ip in self._connect_ips(host, port):
            try:
                return self._backend.connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options)
            except self._connect_errors() as exc:
                last_exc = exc
        raise self._no_usable_ips(host, last_exc)

    def sleep(self, seconds: float) -> None:
        self._backend.sleep(seconds)


def _origin_scheme_context(request: Any) -> dict[tuple[str, int], str]:
    host, port, scheme = request.url.host, request.url.port, request.url.scheme
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    return {(host, port): scheme} if host and port is not None and scheme in _HTTP_SCHEMES else {}


@contextmanager
def _origin_scope(schemes_by_origin_var: Any, request: Any):
    """Expose the request's origin scheme to the connect-time backend for this request only."""
    token = schemes_by_origin_var.set(_origin_scheme_context(request))
    try:
        yield
    finally:
        schemes_by_origin_var.reset(token)


def _install_ssrf_guard_on_transport(transport: Any, schemes_by_origin_var: Any, *, is_async: bool = False) -> None:
    """Swap a direct or proxy transport's network backend for the guarded one (idempotent)."""
    state = getattr(transport, "__dict__", {}) if transport is not None else {}
    if transport is None or state.get("_hermes_ssrf_guarded", False):
        return
    label = "async httpx transport" if is_async else "httpx transport"
    pool = state.get("_pool")
    if pool is None or not hasattr(pool, "_network_backend"):
        inner = state.get("_inner")
        if inner is not None:
            _install_ssrf_guard_on_transport(inner, schemes_by_origin_var, is_async=is_async)
            state["_hermes_ssrf_guarded"] = True
            return
        raise SSRFConnectionBlocked(f"Unsupported {label} cannot be made SSRF-safe")
    is_proxy = type(pool).__name__ in {"HTTPProxy", "AsyncHTTPProxy", "SOCKSProxy", "AsyncSOCKSProxy"}
    if is_proxy:
        backend_cls = _SSRFGuardedAsyncProxyNetworkBackend if is_async else _SSRFGuardedProxyNetworkBackend
    else:
        backend_cls = _SSRFGuardedAsyncNetworkBackend if is_async else _SSRFGuardedNetworkBackend
    pool._network_backend = backend_cls(schemes_by_origin_var, backend=pool._network_backend)
    method_name = "handle_async_request" if is_async else "handle_request"
    handle = getattr(transport, method_name, None)
    if handle is None:
        raise SSRFConnectionBlocked(f"Unsupported {label} cannot be made SSRF-safe")

    async def guarded_async(request: Any) -> Any:
        with _origin_scope(schemes_by_origin_var, request):
            return await handle(request)

    def guarded_sync(request: Any) -> Any:
        with _origin_scope(schemes_by_origin_var, request):
            return handle(request)
    setattr(transport, method_name, guarded_async if is_async else guarded_sync)
    transport._hermes_ssrf_guarded = True


def _install_ssrf_guard_on_client(client: Any, *, is_async: bool = False) -> None:
    """Guard every direct and proxy transport owned by an httpx-compatible client."""
    import contextvars
    var_name = "hermes_ssrf_async_origin_schemes" if is_async else "hermes_ssrf_origin_schemes"
    origin_var = contextvars.ContextVar(var_name)
    transports = [getattr(client, "__dict__", {}).get("_transport")]
    transports.extend((getattr(client, "__dict__", {}).get("_mounts") or {}).values())
    for transport in transports:
        if transport is not None:
            _install_ssrf_guard_on_transport(transport, origin_var, is_async=is_async)


def install_ssrf_guard_on_client(client: Any, *, is_async: bool = False) -> Any:
    """Install the outbound guard on every transport and return *client*."""
    _install_ssrf_guard_on_client(client, is_async=is_async)
    return client


def install_ssrf_guard_on_transport(transport: Any, *, is_async: bool = False) -> Any:
    """Install the connect-time guard on an httpx/httpx2 transport and return it.

    The wrapper delegates to the transport's existing backend instead of importing one httpcore
    flavour, so MCP's separately packaged ``httpx2``/``httpcore2`` stack keeps its native stream
    types and cancellation semantics.
    """
    import contextvars
    _install_ssrf_guard_on_transport(
        transport, contextvars.ContextVar(f"hermes_ssrf_origin_{id(transport)}"), is_async=is_async)
    return transport


def _guard_request_target(request: Any) -> None:
    """Validate every request target, including redirects and proxied requests.

    Proxied targets deliberately use local DNS too: the validated IP is written into CONNECT,
    absolute-form HTTP, or SOCKS routing so an upstream proxy cannot resolve the hostname again.
    """
    url = request.url
    host, scheme = url.host, url.scheme
    port = url.port if url.port is not None else {"http": 80, "https": 443}.get(scheme)
    if not host or port is None:
        raise SSRFConnectionBlocked("Blocked request with no network destination")
    _resolved_http_connect_ips(host, port, scheme)


def ssrf_safe_event_hooks(
    event_hooks: Any = None, *, is_async: bool = False, policy_fingerprint: Any = None,
) -> dict[str, list]:
    """Merge a fail-closed target check ahead of existing httpx/httpx2 request hooks."""
    hooks = {name: list(callbacks) for name, callbacks in dict(event_hooks or {}).items()}

    async def async_guard(request: Any) -> None:
        if policy_fingerprint is not None and ssrf_policy_fingerprint() != policy_fingerprint:
            raise SSRFConnectionBlocked("Blocked request after outbound network policy changed")
        await asyncio.to_thread(_guard_request_target, request)

    def sync_guard(request: Any) -> None:
        if policy_fingerprint is not None and ssrf_policy_fingerprint() != policy_fingerprint:
            raise SSRFConnectionBlocked("Blocked request after outbound network policy changed")
        _guard_request_target(request)

    guard = async_guard if is_async else sync_guard
    hooks["request"] = [guard, *hooks.get("request", [])]
    return hooks


def create_ssrf_safe_async_client_for(httpx_module: Any, **kwargs: Any) -> Any:
    """Create a guarded async client from ``httpx`` or the MCP SDK's ``httpx2`` module."""
    kwargs["event_hooks"] = ssrf_safe_event_hooks(
        kwargs.get("event_hooks"), is_async=True, policy_fingerprint=ssrf_policy_fingerprint())
    client = httpx_module.AsyncClient(**kwargs)
    _install_ssrf_guard_on_client(client, is_async=True)
    return client


def create_ssrf_safe_client_for(httpx_module: Any, **kwargs: Any) -> Any:
    """Create a guarded sync client from an httpx-compatible module."""
    kwargs["event_hooks"] = ssrf_safe_event_hooks(
        kwargs.get("event_hooks"), policy_fingerprint=ssrf_policy_fingerprint())
    client = httpx_module.Client(**kwargs)
    _install_ssrf_guard_on_client(client)
    return client


def create_ssrf_safe_async_client(**kwargs: Any) -> Any:
    """``httpx.AsyncClient`` with connect-time SSRF validation: direct HTTP(S) connections are
    resolved, validated, and dialed by IP while the hostname is preserved for Host, SNI, and
    certificate verification. Proxied requests are preflight-validated on every hop."""
    import httpx
    return create_ssrf_safe_async_client_for(httpx, **kwargs)


def create_ssrf_safe_client(**kwargs: Any) -> Any:
    """Create an ``httpx.Client`` with connect-time SSRF validation."""
    import httpx
    return create_ssrf_safe_client_for(httpx, **kwargs)


def redirect_target_from_response(response: Any) -> Optional[str]:
    """Redirect target visible from inside an httpx response hook. ``response.next_request`` is
    frequently ``None`` inside hooks (populated later by the follower), which would make an SSRF
    redirect guard silently never fire — so resolve from ``Location`` first, then ``next_request``."""
    if not getattr(response, "is_redirect", False):
        return None
    location = (getattr(response, "headers", {}) or {}).get("location")
    if location:
        return urljoin(str(getattr(response, "url", "")), str(location))
    next_request = getattr(response, "next_request", None)
    return str(next_request.url) if next_request else None
