"""Fail-closed application-layer boundary for offline experiment children."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import subprocess
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Mapping, MutableMapping, Sequence
from urllib.parse import urlsplit


class ExternalCallBoundaryError(RuntimeError):
    pass


SAFETY_SWITCHES = (
    "ALLOW_NETWORK",
    "ALLOW_LIVE_SERVICES",
    "ALLOW_SANDBOX_SERVICES",
    "ALLOW_REAL_PAYMENT",
    "ALLOW_PRODUCTION_WRITES",
)
PROXY_ENV_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "ftp_proxy",
)
DYNAMIC_LOADER_ENV_VARS = ("LD_PRELOAD", "LD_LIBRARY_PATH")
DENY_INET_LIBRARY = (
    Path(__file__).resolve().parents[1]
    / "canonical/runtime/deny-inet/libminmandate_deny_inet.so"
).resolve()
ENDPOINT_ENV_VARS = {
    "OLLAMA_HOST", "MINMANDATE_ENDPOINT", "MERCHANT_ENDPOINT",
    "REDEMPTION_ENDPOINT", "SETTLEMENT_ENDPOINT",
    "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "HF_ENDPOINT",
}
PRODUCTION_DOMAINS = (
    "clay.com", "attio.com", "hubspot.com", "intercom.com",
    "stripe.com", "alpaca.markets", "binance.com",
)
_FALSE = {"", "0", "false", "no", "off"}
_TRUE = {"1", "true", "yes", "on"}
_SENSITIVE_EXACT = {
    "CLAY_API_KEY", "ATTIO_API_KEY", "HUBSPOT_API_KEY",
    "HUBSPOT_ACCESS_TOKEN", "INTERCOM_ACCESS_TOKEN",
    "STRIPE_API_KEY", "STRIPE_SECRET_KEY", "ALPACA_API_KEY",
    "ALPACA_SECRET_KEY", "BINANCE_API_KEY", "BINANCE_SECRET_KEY",
    "OAUTH_TOKEN", "OAUTH_ACCESS_TOKEN", "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "CLAY_TOKEN", "ATTIO_TOKEN", "HUBSPOT_TOKEN", "INTERCOM_TOKEN",
    "STRIPE_TOKEN", "ALPACA_TOKEN", "BINANCE_TOKEN",
}
_SENSITIVE_RE = re.compile(
    r"(?:^|_)(?:API_KEY|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|OAUTH_TOKEN|"
    r"BEARER|PASSWORD|SECRET|SECRET_KEY|CLIENT_SECRET|PRIVATE_KEY|"
    r"SIGNING_SECRET|WEBHOOK_SECRET|CREDENTIALS?)(?:$|_)",
    re.IGNORECASE,
)
_ENDPOINT_RE = re.compile(
    r"(?:_ENDPOINT|_BASE_URL|_API_BASE|_API_URL|_SERVICE_URL|_URL|_URI|"
    r"_HOST|_ORIGIN)$", re.IGNORECASE
)


def _enabled(value: object) -> bool:
    normalized = str(value).strip().lower()
    if normalized in _FALSE:
        return False
    if normalized in _TRUE:
        return True
    raise ExternalCallBoundaryError(
        f"ambiguous safety switch value {value!r}"
    )


def is_sensitive_env_name(name: str) -> bool:
    upper = name.upper()
    return upper in _SENSITIVE_EXACT or bool(_SENSITIVE_RE.search(upper))


def is_endpoint_env_name(name: str) -> bool:
    return name.upper() in ENDPOINT_ENV_VARS or bool(
        _ENDPOINT_RE.search(name)
    )


def is_loopback_host(host: str) -> bool:
    value = host.strip().strip("[]").split("%", 1)[0].lower()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def validate_local_endpoint(endpoint: str) -> str:
    value = str(endpoint).strip()
    if not value:
        raise ExternalCallBoundaryError("empty endpoint")
    parsed = urlsplit(value if "://" in value else f"http://{value}")
    if parsed.scheme not in {"http", "https", "ws", "wss", "tcp"}:
        raise ExternalCallBoundaryError(
            f"prohibited endpoint scheme {parsed.scheme!r}"
        )
    if parsed.username or parsed.password:
        raise ExternalCallBoundaryError("endpoint userinfo is prohibited")
    if not parsed.hostname or not is_loopback_host(parsed.hostname):
        raise ExternalCallBoundaryError(
            f"non-loopback endpoint prohibited: {endpoint!r}"
        )
    return value


def source_tree_sha256(path: str | Path) -> str:
    """Hash stable source files while excluding interpreter caches."""

    root = Path(path).resolve()
    if not root.is_dir():
        raise ExternalCallBoundaryError(f"source tree is absent: {root}")
    files = sorted(
        candidate
        for candidate in root.rglob("*")
        if candidate.is_file()
        and "__pycache__" not in candidate.parts
        and candidate.suffix != ".pyc"
    )
    if not files:
        raise ExternalCallBoundaryError(f"source tree is empty: {root}")
    digest = hashlib.sha256()
    for candidate in files:
        if candidate.is_symlink():
            raise ExternalCallBoundaryError(
                f"symlink prohibited in frozen source tree: {candidate}"
            )
        relative = candidate.relative_to(root).as_posix().encode("utf-8")
        payload = candidate.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def assert_experiment_environment(
    env: Mapping[str, str] | None = None,
) -> None:
    active = dict(os.environ if env is None else env)
    for switch in SAFETY_SWITCHES:
        if _enabled(active.get(switch, "false")):
            raise ExternalCallBoundaryError(f"{switch} must remain false")
    leaked = sorted(
        key for key, value in active.items()
        if value and is_sensitive_env_name(key)
    )
    if leaked:
        raise ExternalCallBoundaryError(
            "credential material prohibited in experiment child: "
            + ", ".join(leaked)
        )
    proxies = sorted(key for key in PROXY_ENV_VARS if active.get(key))
    if proxies:
        raise ExternalCallBoundaryError(
            "proxy variables prohibited in experiment child: "
            + ", ".join(proxies)
        )
    preload = active.get("LD_PRELOAD", "").strip()
    if preload and Path(preload).resolve() != DENY_INET_LIBRARY:
        raise ExternalCallBoundaryError("untrusted LD_PRELOAD is prohibited")
    if active.get("LD_LIBRARY_PATH"):
        raise ExternalCallBoundaryError("LD_LIBRARY_PATH is prohibited")
    for key, value in active.items():
        lowered = str(value).lower()
        if value and any(domain in lowered for domain in PRODUCTION_DOMAINS):
            raise ExternalCallBoundaryError(
                f"production domain prohibited in environment value {key}"
            )
        if not value or not is_endpoint_env_name(key):
            continue
        validate_local_endpoint(value)


def build_child_environment(
    base_env: Mapping[str, str] | None = None,
    overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Sanitize a copy without mutating os.environ or host networking."""

    source = dict(os.environ if base_env is None else base_env)
    child: MutableMapping[str, str] = {}
    for key, value in source.items():
        if (
            key in PROXY_ENV_VARS
            or key in DYNAMIC_LOADER_ENV_VARS
            or key in SAFETY_SWITCHES
            or is_sensitive_env_name(key)
            or is_endpoint_env_name(key)
        ):
            continue
        child[key] = value
    for switch in SAFETY_SWITCHES:
        child[switch] = "false"
    child["NO_PROXY"] = "localhost,127.0.0.1,::1"
    child["no_proxy"] = "localhost,127.0.0.1,::1"

    for key, value in dict(overrides or {}).items():
        if key in PROXY_ENV_VARS:
            raise ExternalCallBoundaryError(
                f"explicit proxy override {key} prohibited"
            )
        if key == "LD_LIBRARY_PATH":
            raise ExternalCallBoundaryError("LD_LIBRARY_PATH is prohibited")
        if key == "LD_PRELOAD":
            candidate = Path(value).resolve()
            if candidate != DENY_INET_LIBRARY or not candidate.is_file():
                raise ExternalCallBoundaryError(
                    "LD_PRELOAD must be the frozen deny-INET library"
                )
        if value and is_sensitive_env_name(key):
            raise ExternalCallBoundaryError(
                f"explicit credential override {key} prohibited"
            )
        if key in SAFETY_SWITCHES and _enabled(value):
            raise ExternalCallBoundaryError(f"{key} cannot be enabled")
        if is_endpoint_env_name(key):
            validate_local_endpoint(value)
        child[key] = value
    assert_experiment_environment(child)
    return dict(child)


class LocalhostOnlySocketGuard(AbstractContextManager):
    """Process-local guard for DNS, TCP, UDP, and message sends."""

    def __init__(self) -> None:
        self._originals = None

    @staticmethod
    def _check_address(address: object) -> None:
        if not isinstance(address, tuple) or not address:
            raise ExternalCallBoundaryError(
                "only loopback TCP tuple addresses are allowed"
            )
        host = address[0]
        if not isinstance(host, str) or not is_loopback_host(host):
            raise ExternalCallBoundaryError(
                f"outbound socket prohibited: {address!r}"
            )

    def __enter__(self):
        if self._originals is not None:
            raise RuntimeError("socket guard already active")
        originals = {
            "getaddrinfo": socket.getaddrinfo,
            "gethostbyname": socket.gethostbyname,
            "gethostbyname_ex": socket.gethostbyname_ex,
            "gethostbyaddr": socket.gethostbyaddr,
            "create_connection": socket.create_connection,
            "connect": socket.socket.connect,
            "connect_ex": socket.socket.connect_ex,
            "sendto": socket.socket.sendto,
            "sendmsg": socket.socket.sendmsg,
        }
        self._originals = originals

        def guarded_getaddrinfo(host, *args, **kwargs):
            if not isinstance(host, str) or not is_loopback_host(host):
                raise ExternalCallBoundaryError(
                    f"DNS lookup prohibited: {host!r}"
                )
            return originals["getaddrinfo"](host, *args, **kwargs)

        def guarded_gethostbyname(host):
            if not isinstance(host, str) or not is_loopback_host(host):
                raise ExternalCallBoundaryError(
                    f"DNS lookup prohibited: {host!r}"
                )
            return originals["gethostbyname"](host)

        def guarded_gethostbyname_ex(host):
            if not isinstance(host, str) or not is_loopback_host(host):
                raise ExternalCallBoundaryError(
                    f"DNS lookup prohibited: {host!r}"
                )
            return originals["gethostbyname_ex"](host)

        def guarded_gethostbyaddr(host):
            if not isinstance(host, str) or not is_loopback_host(host):
                raise ExternalCallBoundaryError(
                    f"reverse DNS lookup prohibited: {host!r}"
                )
            return originals["gethostbyaddr"](host)

        def guarded_create(address, *args, **kwargs):
            self._check_address(address)
            return originals["create_connection"](address, *args, **kwargs)

        def guarded_connect(sock, address):
            self._check_address(address)
            return originals["connect"](sock, address)

        def guarded_connect_ex(sock, address):
            self._check_address(address)
            return originals["connect_ex"](sock, address)

        def guarded_sendto(sock, data, *args):
            if not args:
                raise ExternalCallBoundaryError("sendto address is required")
            self._check_address(args[-1])
            return originals["sendto"](sock, data, *args)

        def guarded_sendmsg(sock, buffers, ancdata=(), flags=0, address=None):
            if address is None:
                raise ExternalCallBoundaryError(
                    "sendmsg on an unverified connected socket is prohibited"
                )
            self._check_address(address)
            return originals["sendmsg"](
                sock, buffers, ancdata, flags, address
            )

        socket.getaddrinfo = guarded_getaddrinfo
        socket.gethostbyname = guarded_gethostbyname
        socket.gethostbyname_ex = guarded_gethostbyname_ex
        socket.gethostbyaddr = guarded_gethostbyaddr
        socket.create_connection = guarded_create
        socket.socket.connect = guarded_connect
        socket.socket.connect_ex = guarded_connect_ex
        socket.socket.sendto = guarded_sendto
        socket.socket.sendmsg = guarded_sendmsg
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self._originals is not None:
            socket.getaddrinfo = self._originals["getaddrinfo"]
            socket.gethostbyname = self._originals["gethostbyname"]
            socket.gethostbyname_ex = self._originals["gethostbyname_ex"]
            socket.gethostbyaddr = self._originals["gethostbyaddr"]
            socket.create_connection = self._originals["create_connection"]
            socket.socket.connect = self._originals["connect"]
            socket.socket.connect_ex = self._originals["connect_ex"]
            socket.socket.sendto = self._originals["sendto"]
            socket.socket.sendmsg = self._originals["sendmsg"]
        self._originals = None
        return None


def run_local_child(
    argv: Sequence[str],
    *,
    base_env: Mapping[str, str] | None = None,
    overrides: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
    **kwargs,
) -> subprocess.CompletedProcess:
    child_env = build_child_environment(base_env, overrides)
    return subprocess.run(
        list(argv),
        env=child_env,
        cwd=None if cwd is None else str(cwd),
        check=kwargs.pop("check", True),
        **kwargs,
    )
