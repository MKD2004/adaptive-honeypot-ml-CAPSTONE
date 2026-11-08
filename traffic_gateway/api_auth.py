"""
traffic_gateway/api_auth.py

Authentication for the gateway API's state-changing endpoints, and a start-up
guard that refuses to expose them unprotected.

WHY. HONEYPOT_AUDIT.md PART 3, fix #1 -- rated more urgent than any of the other
thirteen items. `POST`/`DELETE` on `/api/blacklist` and `/api/whitelist` had no
authentication and `CORS(app)` allowed every origin, so anyone who could reach
port 5000 could whitelist themselves in one HTTP request. That is a complete
bypass of the gateway, the honeypot and MT3 at once. It matters more now that
`response_mitigation/safelist.py` lets a strong verdict override a whitelist:
self-whitelisting is the way to undo the fix that closed that hole.

THE DESIGN, and why it is shaped like this

A honeypot console has one operator and no user accounts, so a shared bearer
token is the right weight of mechanism -- sessions, password hashing and a user
table would all be scaffolding around a single secret.

Three rules:

  1. State-changing endpoints (POST/DELETE/PUT/PATCH) require the token whenever
     one is configured.
  2. Reads are open by default. The dashboard polls them constantly and they
     carry no authority. `GATEWAY_API_REQUIRE_AUTH_FOR_READS=1` closes them too,
     which is worth doing on a public box because the feed contains attacker IPs
     and captured credentials.
  3. **Binding a non-loopback address with no token is refused at start-up.**
     This is the part that actually protects anyone. The realistic failure is not
     a weak token, it is deploying to a VPS having never set one -- so that
     specific mistake stops the process instead of silently exposing it.

Leaving `GATEWAY_API_TOKEN` unset while bound to loopback keeps today's
behaviour exactly, so the demo and the local dashboard are unaffected.

WHAT THIS DOES NOT DO

No TLS. A bearer token over plain HTTP is readable in transit, so on a public
host this belongs behind an SSH tunnel or a TLS-terminating reverse proxy. The
start-up guard deliberately does not pretend otherwise -- it stops the
no-token-on-a-public-port mistake, not every transport mistake.

No rate limiting on the token check. An attacker who can reach the port can
guess, so generate a long random token (`secrets.token_urlsafe(32)`), which is
what `python -m traffic_gateway.api_auth` prints.
"""
from __future__ import annotations

import hmac
import ipaddress
import logging
import os
from functools import wraps
from typing import Callable, List, Optional, Sequence

log = logging.getLogger("traffic_gateway.api_auth")

__all__ = [
    "AuthError", "InsecureExposure",
    "configured_token", "allowed_origins", "reads_need_auth",
    "token_from_request", "token_matches", "require_token",
    "assert_safe_to_serve", "is_loopback_host", "auth_status",
]

# Methods that change state. GET/HEAD/OPTIONS do not.
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_DEFAULT_ORIGINS = (
    "http://localhost:5173", "http://127.0.0.1:5173",     # vite dev server
    "http://localhost:3000", "http://127.0.0.1:3000",
    "http://localhost:5000", "http://127.0.0.1:5000",     # the legacy dashboard
)


class AuthError(Exception):
    """A request did not carry a usable token."""


class InsecureExposure(RuntimeError):
    """Refusing to serve: the bind address is reachable and no token is set."""


def configured_token() -> Optional[str]:
    """`GATEWAY_API_TOKEN`, or None when unset/blank.

    A token shorter than 16 characters is rejected outright rather than accepted
    with a warning. A short secret on a public port is the failure this module
    exists to prevent, and a warning in a log nobody reads is not protection.
    """
    raw = os.environ.get("GATEWAY_API_TOKEN", "").strip()
    if not raw:
        return None
    if len(raw) < 16:
        raise InsecureExposure(
            f"GATEWAY_API_TOKEN is only {len(raw)} characters. Use at least 16; "
            f"generate one with: python -m traffic_gateway.api_auth")
    return raw


def reads_need_auth() -> bool:
    """Whether GET endpoints also require the token."""
    return os.environ.get("GATEWAY_API_REQUIRE_AUTH_FOR_READS", "").strip().lower() in {
        "1", "true", "yes", "on"}


def allowed_origins() -> List[str]:
    """Browser origins the API answers to.

    `GATEWAY_API_ORIGINS` is a comma-separated list. `*` is honoured but logged
    loudly, because it is what the audit found and it is almost never right.
    """
    raw = os.environ.get("GATEWAY_API_ORIGINS", "").strip()
    if not raw:
        return list(_DEFAULT_ORIGINS)
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    if "*" in origins:
        log.warning("GATEWAY_API_ORIGINS=* allows every browser origin. This is "
                    "the wide-open CORS the audit flagged; set real origins.")
    return origins


def is_loopback_host(host: str) -> bool:
    """Is this bind address reachable only from this machine?

    An empty host or 0.0.0.0 / :: means every interface, which is NOT loopback.
    Anything unparseable is treated as reachable -- fail closed.
    """
    text = (host or "").strip()
    if not text:
        return False
    if text in ("localhost",):
        return True
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    if addr in (ipaddress.ip_address("0.0.0.0"), ipaddress.ip_address("::")):
        return False
    return addr.is_loopback


def assert_safe_to_serve(host: str) -> None:
    """Raise InsecureExposure if `host` is reachable and no token is configured.

    Called from api.serve(). This is the guard that matters: the realistic
    mistake is deploying to a public box having never set a token.
    """
    token = configured_token()          # also validates the length
    if token is not None:
        return
    if is_loopback_host(host):
        log.info("API on %s with no token: loopback only, so state-changing "
                 "endpoints stay open (unchanged local behaviour).", host)
        return
    raise InsecureExposure(
        f"Refusing to serve the API on {host!r} with no GATEWAY_API_TOKEN set.\n"
        f"  POST/DELETE on /api/blacklist and /api/whitelist would be open to "
        f"anyone who can reach this port, which lets them whitelist themselves "
        f"past the gateway, the honeypot and MT3 (HONEYPOT_AUDIT.md PART 3).\n"
        f"  Either set a token:    GATEWAY_API_TOKEN=$(python -m traffic_gateway.api_auth)\n"
        f"  or bind to loopback:   --host 127.0.0.1")


def token_from_request(headers, args=None) -> Optional[str]:
    """The presented token, from `Authorization: Bearer ...` or `X-API-Token`.

    Query strings are deliberately NOT accepted: they end up in access logs,
    browser history and `Referer` headers.
    """
    auth = (headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        candidate = auth[7:].strip()
        if candidate:
            return candidate
    header = (headers.get("X-API-Token") or "").strip()
    return header or None


def token_matches(presented: Optional[str], expected: Optional[str]) -> bool:
    """Constant-time comparison, so timing does not leak the token."""
    if not expected or not presented:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def require_token(view: Callable) -> Callable:
    """Flask decorator: demand the token on writes (and on reads if configured).

    No token configured -> the view runs. That keeps local development and the
    demo exactly as they were; `assert_safe_to_serve` is what stops that leniency
    reaching a public port.
    """
    @wraps(view)
    def wrapper(*args, **kwargs):
        from flask import jsonify, request

        expected = configured_token()
        if expected is None:
            return view(*args, **kwargs)

        is_write = request.method.upper() in _WRITE_METHODS
        if not is_write and not reads_need_auth():
            return view(*args, **kwargs)

        presented = token_from_request(request.headers)
        if not token_matches(presented, expected):
            log.warning("rejected unauthenticated %s %s from %s",
                        request.method, request.path, request.remote_addr)
            body = {"ok": False,
                    "error": "authentication required",
                    "detail": "send the token as 'Authorization: Bearer <token>' "
                              "or 'X-API-Token: <token>'"}
            return jsonify(body), 401, {"WWW-Authenticate": "Bearer"}
        return view(*args, **kwargs)

    return wrapper


def auth_status(host: Optional[str] = None) -> dict:
    """What the API will do, for /api/health and the start-up banner.

    Never includes the token or any part of it.
    """
    try:
        token = configured_token()
        problem = None
    except InsecureExposure as exc:
        token, problem = None, str(exc)
    status = {
        "token_configured": token is not None,
        "writes_require_token": token is not None,
        "reads_require_token": bool(token is not None and reads_need_auth()),
        "allowed_origins": allowed_origins(),
    }
    if host is not None:
        status["bind_is_loopback"] = is_loopback_host(host)
    if problem:
        status["problem"] = problem
    return status


def _generate() -> str:
    import secrets
    return secrets.token_urlsafe(32)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Print a fresh token. `python -m traffic_gateway.api_auth`"""
    print(_generate())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
