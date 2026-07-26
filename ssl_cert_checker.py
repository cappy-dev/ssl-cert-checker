#!/usr/bin/env python3
"""ssl-cert-checker

Check the TLS/SSL certificate expiry for one or more hostnames and report
when each certificate is close to expiring. Pure standard library, no
external dependencies.

Usage:
    python3 ssl_cert_checker.py example.com google.com github.com
    python3 ssl_cert_checker.py --days 14 host1.example.com host2.example.com
    python3 ssl_cert-checker --json example.com
    echo -e "example.com\\ngithub.com" | python3 ssl_cert_checker.py -                  # read hosts from stdin

Exit codes:
    0  all checked certificates are outside the warning window
    1  at least one certificate is within the warning window or already expired
    2  at least one host could not be checked at all (DNS, connection, TLS error)
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone


DEFAULT_PORT = 443
DEFAULT_WARNING_DAYS = 30
CONNECT_TIMEOUT = 10
DEFAULT_USER_AGENT = "ssl-cert-checker/1.0 (https://github.com/cappy-dev/ssl-cert-checker)"


@dataclass
class CertResult:
    host: str
    port: int
    status: str            # "ok", "warning", "expired", "error"
    subject: str
    issuer: str
    not_before: str        # ISO 8601 UTC or empty on error
    not_after: str         # ISO 8601 UTC or empty on error
    days_remaining: int    # negative if expired
    message: str           # human readable detail or error message


def _default_context() -> ssl.SSLContext:
    """Build an SSL context that still lets us read the cert dict.

    We disable hostname pinning so we can still inspect self-signed or wildcard
    certificates, but we keep CERT_OPTIONAL so that getpeercert() returns the
    parsed certificate dictionary rather than an empty dict (Python returns
    '{}' when verification is fully disabled, for safety reasons).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL
    return ctx


def _iso(dt: datetime) -> str:
    """Render a datetime as ISO 8601 UTC string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_host(host: str, port: int = DEFAULT_PORT, timeout: int = CONNECT_TIMEOUT) -> CertResult:
    """Connect to host:port over TLS and return a CertResult."""
    base = CertResult(
        host=host,
        port=port,
        status="error",
        subject="",
        issuer="",
        not_before="",
        not_after="",
        days_remaining=-9999,
        message="",
    )
    try:
        addr_info = socket.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        base.message = f"DNS resolution failed: {exc}"
        return base

    ctx = _default_context()
    last_error = ""
    for family, socktype, proto, _canon, sockaddr in addr_info:
        try:
            with socket.create_connection(sockaddr, timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        base.message = "No certificate presented by the server."
                        return base
                    return _result_from_cert(base, cert)
        except (socket.timeout, OSError, ssl.SSLError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            continue

    base.message = f"Could not establish TLS connection. Last error: {last_error}"
    return base


def _result_from_cert(base: CertResult, cert: dict) -> CertResult:
    subject_parts = ["=".join(item) for sublist in cert.get("subject", []) for item in sublist]
    issuer_parts = ["=".join(item) for sublist in cert.get("issuer", []) for item in sublist]
    subject = ", ".join(subject_parts)
    issuer = ", ".join(issuer_parts)

    not_before_str = cert.get("notBefore", "")
    not_after_str = cert.get("notAfter", "")
    try:
        not_before = ssl.cert_time_to_seconds(not_before_str)
        not_after = ssl.cert_time_to_seconds(not_after_str)
    except (ValueError, TypeError) as exc:
        base.message = f"Could not parse certificate dates: {exc}"
        return base

    now = datetime.now(timezone.utc).timestamp()
    not_before_dt = datetime.fromtimestamp(not_before, tz=timezone.utc)
    not_after_dt = datetime.fromtimestamp(not_after, tz=timezone.utc)
    days_remaining = int((not_after - now) // 86400)

    if now > not_after:
        status = "expired"
        message = f"Certificate expired {-days_remaining} day(s) ago."
    elif now < not_before:
        status = "warning"
        message = "Certificate is not yet valid (starts in the future)."
    else:
        status = "ok"
        message = f"Certificate valid for {days_remaining} more day(s)."

    return CertResult(
        host=base.host,
        port=base.port,
        status=status,
        subject=subject,
        issuer=issuer,
        not_before=_iso(not_before_dt),
        not_after=_iso(not_after_dt),
        days_remaining=days_remaining,
        message=message,
    )


def _format_result(result: CertResult, warning_days: int) -> str:
    """Render one result as plain text for terminal output."""
    if result.status == "error":
        symbol = "ERROR"
    elif result.status == "expired":
        symbol = "EXPIRED"
    elif result.status == "warning":
        symbol = "WARNING"
    elif result.days_remaining <= warning_days:
        symbol = "WARNING"
    else:
        symbol = "OK"

    lines = [
        f"[{symbol}] {result.host}:{result.port}",
        f"  subject : {result.subject}",
        f"  issuer  : {result.issuer}",
    ]
    if result.status in ("ok", "warning", "expired"):
        lines.append(f"  expires: {result.not_after}")
        lines.append(f"  days   : {result.days_remaining}")
    lines.append(f"  detail : {result.message}")
    return "\n".join(lines)


def _read_hosts(args: argparse.Namespace) -> list[str]:
    hosts = list(args.hosts) if args.hosts else []
    if args.stdin or "-" in hosts:
        if "-" in hosts:
            hosts.remove("-")
        data = sys.stdin.read()
        stdin_hosts = [line.strip() for line in data.splitlines() if line.strip()]
        hosts.extend(stdin_hosts)
    return hosts


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ssl-cert-checker",
        description="Check TLS certificate expiry for one or more hostnames.",
    )
    parser.add_argument(
        "hosts",
        nargs="*",
        help="Hostnames to check. Use '-' to also read hosts from stdin.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port to connect to (default: {DEFAULT_PORT}).",
    )
    parser.add_argument(
        "-w",
        "--days",
        type=int,
        default=DEFAULT_WARNING_DAYS,
        help="Warn when a certificate expires within this many days (default: 30).",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read hostnames from stdin, one per line.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as a JSON array.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=CONNECT_TIMEOUT,
        help=f"Per-host connect timeout in seconds (default: {CONNECT_TIMEOUT}).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.hosts and not args.stdin:
        parse_args(["--help"])

    hosts = _read_hosts(args)
    if not hosts:
        print("No hosts provided.", file=sys.stderr)
        return 2

    hosts = list(dict.fromkeys(hosts))  # de-duplicate, keep order
    results = [
        check_host(host, port=args.port, timeout=args.timeout) for host in hosts
    ]

    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        for r in results:
            print(_format_result(r, args.days))
            print()

    now_expired = any(r.status == "expired" for r in results)
    now_warning = any(r.days_remaining <= args.days and r.status != "expired" for r in results)
    now_error = any(r.status == "error" for r in results)

    if now_error:
        return 2
    if now_expired or now_warning:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
