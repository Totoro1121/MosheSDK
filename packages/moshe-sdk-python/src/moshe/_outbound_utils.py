from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlparse

_LOOPBACK_RE = re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


@dataclass(frozen=True)
class ParsedTarget:
    raw: str
    hostname: str
    scheme: str
    path: str


def parse_outbound_target(target: str) -> ParsedTarget | None:
    parsed = urlparse(target)
    if not parsed.scheme or not parsed.hostname:
        return None
    return ParsedTarget(
        raw=target,
        hostname=parsed.hostname.lower(),
        scheme=parsed.scheme.lower(),
        path=parsed.path or "/",
    )


def domain_matches_pattern(hostname: str, pattern: str) -> bool:
    normalized_host = hostname.lower()
    normalized_pattern = pattern.lower()
    if normalized_pattern.startswith("*."):
        suffix = normalized_pattern[2:]
        return normalized_host == suffix or normalized_host.endswith(f".{suffix}")
    return normalized_host == normalized_pattern or normalized_host.endswith(f".{normalized_pattern}")


def is_local_network_host(hostname: str) -> bool:
    normalized = hostname.lower()
    return normalized in {"localhost", "0.0.0.0", "::1", "[::1]"} or bool(_LOOPBACK_RE.match(normalized))


def _parse_pattern_target(pattern: str) -> tuple[str, str, str] | None:
    normalized = pattern.strip().lower()
    if normalized == "":
        return None

    scheme = "https"
    remainder = normalized
    if normalized.startswith("http://"):
        scheme = "http"
        remainder = normalized[len("http://") :]
    elif normalized.startswith("https://"):
        scheme = "https"
        remainder = normalized[len("https://") :]

    slash_index = remainder.find("/")
    authority = remainder[:slash_index] if slash_index >= 0 else remainder
    path = remainder[slash_index:] if slash_index >= 0 else "/"
    if authority == "":
        return None

    return scheme, authority, path


def matches_outbound_pattern(target: str, pattern: str) -> bool:
    normalized_pattern = pattern.strip().lower()
    parsed_target = parse_outbound_target(target)
    if parsed_target is None:
        return normalized_pattern in target.lower()

    parsed_pattern = _parse_pattern_target(normalized_pattern)
    if parsed_pattern is None:
        return normalized_pattern in target.lower()

    pattern_has_scheme = normalized_pattern.startswith("http://") or normalized_pattern.startswith("https://")
    scheme, authority, path = parsed_pattern
    host_parts = authority.split(":", 1)
    hostname = host_parts[0]
    port = host_parts[1] if len(host_parts) > 1 else ""

    if pattern_has_scheme and parsed_target.scheme != scheme:
        return False

    if not domain_matches_pattern(parsed_target.hostname, hostname):
        return False

    parsed_target_port = urlparse(target).port
    if port and str(parsed_target_port or "") != port:
        return False

    if path and path != "/" and not parsed_target.path.startswith(path):
        return False

    return True
