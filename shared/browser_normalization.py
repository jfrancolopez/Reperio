"""Browser URL/domain and timestamp display normalization helpers."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from hashlib import sha256
from ipaddress import ip_address
from typing import Any
from urllib.parse import SplitResult, parse_qsl, quote, unquote, urlsplit, urlunsplit

COMMON_SECOND_LEVEL_DOMAINS = frozenset({"co", "com", "edu", "gov", "net", "org"})
URL_FIELDS = ("url", "source_url")


def normalize_browser_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return a browser artifact with derived URL/domain/time fields.

    The original URL-bearing fields are preserved exactly. Derived fields are
    advisory search/display values and must not be used as replacement evidence.
    """

    normalized = deepcopy(dict(record))
    for field in URL_FIELDS:
        value = normalized.get(field)
        if isinstance(value, str) and value:
            normalized[f"{field}_normalization"] = normalize_url(value)
    for key, value in tuple(normalized.items()):
        if key.endswith("_time") and isinstance(value, Mapping):
            normalized[key] = normalize_timestamp_display(value)
    if normalized.get("artifact_kind") == "visit":
        normalized["visit_collapse_key"] = _visit_collapse_key(normalized)
    return normalized


def normalize_url(url: str) -> dict[str, Any]:
    warnings: list[str] = []
    try:
        parsed = urlsplit(url)
    except ValueError:
        return {
            "original_url_preserved": url,
            "canonical_url": url,
            "display_url": url,
            "host": "",
            "registrable_domain": "",
            "origin": "",
            "query_keys": (),
            "fragment_present": "#" in url,
            "warnings": ("malformed_url",),
        }
    scheme = parsed.scheme.lower()
    raw_host = parsed.hostname or ""
    host = _safe_host(raw_host, warnings)
    port = _port(parsed, warnings)
    netloc = _netloc(host, port, scheme) if host else parsed.netloc.lower()
    path = quote(unquote(parsed.path), safe="/%:@")
    query = quote(unquote(parsed.query), safe="=&?/:@+,%")
    canonical_url = urlunsplit((scheme, netloc, path, query, ""))
    origin = urlunsplit((scheme, netloc, "", "", "")) if scheme and netloc else ""
    query_keys = tuple(key for key, _value in parse_qsl(parsed.query, keep_blank_values=True))
    if parsed.fragment:
        warnings.append("fragment_omitted_from_canonical_url")
    return {
        "original_url_preserved": url,
        "canonical_url": canonical_url or url,
        "display_url": urlunsplit((scheme, netloc, path, query, parsed.fragment)),
        "scheme": scheme,
        "host": host,
        "registrable_domain": _registrable_domain(host),
        "origin": origin,
        "query_keys": query_keys,
        "fragment_present": bool(parsed.fragment),
        "warnings": tuple(warnings),
    }


def normalize_timestamp_display(timestamp: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(timestamp)
    normalized_utc = normalized.get("normalized_utc")
    timezone = str(normalized.get("display_timezone") or "UTC")
    if isinstance(normalized_utc, str) and "local_display" not in normalized:
        normalized["local_display"] = normalized_utc
    if "timezone_note" not in normalized:
        normalized["timezone_note"] = (
            "source_timezone_unavailable_utc_display"
            if timezone == "UTC"
            else "source_timezone_display"
        )
    return normalized


def _safe_host(host: str, warnings: list[str]) -> str:
    if not host:
        return ""
    lower_host = host.rstrip(".").lower()
    try:
        ascii_host = lower_host.encode("idna").decode("ascii")
    except UnicodeError:
        warnings.append("invalid_idn_host")
        return lower_host
    if ascii_host != lower_host:
        warnings.append("idn_host_punycode_display")
    return ascii_host


def _registrable_domain(host: str) -> str:
    if not host or _looks_like_ip(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in COMMON_SECOND_LEVEL_DOMAINS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _looks_like_ip(host: str) -> bool:
    try:
        ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _port(parsed: SplitResult, warnings: list[str]) -> int | None:
    try:
        return parsed.port
    except ValueError:
        warnings.append("invalid_port")
        return None


def _netloc(host: str, port: int | None, scheme: str) -> str:
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port is None or (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return host_part
    return f"{host_part}:{port}"


def _visit_collapse_key(record: Mapping[str, Any]) -> str:
    url_facts = record.get("url_normalization")
    canonical_url = ""
    if isinstance(url_facts, Mapping):
        canonical_url = str(url_facts.get("canonical_url") or "")
    visit_time = record.get("visit_time")
    normalized_utc = ""
    if isinstance(visit_time, Mapping):
        normalized_utc = str(visit_time.get("normalized_utc") or "")
    raw_key = "\0".join((str(record.get("profile_id") or ""), canonical_url, normalized_utc))
    return f"browser-visit-collapse-{sha256(raw_key.encode('utf-8')).hexdigest()[:32]}"
