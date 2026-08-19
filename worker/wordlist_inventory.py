"""Dictionary/rule/mask inventory and strategy management (RPR-097).

Tracks wordlists with source/licence/hash/size/language metadata, validates
hashcat-style rules and masks while rejecting arbitrary shell syntax, estimates
search space, orders strategies, and enforces enablement and import limits.
Wordlist downloads never occur without an explicit admin action. Pure and
dependency-free; no network or file I/O.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

WORDLIST_INVENTORY_VERSION = "wordlist-inventory-v1"

DICTIONARY_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_SOURCE_SCHEMES = frozenset({"https", "scratch"})
SHELL_METACHARS = frozenset({";", "&", "|", "<", ">", "`", "(", ")", "'", '"', " "})
RULE_SUBSTITUTION_PREFIXES = ("$(", "${", "$[", "$`")

MASK_CHARSETS = {
    "?l": 26,
    "?u": 26,
    "?d": 10,
    "?s": 33,
    "?a": 95,
    "?b": 256,
}
CUSTOM_MASK = re.compile(r"^\?[1-9]$")
CUSTOM_RANGE = re.compile(r"\[[a-zA-Z0-9!@#$%^&*()_+{}\[\]:,.<>?/|~`-]+\]")

MAX_IMPORT_BYTES = 512 * 1024 * 1024
DEFAULT_ADMIN_ACTION = False


class WordlistInventoryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Dictionary:
    name: str
    source: str
    license: str
    sha256: str
    size_bytes: int
    language: str
    enabled: bool = True


@dataclass(frozen=True)
class WordlistInventory:
    version: str
    dictionaries: tuple[Dictionary, ...]

    def by_name(self, name: str) -> Dictionary | None:
        for dictionary in self.dictionaries:
            if dictionary.name == name:
                return dictionary
        return None

    def enabled_names(self) -> tuple[str, ...]:
        return tuple(dictionary.name for dictionary in self.dictionaries if dictionary.enabled)


def register_dictionaries(records: Sequence[Mapping[str, Any]]) -> WordlistInventory:
    """Build the inventory, rejecting duplicates and missing licence metadata."""
    dictionaries: list[Dictionary] = []
    seen: set[str] = set()
    for record in records:
        name = _required_str(record, "name")
        if not DICTIONARY_NAME_RE.match(name):
            raise WordlistInventoryError("unsafe_name", f"dictionary name {name!r} is not safe")
        if name in seen:
            raise WordlistInventoryError(
                "duplicate_dictionary", f"dictionary {name!r} is registered more than once"
            )
        seen.add(name)
        source = _required_str(record, "source")
        scheme = source.split(":", 1)[0].lower() if ":" in source else ""
        if scheme not in SAFE_SOURCE_SCHEMES:
            raise WordlistInventoryError(
                "unsafe_source", "wordlist sources must be https or scratch references"
            )
        sha256 = _required_str(record, "sha256").lower()
        if not SHA256_RE.match(sha256):
            raise WordlistInventoryError("invalid_hash", "sha256 must be a 64 hex character digest")
        license = _required_str(record, "license")
        size_bytes = _positive_int(record.get("size_bytes"))
        language = _optional_str(record.get("language")) or "unknown"
        dictionaries.append(
            Dictionary(
                name=name,
                source=source,
                license=license,
                sha256=sha256,
                size_bytes=size_bytes,
                language=language,
                enabled=bool(record.get("enabled", True)),
            )
        )
    return WordlistInventory(version=WORDLIST_INVENTORY_VERSION, dictionaries=tuple(dictionaries))


def hash_matches(dictionary: Dictionary, expected_sha256: str) -> bool:
    """Detect a changed wordlist via its immutable sha256."""
    return dictionary.sha256 == expected_sha256.lower()


def validate_rule(rule: str) -> str | None:
    """Validate a hashcat rule token; arbitrary shell syntax is rejected."""
    if not rule:
        return "rule is empty"
    if any(char in SHELL_METACHARS for char in rule):
        return "rule contains shell metacharacters"
    if any(prefix in rule for prefix in RULE_SUBSTITUTION_PREFIXES):
        return "rule contains shell command substitution"
    if not re.match(r"^[A-Za-z0-9:_$\-+*?^!%#.@{}]+$", rule):
        return "rule contains unsupported characters"
    return None


def validate_mask(mask: str) -> str | None:
    """Validate a hashcat mask; custom charsets must be defined and bounded."""
    if not mask:
        return "mask is empty"
    if any(char in SHELL_METACHARS for char in mask):
        return "mask contains shell metacharacters"
    position = 0
    defined_custom = set()
    while position < len(mask):
        char = mask[position]
        if char == "?":
            if position + 1 >= len(mask):
                return "mask ends with an incomplete charset token"
            token = mask[position : position + 2]
            if token in MASK_CHARSETS:
                position += 2
                continue
            if CUSTOM_MASK.match(token):
                defined_custom.add(token)
                position += 2
                continue
            return f"mask contains unknown charset token {token!r}"
        if char == "[":
            match = CUSTOM_RANGE.match(mask, position)
            if match is None:
                return "mask contains an invalid custom range"
            position = match.end()
            continue
        if char == "\\" or char == "{":
            position += 1
            continue
        return f"mask contains unsupported literal {char!r}"
    return None


def estimate_mask_space(mask: str) -> int:
    """Estimated search space as the product of per-position charset sizes."""
    error = validate_mask(mask)
    if error is not None:
        raise WordlistInventoryError("invalid_mask", error)
    total = 1
    position = 0
    while position < len(mask):
        char = mask[position]
        if char == "?":
            token = mask[position : position + 2]
            total *= MASK_CHARSETS.get(token, 95)
            position += 2
        elif char == "[":
            match = CUSTOM_RANGE.match(mask, position)
            if match is None:
                raise WordlistInventoryError(
                    "invalid_mask", "mask contains an invalid custom range"
                )
            total *= len(match.group(0)[1:-1])
            position = match.end()
        else:
            position += 1
    return total


def ordered_strategies(
    strategy_names: Sequence[str], inventory: WordlistInventory
) -> tuple[str, ...]:
    """Ordered, deduplicated strategies restricted to enabled dictionaries."""
    ordered: list[str] = []
    seen: set[str] = set()
    for name in strategy_names:
        dictionary = inventory.by_name(name)
        if dictionary is None:
            raise WordlistInventoryError("unknown_dictionary", f"dictionary {name!r} is unknown")
        if not dictionary.enabled:
            raise WordlistInventoryError("disabled_dictionary", f"dictionary {name!r} is disabled")
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)
    return tuple(ordered)


def set_enabled(inventory: WordlistInventory, name: str, enabled: bool) -> WordlistInventory:
    """Return a new inventory with a dictionary's enablement toggled."""
    updated = tuple(
        Dictionary(
            name=dictionary.name,
            source=dictionary.source,
            license=dictionary.license,
            sha256=dictionary.sha256,
            size_bytes=dictionary.size_bytes,
            language=dictionary.language,
            enabled=enabled if dictionary.name == name else dictionary.enabled,
        )
        for dictionary in inventory.dictionaries
    )
    return WordlistInventory(version=inventory.version, dictionaries=updated)


def import_allowed(*, size_bytes: int, explicit_admin_action: bool) -> tuple[bool, str | None]:
    """Import limits: no downloads without explicit admin action; size bounded."""
    if not explicit_admin_action:
        return False, "a wordlist download requires an explicit admin action"
    if size_bytes > MAX_IMPORT_BYTES:
        return False, "wordlist import exceeds the maximum allowed size"
    return True, None


def inventory_summary(inventory: WordlistInventory) -> dict[str, Any]:
    """Non-secret inventory summary for reporting and UI."""
    return {
        "version": WORDLIST_INVENTORY_VERSION,
        "count": len(inventory.dictionaries),
        "enabled": list(inventory.enabled_names()),
        "total_bytes": sum(dictionary.size_bytes for dictionary in inventory.dictionaries),
        "languages": sorted({dictionary.language for dictionary in inventory.dictionaries}),
    }


def _required_str(record: Mapping[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise WordlistInventoryError("missing_field", f"record requires field {key!r}")
    return value


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _positive_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise WordlistInventoryError("invalid_size", "size must be a positive integer")
    return int(value)
