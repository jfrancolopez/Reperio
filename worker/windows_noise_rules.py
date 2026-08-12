"""Versioned Windows noise rules with reversible visibility decisions."""

from __future__ import annotations

from dataclasses import dataclass

from worker.content_signature import SignatureResult
from worker.windows_profiles import WindowsUserProfile

RULESET_VERSION = "windows-noise-v1"
PERSONAL_MIME_PREFIXES = ("image/", "application/pdf")


@dataclass(frozen=True)
class NoiseRule:
    rule_id: str
    path_contains: tuple[str, ...]
    reason: str
    visibility: str = "lower"


@dataclass(frozen=True)
class NoiseDecision:
    ruleset_version: str
    visibility: str
    rule_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    evidence: tuple[str, ...]
    override_allowed: bool = True


RULES = (
    NoiseRule(
        "win-os-components", ("windows/system32", "windows/syswow64"), "Windows OS component path"
    ),
    NoiseRule("win-winsxs", ("windows/winsxs",), "Windows component store"),
    NoiseRule("win-drivers", ("windows/system32/drivers",), "Windows driver store"),
    NoiseRule("win-fonts", ("windows/fonts",), "Windows font asset"),
    NoiseRule(
        "win-icons-wallpapers", ("windows/web/wallpaper", "windows/cursors"), "Windows visual asset"
    ),
    NoiseRule(
        "win-update-cache", ("windows/softwaredistribution/download",), "Windows update cache"
    ),
    NoiseRule(
        "browser-cache", ("appdata/local/google/chrome/user data/default/cache",), "Browser cache"
    ),
    NoiseRule("temp-files", ("appdata/local/temp", "/temp/"), "Temporary file path"),
    NoiseRule(
        "package-store",
        ("appdata/local/packages", "program files/windowsapps"),
        "Application package store",
    ),
)


def evaluate_windows_noise(
    *,
    display_path: str,
    signature: SignatureResult,
    profile: WindowsUserProfile | None = None,
) -> NoiseDecision:
    """Evaluate reversible Windows noise rules against deterministic evidence."""

    lowered = display_path.replace("\\", "/").lower()
    matched: list[NoiseRule] = []
    for rule in RULES:
        if any(fragment in lowered for fragment in rule.path_contains):
            matched.append(rule)
    evidence: list[str] = []
    if profile is not None:
        evidence.append(f"profile:{profile.profile_id}")
    if _personal_content(signature):
        evidence.append("personal_content_signature")
    if not matched:
        return NoiseDecision(RULESET_VERSION, "normal", (), (), tuple(evidence))
    if _personal_content(signature):
        return NoiseDecision(
            RULESET_VERSION,
            "review",
            tuple(rule.rule_id for rule in matched),
            tuple(rule.reason for rule in matched),
            tuple((*evidence, "noise_rule_conflict")),
        )
    return NoiseDecision(
        RULESET_VERSION,
        "lower",
        tuple(rule.rule_id for rule in matched),
        tuple(rule.reason for rule in matched),
        tuple(evidence),
    )


def _personal_content(signature: SignatureResult) -> bool:
    return signature.mime_type.startswith(PERSONAL_MIME_PREFIXES) or signature.signature in {"docx"}
