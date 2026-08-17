"""Local deterministic language detection for extracted and OCR text."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

PARSER_VERSION = "language-detection-v1"
MIN_ALPHA_CHARS = 20
MIN_TOKEN_COUNT = 4
MIN_CONFIDENCE = 0.35
MIXED_SECONDARY_RATIO = 0.55
TOKEN_RE = re.compile(r"[A-Za-zÀ-ÖØ-öø-ÿ']+")

LANGUAGE_MARKERS = {
    "en": frozenset(
        "the and this that with from have are was were hello world recovery document scanned image language confidence".split()
    ),
    "es": frozenset(
        "el la los las que de para con una este esta hola mundo recuperación documento escaneado imagen idioma confianza".split()
    ),
    "fr": frozenset(
        "le la les des que pour avec une bonjour monde récupération document numérisé image langue confiance".split()
    ),
    "de": frozenset(
        "der die das und mit für ist sind hallo welt wiederherstellung dokument gescannt bild sprache vertrauen".split()
    ),
    "pt": frozenset(
        "o a os as que para com uma olá mundo recuperação documento digitalizado imagem idioma confiança".split()
    ),
}


@dataclass(frozen=True)
class LanguageScore:
    language: str
    confidence: float
    matched_terms: tuple[str, ...]


@dataclass(frozen=True)
class LanguageDetectionResult:
    status: str
    primary_language: str
    confidence: float
    scores: tuple[LanguageScore, ...]
    sample_size: int
    warnings: tuple[str, ...]
    parser_version: str = PARSER_VERSION


def detect_text_language(
    text: str, *, min_alpha_chars: int = MIN_ALPHA_CHARS
) -> LanguageDetectionResult:
    if min_alpha_chars <= 0:
        raise ValueError("minimum sample size must be positive")
    sample = text[:20_000]
    tokens = tuple(_tokens(sample))
    alpha_chars = sum(1 for char in sample if char.isalpha())
    warnings: list[str] = []
    if _mostly_numeric_or_noise(sample, alpha_chars):
        return _unknown(alpha_chars, ("low_language_signal",))
    if alpha_chars < min_alpha_chars or len(tokens) < MIN_TOKEN_COUNT:
        return _unknown(alpha_chars, ("short_text",))

    token_counts = Counter(tokens)
    scores = tuple(
        _score(language, markers, token_counts, len(tokens))
        for language, markers in LANGUAGE_MARKERS.items()
    )
    ordered = tuple(sorted(scores, key=lambda item: (-item.confidence, item.language)))
    best = ordered[0]
    if best.confidence < MIN_CONFIDENCE:
        return _unknown(alpha_chars, ("low_confidence_language",))
    primary = best.language
    if len(ordered) > 1 and ordered[1].confidence >= best.confidence * MIXED_SECONDARY_RATIO:
        primary = "mixed"
        warnings.append(f"mixed_language:{best.language}+{ordered[1].language}")
    if "ocr" in sample.lower() or "confidence" in sample.lower():
        warnings.append("ocr_noise_tolerated")
    return LanguageDetectionResult(
        status="complete",
        primary_language=primary,
        confidence=round(best.confidence, 2),
        scores=ordered,
        sample_size=alpha_chars,
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _score(
    language: str, markers: frozenset[str], token_counts: Counter[str], token_count: int
) -> LanguageScore:
    matched: list[str] = []
    hits = 0
    for marker in sorted(markers):
        count = token_counts.get(marker, 0)
        if count:
            matched.append(marker)
            hits += count
    accent_bonus = _accent_bonus(language, token_counts)
    confidence = min(1.0, (hits + accent_bonus) / max(4, min(token_count, 20)))
    return LanguageScore(language, round(confidence, 2), tuple(matched[:12]))


def _accent_bonus(language: str, token_counts: Counter[str]) -> float:
    text = " ".join(token_counts)
    if language == "es" and any(char in text for char in "áéíóúñ"):
        return 1.0
    if language == "fr" and any(char in text for char in "àâçéèêëîïôûùüÿœ"):
        return 1.0
    if language == "de" and any(char in text for char in "äöüß"):
        return 1.0
    if language == "pt" and any(char in text for char in "ãõçáâêíóôú"):
        return 1.0
    return 0.0


def _tokens(text: str) -> tuple[str, ...]:
    return tuple(
        match.group(0).lower().strip("'")
        for match in TOKEN_RE.finditer(text)
        if len(match.group(0).strip("'")) > 1
    )


def _mostly_numeric_or_noise(sample: str, alpha_chars: int) -> bool:
    visible = sum(1 for char in sample if not char.isspace())
    if visible == 0:
        return True
    digits = sum(1 for char in sample if char.isdigit())
    punctuation = sum(1 for char in sample if not char.isalnum() and not char.isspace())
    return digits > alpha_chars or punctuation > alpha_chars * 2


def _unknown(sample_size: int, warnings: tuple[str, ...]) -> LanguageDetectionResult:
    return LanguageDetectionResult("unknown", "unknown", 0.0, (), sample_size, warnings)
