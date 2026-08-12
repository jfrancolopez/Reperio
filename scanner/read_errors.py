"""Bounded scanner read-error handling for damaged source ranges."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from scanner import messages


class ReadErrorHandlingError(ValueError):
    """Raised when a read policy is invalid."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ReadTimeoutError(OSError):
    """Normalized timeout from a source read operation."""


@dataclass(frozen=True)
class ReadErrorRange:
    offset_bytes: int
    length_bytes: int
    code: str
    attempts: int


@dataclass(frozen=True)
class ReadCounters:
    attempted_reads: int = 0
    successful_reads: int = 0
    retry_reads: int = 0
    failed_reads: int = 0
    skipped_bytes: int = 0
    recovered_after_retry: int = 0
    short_reads: int = 0
    timeouts: int = 0

    def as_payload(self) -> dict[str, int]:
        return {
            "attempted_reads": self.attempted_reads,
            "successful_reads": self.successful_reads,
            "retry_reads": self.retry_reads,
            "failed_reads": self.failed_reads,
            "skipped_bytes": self.skipped_bytes,
            "recovered_after_retry": self.recovered_after_retry,
            "short_reads": self.short_reads,
            "timeouts": self.timeouts,
        }


@dataclass(frozen=True)
class ReadPolicy:
    max_attempts: int = 3
    base_backoff_ms: int = 10
    max_error_ranges: int = 128
    pause_after_errors: int = 16
    pause_temperature_celsius: int | None = None

    def __post_init__(self) -> None:
        if self.max_attempts <= 0:
            raise ReadErrorHandlingError("invalid_policy", "max attempts must be positive")
        if self.base_backoff_ms < 0:
            raise ReadErrorHandlingError("invalid_policy", "backoff must not be negative")
        if self.max_error_ranges <= 0 or self.pause_after_errors <= 0:
            raise ReadErrorHandlingError("invalid_policy", "thresholds must be positive")


@dataclass(frozen=True)
class ReadOutcome:
    data: bytes
    gap: ReadErrorRange | None
    counters: ReadCounters
    warnings: tuple[Mapping[str, object], ...]
    pause_reason: str | None = None


class RawReader(Protocol):
    def read_at(self, offset_bytes: int, length_bytes: int) -> bytes: ...


class ResilientReader:
    """Read wrapper with finite retries, gap recording, and pause thresholds."""

    def __init__(
        self,
        reader: RawReader,
        *,
        policy: ReadPolicy | None = None,
        sleep: Callable[[float], None] | None = None,
        temperature: Callable[[], int | None] | None = None,
    ) -> None:
        self.reader = reader
        self.policy = policy or ReadPolicy()
        self.sleep = sleep or (lambda seconds: None)
        self.temperature = temperature or (lambda: None)
        self.counters = ReadCounters()
        self.error_ranges: list[ReadErrorRange] = []

    def read_at(self, offset_bytes: int, length_bytes: int) -> bytes:
        outcome = self.read_or_gap(offset_bytes, length_bytes)
        if outcome.gap is not None:
            return bytes(length_bytes)
        return outcome.data

    def read_or_gap(self, offset_bytes: int, length_bytes: int) -> ReadOutcome:
        if offset_bytes < 0 or length_bytes < 0:
            raise ReadErrorHandlingError("invalid_range", "read range must not be negative")
        last_code = "read_error"
        for attempt in range(1, self.policy.max_attempts + 1):
            self.counters = _replace_counter(
                self.counters, attempted_reads=self.counters.attempted_reads + 1
            )
            try:
                data = self.reader.read_at(offset_bytes, length_bytes)
            except ReadTimeoutError:
                last_code = "timeout"
                self.counters = _replace_counter(self.counters, timeouts=self.counters.timeouts + 1)
            except OSError:
                last_code = "eio"
            else:
                if len(data) == length_bytes:
                    self.counters = _replace_counter(
                        self.counters,
                        successful_reads=self.counters.successful_reads + 1,
                        recovered_after_retry=self.counters.recovered_after_retry
                        + (1 if attempt > 1 else 0),
                    )
                    return ReadOutcome(
                        data, None, self.counters, self.warnings(), self._pause_reason()
                    )
                last_code = "short_read"
                self.counters = _replace_counter(
                    self.counters, short_reads=self.counters.short_reads + 1
                )
            if attempt < self.policy.max_attempts:
                self.counters = _replace_counter(
                    self.counters, retry_reads=self.counters.retry_reads + 1
                )
                self.sleep(self._backoff_seconds(attempt))

        gap = ReadErrorRange(offset_bytes, length_bytes, last_code, self.policy.max_attempts)
        self.error_ranges.append(gap)
        self.counters = _replace_counter(
            self.counters,
            failed_reads=self.counters.failed_reads + 1,
            skipped_bytes=self.counters.skipped_bytes + length_bytes,
        )
        pause_reason = self._pause_reason()
        return ReadOutcome(bytes(length_bytes), gap, self.counters, self.warnings(), pause_reason)

    def warning_messages(self, *, stage: str, sequence_start: int = 0) -> tuple[bytes, ...]:
        encoded: list[bytes] = []
        for sequence, warning in enumerate(self.warnings(), start=sequence_start):
            encoded.append(
                messages.encode_message(
                    "warning",
                    sequence,
                    {
                        "stage": stage,
                        "code": str(warning["code"]),
                        "message": str(warning["message"]),
                    },
                )
            )
        return tuple(encoded)

    def warnings(self) -> tuple[Mapping[str, object], ...]:
        warnings: list[Mapping[str, object]] = []
        for error in self.error_ranges:
            warnings.append(
                {
                    "code": "read_gap",
                    "message": f"skipped unreadable range at {error.offset_bytes} length {error.length_bytes}",
                    "offset_bytes": error.offset_bytes,
                    "length_bytes": error.length_bytes,
                    "read_error_code": error.code,
                }
            )
        pause_reason = self._pause_reason()
        if pause_reason is not None:
            warnings.append({"code": "read_pause_recommended", "message": pause_reason})
        return tuple(warnings)

    def _pause_reason(self) -> str | None:
        if len(self.error_ranges) >= self.policy.pause_after_errors:
            return "read error threshold reached"
        if len(self.error_ranges) >= self.policy.max_error_ranges:
            return "maximum read error ranges reached"
        temperature = self.temperature()
        if (
            temperature is not None
            and self.policy.pause_temperature_celsius is not None
            and temperature >= self.policy.pause_temperature_celsius
        ):
            return "source temperature threshold reached"
        return None

    def _backoff_seconds(self, attempt: int) -> float:
        return float(self.policy.base_backoff_ms * (2 ** (attempt - 1))) / 1000


def _replace_counter(counters: ReadCounters, **updates: int) -> ReadCounters:
    values = counters.as_payload()
    values.update(updates)
    return ReadCounters(**values)
