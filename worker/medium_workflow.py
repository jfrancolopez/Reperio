"""Removable-media selection and batch workflow (RPR-187).

One-at-a-time "finish this medium, insert the next" workflow for disk, flash,
card, optical, and floppy/legacy sources. Replacing media never resumes or
starts automatically, completed prior cases stay browsable/exportable while the
next medium scans, and empty or unsupported readers get an explanation. This
module offers no erase, format, initialize, burn, blank, repair, or
source-delete control; the destructive-control guard is enforced in code and
tests.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from worker.device_wizard import SourceCard

MEDIUM_WORKFLOW_VERSION = "medium-workflow-v1"

DESTRUCTIVE_LABELS = frozenset(
    {"erase", "format", "initialize", "burn", "blank", "repair", "wipe", "delete"}
)


class MediumWorkflowError(ValueError):
    """Raised when a workflow input is invalid or a destructive control is attempted."""


@dataclass(frozen=True)
class InsertionState:
    state: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScratchEstimate:
    needed_bytes: int
    available_bytes: int
    sufficient: bool
    reason: str | None = None


@dataclass(frozen=True)
class BatchStep:
    order: int
    source_id: str
    reader_id: str
    medium_present: bool
    medium_identity_proven: bool
    status: str
    can_finish: bool
    can_insert_next: bool


def insertion_state(card: SourceCard) -> InsertionState:
    """Describe the current insertion/removal state of a reader."""
    if not card.medium_present:
        return InsertionState("empty", ("no_medium_present",))
    if not card.medium_identity_proven:
        return InsertionState("unsupported", ("medium_identity_unproven",))
    return InsertionState("present")


def unsupported_medium_explanation(card: SourceCard) -> str:
    """Human explanation for empty or unsupported readers."""
    if not card.medium_present:
        return "Insert a supported medium into this reader to continue."
    if card.medium_present and not card.medium_identity_proven:
        return "A medium is present but its identity could not be proven; replace it and try again."
    return "This medium is supported and ready for scanning."


def scratch_estimate(
    card: SourceCard,
    *,
    available_bytes: int,
    multiplier: float = 1.5,
) -> ScratchEstimate:
    """Capacity-aware scratch estimate; reports insufficiency clearly."""
    if multiplier <= 0:
        raise MediumWorkflowError("invalid_multiplier", "scratch multiplier must be positive")
    capacity = card.capacity_bytes or 0
    needed = max(1, int(capacity * multiplier))
    if capacity and available_bytes < needed:
        return ScratchEstimate(
            needed_bytes=needed,
            available_bytes=available_bytes,
            sufficient=False,
            reason="insufficient_scratch",
        )
    return ScratchEstimate(
        needed_bytes=needed,
        available_bytes=available_bytes,
        sufficient=True,
    )


def plan_batch(
    cards: Sequence[SourceCard],
    *,
    completed_source_ids: Sequence[str] = (),
) -> tuple[tuple[BatchStep, ...], tuple[str, ...]]:
    """One-at-a-time batch plan; never resumes or auto-starts a replacement.

    Exactly one active medium can scan at a time. Replacing a medium in the same
    reader moves it to the end of the queue and requires the operator to finish
    the current medium first.
    """
    completed = set(completed_source_ids)
    steps: list[BatchStep] = []
    warnings: list[str] = []
    seen_readers: dict[str, str] = {}
    for index, card in enumerate(cards):
        if card.source_id in completed:
            status = "completed"
        else:
            status = "ready" if (index == 0 and card.medium_identity_proven) else "queued"
        previous_reader = seen_readers.get(card.reader_id)
        if previous_reader and previous_reader != card.source_id:
            warnings.append(f"same_reader_replaced:{card.reader_id}")
            if status != "completed":
                status = "queued"
        seen_readers[card.reader_id] = card.source_id
        steps.append(
            BatchStep(
                order=index,
                source_id=card.source_id,
                reader_id=card.reader_id,
                medium_present=card.medium_present,
                medium_identity_proven=card.medium_identity_proven,
                status=status,
                can_finish=status in {"ready", "completed"},
                can_insert_next=(index < len(cards) - 1 and status == "completed"),
            )
        )
    return tuple(steps), tuple(dict.fromkeys(warnings))


def assert_no_destructive_controls(controls: Sequence[str]) -> None:
    """Guard: reject any control carrying a destructive source label."""
    for control in controls:
        label = control.strip().lower()
        if label in DESTRUCTIVE_LABELS:
            raise MediumWorkflowError(
                "destructive_control_forbidden",
                f"destructive control {control!r} must not exist",
            )


def workflow_snapshot(
    cards: Sequence[SourceCard],
    *,
    completed_source_ids: Sequence[str] = (),
    scratch_available_bytes: int = 0,
    controls: Sequence[str] = (),
    prior_cases_available: bool = True,
) -> dict[str, Any]:
    """Deterministic batch workflow snapshot for the UI."""
    assert_no_destructive_controls(controls)
    steps, warnings = plan_batch(cards, completed_source_ids=completed_source_ids)
    active_step = next((step for step in steps if step.status == "ready"), None)
    active_card = next(
        (
            card
            for card in cards
            if active_step is not None and card.source_id == active_step.source_id
        ),
        None,
    )
    scratch = (
        scratch_estimate(active_card, available_bytes=scratch_available_bytes)
        if active_card is not None
        else None
    )
    return {
        "workflow_version": MEDIUM_WORKFLOW_VERSION,
        "steps": [
            {
                "order": step.order,
                "source_id": step.source_id,
                "reader_id": step.reader_id,
                "medium_present": step.medium_present,
                "medium_identity_proven": step.medium_identity_proven,
                "status": step.status,
                "can_finish": step.can_finish,
                "can_insert_next": step.can_insert_next,
            }
            for step in steps
        ],
        "active_source_id": active_step.source_id if active_step is not None else None,
        "scratch": {
            "needed_bytes": scratch.needed_bytes if scratch else 0,
            "available_bytes": scratch.available_bytes if scratch else 0,
            "sufficient": scratch.sufficient if scratch else True,
            "reason": scratch.reason if scratch else None,
        }
        if scratch
        else None,
        "warnings": list(warnings),
        "prior_cases_browsable": prior_cases_available,
        "destructive_controls": [],
    }
