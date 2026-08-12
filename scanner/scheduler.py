"""Deterministic deep-scan stage scheduler."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

PRODUCT_SCAN_MODE = "deep-scan-v1"

STAGE_VALIDATION = "validation"
STAGE_VOLUMES = "volumes"
STAGE_ENUMERATION = "enumeration"
STAGE_ARTIFACTS = "artifacts"
STAGE_ENRICHMENT = "enrichment"
STAGE_CARVING = "carving"
STAGE_FINALIZATION = "finalization"

STAGE_PENDING = "pending"
STAGE_RUNNING = "running"
STAGE_PAUSED = "paused"
STAGE_COMPLETED = "completed"
STAGE_FAILED = "failed"
STAGE_SKIPPED = "skipped"


@dataclass(frozen=True)
class StageDefinition:
    name: str
    dependencies: frozenset[str]
    io_cost: int
    mandatory: bool = True


@dataclass(frozen=True)
class SchedulerConfig:
    max_io_cost: int = 1
    enable_enrichment: bool = True
    enable_carving: bool = True


@dataclass(frozen=True)
class StagePlan:
    scan_mode: str
    runnable: tuple[str, ...]
    blocked: tuple[str, ...]


class SchedulerError(ValueError):
    """Raised when a scan stage graph is invalid or unsafe."""


STAGES = {
    STAGE_VALIDATION: StageDefinition(STAGE_VALIDATION, frozenset(), 1, True),
    STAGE_VOLUMES: StageDefinition(STAGE_VOLUMES, frozenset({STAGE_VALIDATION}), 1, True),
    STAGE_ENUMERATION: StageDefinition(STAGE_ENUMERATION, frozenset({STAGE_VOLUMES}), 1, True),
    STAGE_ARTIFACTS: StageDefinition(STAGE_ARTIFACTS, frozenset({STAGE_ENUMERATION}), 1, False),
    STAGE_ENRICHMENT: StageDefinition(STAGE_ENRICHMENT, frozenset({STAGE_ARTIFACTS}), 1, False),
    STAGE_CARVING: StageDefinition(
        STAGE_CARVING,
        frozenset({STAGE_VALIDATION, STAGE_VOLUMES, STAGE_ENUMERATION}),
        1,
        False,
    ),
    STAGE_FINALIZATION: StageDefinition(
        STAGE_FINALIZATION,
        frozenset({STAGE_ENUMERATION, STAGE_ARTIFACTS, STAGE_ENRICHMENT, STAGE_CARVING}),
        1,
        True,
    ),
}


def stage_order() -> tuple[str, ...]:
    """Return a stable topological stage order for the one product scan mode."""

    remaining = set(STAGES)
    completed: set[str] = set()
    order: list[str] = []
    while remaining:
        ready = sorted(
            stage for stage in remaining if STAGES[stage].dependencies.issubset(completed)
        )
        if not ready:
            raise SchedulerError("stage graph contains a dependency cycle")
        for stage in ready:
            remaining.remove(stage)
            completed.add(stage)
            order.append(stage)
    return tuple(order)


def initial_statuses() -> dict[str, str]:
    return {stage: STAGE_PENDING for stage in STAGES}


def runnable_stages(
    statuses: Mapping[str, str], config: SchedulerConfig = SchedulerConfig()
) -> StagePlan:
    """Select runnable stages under dependency and conservative I/O limits."""

    _validate_statuses(statuses)
    completed = {
        stage for stage, state in statuses.items() if state in {STAGE_COMPLETED, STAGE_SKIPPED}
    }
    active_io = sum(
        STAGES[stage].io_cost for stage, state in statuses.items() if state == STAGE_RUNNING
    )
    available_io = max(config.max_io_cost - active_io, 0)
    runnable: list[str] = []
    blocked: list[str] = []
    for stage in stage_order():
        if statuses[stage] != STAGE_PENDING:
            continue
        if not _enabled(stage, config):
            continue
        if not _dependencies_satisfied(stage, completed, statuses, config):
            blocked.append(stage)
            continue
        cost = STAGES[stage].io_cost
        if cost <= available_io:
            runnable.append(stage)
            available_io -= cost
        else:
            blocked.append(stage)
    return StagePlan(PRODUCT_SCAN_MODE, tuple(runnable), tuple(blocked))


def pause_all(statuses: Mapping[str, str]) -> dict[str, str]:
    """Propagate an operator pause to running and pending stages."""

    _validate_statuses(statuses)
    return {
        stage: STAGE_PAUSED if state in {STAGE_PENDING, STAGE_RUNNING} else state
        for stage, state in statuses.items()
    }


def apply_stage_failure(
    statuses: Mapping[str, str], failed_stage: str
) -> tuple[dict[str, str], bool]:
    """Mark a failed stage and propagate mandatory dependency consequences."""

    _validate_statuses(statuses)
    if failed_stage not in STAGES:
        raise SchedulerError("unknown stage")
    updated = dict(statuses)
    updated[failed_stage] = STAGE_FAILED
    scan_failed = STAGES[failed_stage].mandatory
    for stage in stage_order():
        if updated[stage] != STAGE_PENDING:
            continue
        if _has_failed_mandatory_dependency(stage, updated):
            updated[stage] = STAGE_FAILED
            scan_failed = True
        elif stage != STAGE_FINALIZATION and _has_failed_optional_dependency(stage, updated):
            updated[stage] = STAGE_SKIPPED
    return updated, scan_failed


def restart_plan(
    completed_stages: set[str], config: SchedulerConfig = SchedulerConfig()
) -> StagePlan:
    """Plan a restart without rerunning already completed stages."""

    statuses = initial_statuses()
    for stage in completed_stages:
        if stage not in STAGES:
            raise SchedulerError("unknown completed stage")
        statuses[stage] = STAGE_COMPLETED
    return runnable_stages(statuses, config)


def execution_waves(config: SchedulerConfig = SchedulerConfig()) -> tuple[tuple[str, ...], ...]:
    """Return deterministic waves for graph-order tests and scheduler introspection."""

    statuses = initial_statuses()
    waves: list[tuple[str, ...]] = []
    while True:
        plan = runnable_stages(statuses, config)
        if not plan.runnable:
            break
        waves.append(plan.runnable)
        for stage in plan.runnable:
            statuses[stage] = STAGE_COMPLETED
    return tuple(waves)


def _dependencies_satisfied(
    stage: str, completed: set[str], statuses: Mapping[str, str], config: SchedulerConfig
) -> bool:
    dependencies = STAGES[stage].dependencies
    if stage == STAGE_FINALIZATION:
        optional_ready = all(
            dependency in completed
            or statuses[dependency] in {STAGE_FAILED, STAGE_SKIPPED}
            or not _enabled(dependency, config)
            for dependency in dependencies
            if not STAGES[dependency].mandatory
        )
        mandatory_ready = all(
            dependency in completed for dependency in dependencies if STAGES[dependency].mandatory
        )
        return optional_ready and mandatory_ready
    return dependencies.issubset(completed)


def _has_failed_mandatory_dependency(stage: str, statuses: Mapping[str, str]) -> bool:
    return any(
        statuses[dependency] == STAGE_FAILED and STAGES[dependency].mandatory
        for dependency in STAGES[stage].dependencies
    )


def _has_failed_optional_dependency(stage: str, statuses: Mapping[str, str]) -> bool:
    return any(
        statuses[dependency] == STAGE_FAILED and not STAGES[dependency].mandatory
        for dependency in STAGES[stage].dependencies
    )


def _enabled(stage: str, config: SchedulerConfig) -> bool:
    return not (
        (stage == STAGE_ENRICHMENT and not config.enable_enrichment)
        or (stage == STAGE_CARVING and not config.enable_carving)
    )


def _validate_statuses(statuses: Mapping[str, str]) -> None:
    if set(statuses) != set(STAGES):
        raise SchedulerError("statuses must contain exactly the known stages")
    allowed = {
        STAGE_PENDING,
        STAGE_RUNNING,
        STAGE_PAUSED,
        STAGE_COMPLETED,
        STAGE_FAILED,
        STAGE_SKIPPED,
    }
    if any(state not in allowed for state in statuses.values()):
        raise SchedulerError("unknown stage status")
