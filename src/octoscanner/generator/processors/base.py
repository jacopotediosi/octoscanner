"""Base classes for pipeline processors."""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import PipelineState


class Processor(abc.ABC):
    """Abstract base class for a pipeline processor.

    Attributes:
        title (str): Human-readable processor title.
    """

    title: str

    @abc.abstractmethod
    def run(self, state: PipelineState) -> list[str]:
        """Run the processor and return log lines.

        Args:
            state (PipelineState): Shared pipeline state.

        Returns:
            list[str]: Log lines describing what the processor did.
        """
        ...


def format_summary(label: str, new_count: int, unchanged_count: int, empty_msg: str) -> str:
    """Format a summary line for rules modified by a processor.

    Formats non-zero counts as ``"N new"``, ``"N unchanged"``
    joined by commas. Returns ``empty_msg`` when both are zero.

    Args:
        label (str): Version label prefix (e.g. ``"1.10.0"`` or ``"1.9.0 -> 1.10.0"``).
        new_count (int): Number of new rules generated.
        unchanged_count (int): Number of rules that already existed.
        empty_msg (str): Message to show when both counts are zero.

    Returns:
        str: Formatted summary line like ``"  1.10.0: 3 new"``.

    Examples:
        >>> format_summary("1.10.0", 3, 0, "no deprecations")
        '  1.10.0: 3 new'
        >>> format_summary("1.9.0 -> 1.10.0", 0, 0, "no removals")
        '  1.9.0 -> 1.10.0: no removals'
        >>> format_summary("1.5.0", 2, 4, "no rules")
        '  1.5.0: 2 new, 4 unchanged'
    """
    parts = []
    if new_count:
        parts.append(f"{new_count} new")
    if unchanged_count:
        parts.append(f"{unchanged_count} unchanged")
    return f"  {label}: {', '.join(parts) if parts else empty_msg}"
