"""Base classes for pipeline analyzers."""

from __future__ import annotations

import abc
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import PipelineState


class Analyzer(abc.ABC):
    """Abstract base class for a pipeline analyzer.

    Attributes:
        title (str): Human-readable analyzer title.
    """

    title: str

    @abc.abstractmethod
    def run(self, state: PipelineState, source_dirs: dict[str, Path]) -> list[str]:
        """Run the analyzer and populate the pipeline state.

        Args:
            state (PipelineState): Shared pipeline state to populate.
            source_dirs (dict[str, Path]): Version -> source directory mapping.

        Returns:
            list[str]: Log lines describing what the analyzer did.
        """
        ...
