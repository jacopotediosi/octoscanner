"""Analyzers for extracting information from OctoPrint source code.

Analyzers run first in the generator pipeline, producing analysis results
(e.g., class hierarchy) that processors then use to generate Semgrep rules.
"""

from .base import Analyzer
from .python import PythonAnalyzer

ANALYZERS: list[Analyzer] = [
    PythonAnalyzer(),
]
"""Ordered list of pipeline analyzers, executed sequentially."""

__all__ = ["ANALYZERS"]
