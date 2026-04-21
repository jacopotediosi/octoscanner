"""Generate Semgrep rules by analyzing OctoPrint source code."""

from .pipeline import generate

__all__ = ["generate"]
