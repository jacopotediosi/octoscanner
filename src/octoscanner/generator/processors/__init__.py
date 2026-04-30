"""Processors for generating Semgrep rules from analysis results.

Processors run after analyzers in the generator pipeline, transforming
analysis data (e.g., class hierarchy, deprecation markers) into Semgrep
rule definitions.
"""

from .base import Processor
from .python_deprecation import PythonDeprecationProcessor
from .python_normalization import PythonNormalizationProcessor
from .python_removal import PythonRemovalProcessor
from .python_settings import PythonSettingsRemovalProcessor
from .python_signature_change import PythonSignatureChangeProcessor

PROCESSORS: list[Processor] = [
    PythonDeprecationProcessor(),
    PythonRemovalProcessor(),
    PythonSignatureChangeProcessor(),
    PythonSettingsRemovalProcessor(),
    PythonNormalizationProcessor(),
]
"""Ordered list of pipeline processors, executed sequentially."""

__all__ = ["PROCESSORS"]
