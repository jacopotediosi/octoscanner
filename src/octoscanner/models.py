from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from packaging.version import Version


class RuleType(Enum):
    DEPRECATION = "deprecation"
    REMOVAL = "removal"
    SECURITY = "security"
    PACKAGING = "packaging"


@dataclass(frozen=True)
class Rule:
    id: str
    type: RuleType
    message: str
    severity: str
    suggestion: str | None = None
    since: Version | None = None


@dataclass
class Finding:
    rule: Rule
    file_path: str  # relative to plugin root
    line_number: int
    end_line_number: int | None = None
    code_snippet: str = ""


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def removed(self) -> list[Finding]:
        return [f for f in self.findings if f.rule.type == RuleType.REMOVAL]

    @property
    def deprecated(self) -> list[Finding]:
        return [f for f in self.findings if f.rule.type == RuleType.DEPRECATION]

    @property
    def security(self) -> list[Finding]:
        return [f for f in self.findings if f.rule.type == RuleType.SECURITY]

    @property
    def packaging(self) -> list[Finding]:
        return [f for f in self.findings if f.rule.type == RuleType.PACKAGING]

    @property
    def has_issues(self) -> bool:
        return len(self.findings) > 0
