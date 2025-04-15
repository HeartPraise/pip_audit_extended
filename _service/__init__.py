"""
Vulnerability service interfaces and implementations for `pip-audit`.
"""

from .interface import (
    ConnectionError,
    Dependency,
    ResolvedDependency,
    ServiceError,
    SkippedDependency,
    VulnerabilityResult,
    Vulnerability,
    VulnerabilityService,
)

from .osv import OsvService
from .pypi import PyPIService
from .nvd import NvdService
from .pyup import PyUpService
from .github import GitHubAdvisoryService

__all__ = [
    "ConnectionError",
    "Dependency",
    "ResolvedDependency",
    "ServiceError",
    "SkippedDependency",
    "VulnerabilityResult",
    "Vulnerability",
    "VulnerabilityService",
    "NvdService"
    "OsvService",
    "PyPIService",
    "GitHubAdvisoryService",
]
