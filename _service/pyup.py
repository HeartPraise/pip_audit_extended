"""
Functionality for using the [PyUp](https://pyup.io/) API as a `VulnerabilityService`.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, cast, List, Tuple

import requests
from packaging.version import Version

from pip_audit._cache import caching_session
from pip_audit._service.interface import (
    ConnectionError,
    Dependency,
    ResolvedDependency,
    ServiceError,
    VulnerabilityResult,
    VulnerabilityService
)

logger = logging.getLogger(__name__)


class PyUpService(VulnerabilityService):
    """
    An implementation of `VulnerabilityService` that uses PyUp to provide Python
    package vulnerability information.
    """

    PYUP_API_URL = "https://pyup.io/api/v1/safety"  # Make sure this is the correct endpoint
    PYUP_API_KEY = os.environ.get("PYUP_API_KEY")

    def __init__(self, cache_dir: Path | None = None, timeout: int | None = None):
        """
        Create a new `PyUpService`.

        `cache_dir` is an optional cache directory to use, for caching and reusing PyUp API
        requests. If `None`, `pip-audit` will use its own internal caching directory.

        `timeout` is an optional argument to control how many seconds the component should wait for
        responses to network requests.
        """
        if not self.PYUP_API_KEY:
            raise ServiceError("PyUp API key is required for PyUpService")
        
        self.session = caching_session(cache_dir, use_pip=False)
        self.timeout = timeout

    def query(self, spec: Dependency) -> Tuple[Dependency, List[VulnerabilityResult]]:
        """
        Queries PyUp for the given `Dependency` specification.

        See `VulnerabilityService.query`.
        """
        if spec.is_skipped():
            return spec, []
        spec = cast(ResolvedDependency, spec)

        query = {
            "name": spec.canonical_name,
            "version": str(spec.version),
        }
        
        headers = {
            "Authorization": f"Token {self.PYUP_API_KEY}"
        }

        try:
            response: requests.Response = self.session.post(
                url=self.PYUP_API_URL,
                json=query,
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.ConnectTimeout:
            raise ConnectionError("Could not connect to PyUp's vulnerability feed")
        except requests.HTTPError as http_error:
            status_code = http_error.response.status_code
            error_message = http_error.response.text
            logger.error(f"HTTP Error {status_code}: {error_message}")
            raise ServiceError(f"HTTP Error {status_code}: {error_message}") from http_error

        # If the response is empty, that means that the package/version pair doesn't have any
        # associated vulnerabilities
        #
        # In that case, return an empty list
        results: List[VulnerabilityResult] = []
        response_json = response.json()
        
        # Log the response for debugging
        logger.debug(f"Response from PyUp: {response_json}")

        if not response_json.get("vulnerabilities"):
            return spec, results

        for vuln in response_json["vulnerabilities"]:
            id = vuln.get("vuln_id", "N/A")
            description = vuln.get("description", "N/A")
            published = vuln.get("published", None)
            severity = vuln.get("severity", "unknown").capitalize()

            # PyUp provides fix versions in the response
            fix_versions: List[Version] = []
            if vuln.get("fixed_versions"):
                fix_versions = [Version(ver) for ver in vuln["fixed_versions"]]

            results.append(
                VulnerabilityResult(
                    id=id,
                    description=description,
                    fix_versions=fix_versions,
                    aliases=set(vuln.get("aliases", [])),
                    published=published,
                )
            )

        return spec, results
