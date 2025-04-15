from __future__ import annotations

import json
import logging
import os
import zipfile
from pathlib import Path
from typing import Any, cast

import requests
from packaging.version import Version
from pip_audit._cache import caching_session
from pip_audit._service.interface import (
    ConnectionError,
    Dependency,
    ResolvedDependency,
    ServiceError,
    VulnerabilityResult,
    Vulnerability,
    VulnerabilityService,
)

logger = logging.getLogger(__name__)


class SafetyService(VulnerabilityService):
    """
    An implementation of `VulnerabilityService` that uses the Safety Database (pyup.io)
    to provide Python package vulnerability information.
    """

    SAFETY_API_URL = "https://safety-db.pyup.io/api/v1/"

    def __init__(self, timeout: int | None = None):
        """
        Create a new `SafetyService`.

        `timeout` is an optional argument to control how many seconds the component should wait for
        responses to network requests.
        """
        self.timeout = timeout
        self.session = requests.Session()

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        """
        Queries the Safety database for the given `Dependency` specification.

        See `VulnerabilityService.query`.
        """
        if spec.is_skipped():
            return spec, []
        spec = cast(ResolvedDependency, spec)

        response = self.session.get(
            f"{self.SAFETY_API_URL}vulnerabilities/{spec.canonical_name}",
            timeout=self.timeout,
        )

        if response.status_code != 200:
            logger.error(f"Failed to fetch Safety data for {spec.canonical_name}: {response.status_code}")
            raise ConnectionError("Could not fetch Safety data")

        safety_data = response.json()
        results: list[VulnerabilityResult] = []

        logger.debug(f"Querying Safety for {spec.canonical_name} version {spec.version}")

        for item in safety_data.get("vulnerabilities", []):
            affected_versions = item.get("specifiers", "")

            # Version checking
            if spec.version in affected_versions:
                vulnerability = Vulnerability(
                    id=item.get("id", "Unknown"),
                    description=item.get("description", "No description available"),
                    severity=item.get("severity", "Unknown"),
                )

                results.append(
                    VulnerabilityResult(
                        id=item.get("id", "Unknown"),
                        description=item.get("description", "No description available"),
                        fix_versions=item.get("fixed_versions", []),
                        aliases=set(item.get("aliases", [])),
                        published=item.get("published_at", None),
                    )
                )
                logger.info(f"Found vulnerability {vulnerability.id} for {spec.canonical_name}")

        return spec, results


class GitHubAdvisoryService(VulnerabilityService):
    """
    An implementation of `VulnerabilityService` that uses the GitHub Advisory Database
    to provide Python package vulnerability information.
    """

    GITHUB_API_URL = "https://api.github.com/graphql"

    def __init__(self, token: str, timeout: int | None = None):
        """
        Create a new `GitHubAdvisoryService`.

        `token` is a GitHub personal access token for API authentication.

        `timeout` is an optional argument to control how many seconds the component should wait for
        responses to network requests.
        """
        self.token = token
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        """
        Queries the GitHub Advisory Database for the given `Dependency` specification.

        See `VulnerabilityService.query`.
        """
        if spec.is_skipped():
            return spec, []
        spec = cast(ResolvedDependency, spec)

        query = """
        query($package_name: String!) {
          securityVulnerabilities(ecosystem: PIP, package: $package_name) {
            nodes {
              severity
              advisory {
                identifiers {
                  type
                  value
                }
                description
                publishedAt
              }
              vulnerableVersionRange
            }
          }
        }
        """

        variables = {"package_name": spec.canonical_name}

        response = self.session.post(
            self.GITHUB_API_URL,
            json={"query": query, "variables": variables},
            timeout=self.timeout,
        )

        if response.status_code != 200:
            logger.error(f"Failed to fetch GitHub Advisory data for {spec.canonical_name}: {response.status_code}")
            raise ConnectionError("Could not fetch GitHub Advisory data")

        advisory_data = response.json()
        results: list[VulnerabilityResult] = []

        logger.debug(f"Querying GitHub Advisory for {spec.canonical_name} version {spec.version}")

        vulnerabilities = advisory_data["data"]["securityVulnerabilities"]["nodes"]
        for vuln in vulnerabilities:
            vulnerable_version_range = vuln.get("vulnerableVersionRange", "")
            if spec.version in vulnerable_version_range:
                vulnerability = Vulnerability(
                    id=vuln["advisory"]["identifiers"][0]["value"],
                    description=vuln["advisory"]["description"],
                    severity=vuln["severity"],
                )

                results.append(
                    VulnerabilityResult(
                        id=vulnerability.id,
                        description=vulnerability.description,
                        fix_versions=[],  # Placeholder for actual fix versions
                        aliases=set(),
                        published=vuln["advisory"]["publishedAt"],
                    )
                )
                logger.info(f"Found vulnerability {vulnerability.id} for {spec.canonical_name}")

        return spec, results


class NvdService(VulnerabilityService):
    """
    An implementation of `VulnerabilityService` that uses the National Vulnerability Database (NVD)
    to provide Python package vulnerability information.
    """

    def __init__(self, cache_dir: Path | None = None, timeout: int | None = None):
        """
        Create a new `NvdService`.

        `cache_dir` is an optional cache directory to use for caching and reusing NVD API
        requests. If `None`, `pip-audit` will use its own internal caching directory.

        `timeout` is an optional argument to control how many seconds the component should wait for
        responses to network requests.
        """
        self.cache_dir = cache_dir or Path(".cache")
        self.timeout = timeout
        self.session = caching_session(self.cache_dir, use_pip=False)
        self.nvd_data_path = self.cache_dir / "nvd_data"

    def download_and_extract_nvd_data(self):
        """
        Downloads and extracts the NVD vulnerability data.
        """
        self.nvd_data_path.mkdir(parents=True, exist_ok=True)
        url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
        zip_path = self.nvd_data_path / "nvdcve-1.1-recent.json.zip"
        json_path = self.nvd_data_path / "nvdcve-1.1-recent.json"

        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            with open(zip_path, "wb") as zip_file:
                zip_file.write(response.content)

            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(self.nvd_data_path)

            logger.info(f"NVD data successfully downloaded and extracted to {json_path}")

        except requests.RequestException as e:
            logger.error(f"Failed to download NVD data: {e}")
            raise ConnectionError("Could not download NVD data")

        return json_path

    def load_nvd_data(self, json_path: Path) -> dict[str, Any]:
        """
        Loads the NVD vulnerability data from the extracted JSON file.
        """
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.info(f"NVD data successfully loaded with {len(data.get('CVE_Items', []))} items")
            return data
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load NVD data: {e}")
            raise ServiceError("Invalid NVD data file")

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        """
        Queries the NVD data for the given `Dependency` specification.

        See `VulnerabilityService.query`.
        """
        if spec.is_skipped():
            return spec, []
        spec = cast(ResolvedDependency, spec)

        json_path = self.download_and_extract_nvd_data()
        nvd_data = self.load_nvd_data(json_path)

        results: list[VulnerabilityResult] = []

        logger.debug(f"Querying NVD for {spec.canonical_name} version {spec.version}")

        for item in nvd_data.get("CVE_Items", []):
            cve = item.get("cve", {})
            id = cve.get("CVE_data_meta", {}).get("ID", "Unknown")
            description = cve.get("description", {}).get("description_data", [{}])[0].get("value", "No description available")
            severity = "Unknown"
            impact = item.get("impact", {}).get("baseMetricV3", {})
            if impact:
                severity = impact.get("cvssV3", {}).get("baseSeverity", "Unknown")

            for node in item.get("configurations", {}).get("nodes", []):
                for cpe_match in node.get("cpe_match", []):
                    cpe23_uri = cpe_match.get("cpe23Uri", "")
                    if f"cpe:2.3:a:{spec.canonical_name}" in cpe23_uri:
                        # Check the version range
                        version_start_including = cpe_match.get("versionStartIncluding")
                        version_end_including = cpe_match.get("versionEndIncluding")
                        version_start_excluding = cpe_match.get("versionStartExcluding")
                        version_end_excluding = cpe_match.get("versionEndExcluding")

                        version_check = True

                        if version_start_including and spec.version < Version(version_start_including):
                            logger.debug(f"Skipping {spec.canonical_name} due to version start including {version_start_including}")
                            version_check = False
                        if version_end_including and spec.version > Version(version_end_including):
                            logger.debug(f"Skipping {spec.canonical_name} due to version end including {version_end_including}")
                            version_check = False
                        if version_start_excluding and spec.version <= Version(version_start_excluding):
                            logger.debug(f"Skipping {spec.canonical_name} due to version start excluding {version_start_excluding}")
                            version_check = False
                        if version_end_excluding and spec.version >= Version(version_end_excluding):
                            logger.debug(f"Skipping {spec.canonical_name} due to version end excluding {version_end_excluding}")
                            version_check = False

                        if not version_check:
                            continue

                        # Add detailed information to results
                        vulnerability = Vulnerability(
                            id=id,
                            description=description,
                            severity=severity
                        )

                        results.append(
                            VulnerabilityResult(
                                id=id,
                                description=description,
                                fix_versions=[],  # Placeholder, update if fix versions are available
                                aliases=set(),
                                published=None
                            )
                        )
                        logger.info(f"Found vulnerability {id} for {spec.canonical_name}: {description}")

        return spec, results

    def compare_services(self, spec: Dependency):
        """
        Compares the results of NVD, PyPI, OSV, Safety, and GitHub Advisory services for the given `Dependency`.

        Returns the results from all services for further analysis.
        """
        # Run NVD
        nvd_results = self.query(spec)
        logger.info(f"NVD found {len(nvd_results[1])} vulnerabilities for {spec.canonical_name}")

        # Run PyPI (assumed PyPIService class exists)
        pypi_service = PyPIService()
        pypi_results = pypi_service.query(spec)
        logger.info(f"PyPI found {len(pypi_results[1])} vulnerabilities for {spec.canonical_name}")

        # Run OSV (assumed OSVService class exists)
        osv_service = OSVService()
        osv_results = osv_service.query(spec)
        logger.info(f"OSV found {len(osv_results[1])} vulnerabilities for {spec.canonical_name}")

        # Run Safety
        safety_service = SafetyService()
        safety_results = safety_service.query(spec)
        logger.info(f"Safety found {len(safety_results[1])} vulnerabilities for {spec.canonical_name}")

        # Run GitHub Advisory
        github_token = os.environ.get("GITHUB_TOKEN")
        if not github_token:
            raise ServiceError("GitHub token is required for GitHub Advisory Service")
        github_advisory_service = GitHubAdvisoryService(token=github_token)
        github_results = github_advisory_service.query(spec)
        logger.info(f"GitHub Advisory found {len(github_results[1])} vulnerabilities for {spec.canonical_name}")

        # Compare and log discrepancies
        nvd_ids = {vuln.id for vuln in nvd_results[1]}
        pypi_ids = {vuln.id for vuln in pypi_results[1]}
        osv_ids = {vuln.id for vuln in osv_results[1]}
        safety_ids = {vuln.id for vuln in safety_results[1]}
        github_ids = {vuln.id for vuln in github_results[1]}

        missing_in_nvd = (pypi_ids | osv_ids | safety_ids | github_ids) - nvd_ids
        logger.warning(f"Missing in NVD: {missing_in_nvd}")

        return nvd_results, pypi_results, osv_results, safety_results, github_results


class OutdatedPackageService:
    """
    A service to check for outdated packages based on PyPI data.
    """

    PYPI_SIMPLE_URL = "https://pypi.org/simple/"

    def __init__(self, timeout: int | None = None):
        """
        Create a new `OutdatedPackageService`.

        `timeout` is an optional argument to control how many seconds the component should wait for
        responses to network requests.
        """
        self.timeout = timeout
        self.session = requests.Session()

    def check_outdated(self, spec: Dependency) -> bool:
        """
        Checks if the given `Dependency` is outdated based on the latest version available on PyPI.
        """
        response = self.session.get(f"{self.PYPI_SIMPLE_URL}{spec.canonical_name}/", timeout=self.timeout)
        if response.status_code != 200:
            logger.error(f"Failed to fetch PyPI data for {spec.canonical_name}: {response.status_code}")
            return False

        available_versions = self.extract_versions(response.text)
        latest_version = max(available_versions, key=Version)

        logger.debug(f"Latest version of {spec.canonical_name} on PyPI is {latest_version}")

        if spec.version < Version(latest_version):
            logger.info(f"{spec.canonical_name} is outdated (current: {spec.version}, latest: {latest_version})")
            return True
        return False

    @staticmethod
    def extract_versions(html: str) -> list[Version]:
        """
        Extracts and returns a list of available versions from the HTML page.
        """
        # Use a regular expression or HTML parsing to extract version numbers from the response
        # Here we use a simple regex example (actual implementation might require robust parsing)
        import re

        version_regex = re.compile(r">([\d\.]+)<")
        versions = version_regex.findall(html)
        return [Version(v) for v in versions if Version(v)]


def perform_vulnerability_analysis(specs: list[Dependency]):
    """
    Perform a comprehensive vulnerability analysis using multiple services.
    """
    nvd_service = NvdService()
    pypi_service = PyPIService()
    osv_service = OSVService()
    safety_service = SafetyService()
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        raise ServiceError("GitHub token is required for GitHub Advisory Service")
    github_service = GitHubAdvisoryService(token=github_token)
    outdated_service = OutdatedPackageService()

    for spec in specs:
        logger.info(f"Analyzing {spec.canonical_name} version {spec.version}")

        # Perform vulnerability checks
        nvd_results = nvd_service.query(spec)
        pypi_results = pypi_service.query(spec)
        osv_results = osv_service.query(spec)
        safety_results = safety_service.query(spec)
        github_results = github_service.query(spec)

        # Log vulnerabilities
        log_vulnerabilities(nvd_results, "NVD")
        log_vulnerabilities(pypi_results, "PyPI")
        log_vulnerabilities(osv_results, "OSV")
        log_vulnerabilities(safety_results, "Safety")
        log_vulnerabilities(github_results, "GitHub Advisory")

        # Check for outdated packages
        if outdated_service.check_outdated(spec):
            logger.warning(f"{spec.canonical_name} is outdated!")


def log_vulnerabilities(results: tuple[Dependency, list[VulnerabilityResult]], service_name: str):
    """
    Logs the vulnerabilities found by a specific service.
    """
    spec, vulnerabilities = results
    for vuln in vulnerabilities:
        logger.info(
            f"[{service_name}] {spec.canonical_name} {spec.version} is vulnerable: {vuln.id} - {vuln.description}"
        )


# Example usage:
# Assuming 'dependencies' is a list of Dependency instances representing the Python packages to be analyzed
# perform_vulnerability_analysis(dependencies)
