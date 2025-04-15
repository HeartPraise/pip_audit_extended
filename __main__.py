"""
The `python -m pip_audit` entrypoint.


if __name__ == "__main__":  # pragma: no cover
    from pip_audit._cli import audit

    audit()
"""
import pkg_resources
from pip_audit._service.interface import Dependency
from typing import List, Tuple, Dict, Any, cast
#from pip_audit._service import GitHubAdvisoryService  # Add GitHubAdvisoryService
from pip_audit._cli import audit


import os
import json
import requests
from packaging.version import Version
#from typing import List, Tuple
from pip_audit._service.interface import ResolvedDependency, SkippedDependency
from pip_audit._service.github import GitHubAdvisoryService
from pip_audit._service.interface import VulnerabilityResult


def get_installed_packages() -> List[Tuple[str, str]]:
    """
    Retrieve a list of installed Python packages and their versions.
    
    Returns:
        List[Tuple[str, str]]: A list of tuples containing package names and versions.
    """
    installed_packages = [
        (dist.project_name, dist.version) for dist in pkg_resources.working_set
    ]
    return installed_packages

def generate_report(detected_vulnerabilities):
    """
    Generate a report of detected vulnerabilities in installed packages.
    
    Args:
        detected_vulnerabilities (List[dict]): List of detected vulnerabilities.
    """
    if not detected_vulnerabilities:
        print("No vulnerabilities found in installed packages.")
        return

    print("\nDetected Vulnerabilities:\n")
    for vuln in detected_vulnerabilities:
        print(f"Package: {vuln['package']} {vuln['version']}")
        print(f"Description: {vuln['description']}")
        print(f"Severity: {vuln['severity']}")
        print(f"Published At: {vuln['published']}\n")
        print("-" * 80)

def custom_github_audit():
    vulnerabilities = GitHubAdvisoryService().fetch_github_vulnerabilities()
    installed_packages = get_installed_packages()

    detected_vulnerabilities = []

    for package_name, package_version in installed_packages:
        spec = ResolvedDependency(package_name, package_version)
        service = GitHubAdvisoryService()

        _, vulns = service.query(spec)
        for vulnerability in vulns:
            detected_vulnerabilities.append({
                "package": package_name,
                "version": package_version,
                "description": vulnerability['description'],
                "severity": vulnerability.get('severity', 'UNKNOWN'),
                "published": vulnerability['published'].isoformat() if vulnerability['published'] else 'UNKNOWN',
            })

    generate_report(detected_vulnerabilities)
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--vulnerability-service" and sys.argv[2] == "github":
        custom_github_audit()
    else:
        audit()
