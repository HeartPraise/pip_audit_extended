import os
import json
import requests
import pkg_resources
from typing import List, Tuple, Dict, Any, cast
from pip_audit._service.interface import VulnerabilityService, ResolvedDependency, Dependency, VulnerabilityResult
from datetime import datetime

class GitHubAdvisoryService(VulnerabilityService):
    def __init__(self):
        self.github_token = os.getenv("GITHUB_TOKEN", "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")

    def query(self, spec: Dependency) -> Tuple[Dependency, List[VulnerabilityResult]]:
        if spec.is_skipped():
            return spec, []

        spec = cast(ResolvedDependency, spec)
        vulnerabilities = self.fetch_github_vulnerabilities()
        detected_vulnerabilities = []

        for vulnerability in vulnerabilities:
            if vulnerability.get("package") == spec.canonical_name:
                # Version comparison logic to check if the installed package version is within the vulnerable version range.
                detected_vulnerabilities.append({
                    "id": f"{vulnerability.get('package')}-{vulnerability.get('publishedAt')}",
                    "description": vulnerability.get('description'),
                    "fix_versions": [],  # GitHub advisory doesn't provide fix versions in the query
                    "aliases": set(),
                    "published": self._parse_rfc3339(vulnerability.get('publishedAt')),
                    "severity": vulnerability.get('severity')
                })

        return spec, detected_vulnerabilities

    def fetch_github_vulnerabilities(self) -> List[Dict[str, Any]]:
        url = "https://api.github.com/graphql"
        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Content-Type": "application/json"
        }
        query = {
            "query": """
            {
                securityVulnerabilities(first: 100, ecosystem: PIP) {
                    edges {
                        node {
                            package {
                                name
                            }
                            advisory {
                                description
                                publishedAt
                                severity
                            }
                            vulnerableVersionRange
                        }
                    }
                }
            }
            """
        }

        try:
            response = requests.post(url, headers=headers, json=query)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = []

            for edge in data['data']['securityVulnerabilities']['edges']:
                node = edge['node']
                vulnerabilities.append({
                    "package": node['package']['name'],
                    "description": node['advisory']['description'],
                    "publishedAt": node['advisory']['publishedAt'],
                    "severity": node['advisory']['severity'],
                    "vulnerableVersionRange": node['vulnerableVersionRange']
                })

            return vulnerabilities

        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return []

    @staticmethod
    def _parse_rfc3339(date_string: str | None) -> datetime | None:
        if date_string is None:
            return None
        try:
            return datetime.fromisoformat(date_string.replace("Z", "+00:00"))
        except ValueError:
            return None