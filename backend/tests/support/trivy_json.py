"""Builders of small Trivy JSON reports for the tests."""

import json

from app.parsers.json.parser import parse_report_bytes


def small_report(**metadata: object) -> dict:
    """A tiny valid schema-v2 report with one vulnerability."""
    return {
        "SchemaVersion": 2,
        "ArtifactType": "repository",
        "Metadata": dict(metadata),
        "Results": [{
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-0001",
                "PkgName": "demo",
                "InstalledVersion": "1.0",
                "FixedVersion": "1.1",
                "Status": "fixed",
                "Severity": "high",
            }],
        }],
    }


def as_bytes(report: object) -> bytes:
    """Encode a report the way Trivy writes it (UTF-8 JSON)."""
    return json.dumps(report).encode("utf-8")


def report_with(*results: dict) -> bytes:
    """A small schema-v2 report with the given Results, as file bytes."""
    data = {"SchemaVersion": 2, "ArtifactType": "repository", "Results": list(results)}
    return json.dumps(data).encode("utf-8")


def dockerfile_result(*misconfigs: dict, summary: dict | None = None) -> dict:
    result = {"Target": "Dockerfile", "Class": "config", "Type": "dockerfile",
              "Misconfigurations": list(misconfigs)}
    if summary is not None:
        result["MisconfSummary"] = summary
    return result


def misconf(status: str = "FAIL", **fields: object) -> dict:
    return {"ID": "DS-0002", "Title": "Image user should not be 'root'", "Severity": "HIGH",
            "Status": status, **fields}


def secret(rule: str = "aws-access-key-id", line: int = 3) -> dict:
    return {"RuleID": rule, "Category": "AWS", "Severity": "CRITICAL", "Title": "AWS Access Key ID",
            "StartLine": line, "EndLine": line, "Match": "AKIA-NOT-A-REAL-KEY-0000",
            "Code": {"Lines": [{"Number": line, "Content": "AKIA-NOT-A-REAL-KEY-0000"}]}, "Offset": 10}


def secrets_result(*items: dict, target: str = "deploy.sh") -> dict:
    return {"Target": target, "Class": "secret", "Secrets": list(items)}


def parse(*results: dict):
    return parse_report_bytes("test.json", report_with(*results))
