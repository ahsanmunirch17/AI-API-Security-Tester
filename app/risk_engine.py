# -----------------------------------------
# Risk scoring and finding normalization
# -----------------------------------------

SEVERITY_SCORES = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def calculate_risk(findings: list[dict]) -> str:
    """
    Calculate overall risk from deterministic security findings.

    HIGH finding -> HIGH risk
    Two or more MEDIUM findings -> HIGH risk
    One MEDIUM finding -> MEDIUM risk
    LOW findings only -> LOW risk
    No findings -> LOW risk
    """

    if not findings:
        return "LOW"

    severities = [
        str(finding.get("severity", "LOW")).upper()
        for finding in findings
    ]

    if "HIGH" in severities:
        return "HIGH"

    medium_count = severities.count("MEDIUM")

    if medium_count >= 2:
        return "HIGH"

    if medium_count == 1:
        return "MEDIUM"

    return "LOW"


def normalize_findings(
    security_findings: list[dict],
) -> list[dict]:
    """
    Remove duplicate security findings based on finding type.
    """

    unique_findings = []
    seen_types = set()

    for finding in security_findings:

        finding_type = finding.get(
            "type",
            finding.get("title", "unknown")
        )

        if finding_type in seen_types:
            continue

        seen_types.add(finding_type)

        unique_findings.append(finding)

    return unique_findings