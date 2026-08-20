import json
from pathlib import Path
from datetime import datetime


REPORTS_DIR = Path("reports")


def get_latest_report():
    reports = sorted(
        REPORTS_DIR.glob("report_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )

    if not reports:
        raise FileNotFoundError("No timestamped security report found.")

    return reports[0]


def generate_markdown_report(report_path: Path):

    with open(report_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    endpoint = data.get("endpoint", "Unknown")
    method = data.get("method", "Unknown")
    timestamp = data.get("timestamp", "Unknown")

    response = data.get("response", {})
    status_code = response.get("status_code", "Unknown")

    security_checks = data.get("security_checks", [])
    ai_analysis = data.get("ai_analysis", {})

    risk_level = ai_analysis.get("risk_level", "UNKNOWN")
    summary = ai_analysis.get(
        "summary",
        "No summary available."
    )

    findings = ai_analysis.get("findings", [])
    recommendations = ai_analysis.get(
        "recommendations",
        []
    )

    output = []

    output.append("# AI API Security Assessment Report")
    output.append("")
    output.append("## 1. Assessment Information")
    output.append("")
    output.append(f"- **Endpoint:** `{endpoint}`")
    output.append(f"- **Method:** `{method}`")
    output.append(f"- **Assessment Time:** `{timestamp}`")
    output.append(f"- **HTTP Status:** `{status_code}`")
    output.append(f"- **Overall Risk:** **{risk_level}**")
    output.append("")

    output.append("## 2. Executive Summary")
    output.append("")
    output.append(summary)
    output.append("")

    output.append("## 3. Automated Security Checks")
    output.append("")

    if not security_checks:
        output.append(
            "No automated security indicators were detected."
        )
    else:
        for number, check in enumerate(
            security_checks,
            start=1
        ):
            output.append(
                f"### 3.{number} {check.get('title', 'Security Check')}"
            )
            output.append("")
            output.append(
                f"- **Type:** {check.get('type', 'Unknown')}"
            )
            output.append(
                f"- **Severity:** {check.get('severity', 'UNKNOWN')}"
            )
            output.append("")
            output.append(
                check.get(
                    "description",
                    "No description available."
                )
            )
            output.append("")

            evidence = check.get("evidence")

            if evidence:
                output.append("**Evidence:**")
                output.append("")
                output.append("```text")
                output.append(str(evidence))
                output.append("```")
                output.append("")

    output.append("## 4. AI Findings")
    output.append("")

    if not findings:
        output.append(
            "No AI security findings were reported."
        )
    else:
        for number, finding in enumerate(
            findings,
            start=1
        ):
            output.append(
                f"### 4.{number} "
                f"{finding.get('title', 'Finding')}"
            )
            output.append("")
            output.append(
                f"- **Severity:** "
                f"{finding.get('severity', 'UNKNOWN')}"
            )
            output.append("")
            output.append(
                finding.get(
                    "description",
                    "No description available."
                )
            )
            output.append("")

            evidence = finding.get("evidence")

            if evidence:
                output.append("**Evidence:**")
                output.append("")
                output.append("```text")
                output.append(str(evidence))
                output.append("```")
                output.append("")

    output.append("## 5. Recommendations")
    output.append("")

    if not recommendations:
        output.append(
            "No recommendations were provided."
        )
    else:
        for recommendation in recommendations:
            output.append(
                f"- {recommendation}"
            )

    output.append("")
    output.append("## 6. Raw Response Summary")
    output.append("")
    output.append(
        f"- **Status Code:** `{status_code}`"
    )

    headers = response.get("headers", {})

    if headers:
        output.append("")
        output.append("### Response Headers")
        output.append("")

        for name, value in headers.items():
            output.append(
                f"- `{name}: {value}`"
            )

    output.append("")
    output.append("## 7. Assessment Conclusion")
    output.append("")

    output.append(
        "The automated assessment successfully executed an HTTP "
        "request against the target endpoint and performed both "
        "deterministic security checks and AI-assisted analysis."
    )

    output.append("")

    output.append(
        f"The assessment identified **{len(security_checks)} "
        f"automated security observations** and "
        f"**{len(findings)} AI findings**."
    )

    output.append("")

    output.append(
        "The findings should be validated manually before being "
        "classified as confirmed vulnerabilities."
    )

    output.append("")

    markdown = "\n".join(output)

    output_path = (
        REPORTS_DIR /
        f"{report_path.stem}_summary.md"
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:
        file.write(markdown)

    return output_path


if __name__ == "__main__":

    latest = get_latest_report()

    generated = generate_markdown_report(latest)

    print(f"Source report: {latest}")
    print(f"Summary report: {generated}")