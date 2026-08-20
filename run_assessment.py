import os

from endpoint_tester import test_endpoint
from app.ai_analyzer import analyze_response


TARGET = "https://juice-shop-security-assessment.onrender.com/rest/basket/8"


def main():
    print("=" * 60)
    print("AI API SECURITY ASSESSMENT")
    print("=" * 60)

    token = os.getenv("JWT_TOKEN")

    if not token:
        print("\nERROR: JWT_TOKEN environment variable is not set.")
        print("Run: $env:JWT_TOKEN = $originalToken")
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    print(f"\nTarget: {TARGET}")
    print("Method: GET")
    print("Authentication: Customer JWT")

    print("\n[1] Sending authenticated HTTP request...")

    response = test_endpoint(
        url=TARGET,
        method="GET",
        headers=headers,
    )

    print(f"HTTP Status: {response['status_code']}")

    if "error" in response:
        print("\nRequest failed:")
        print(response["error"])
        return

    print("\n[2] Sending response to AI analyzer...")

    try:
        assessment = analyze_response(
            url=TARGET,
            method="GET",
            response=response,
        )

    except Exception as e:
        print("\nAI analysis failed:")
        print(str(e))
        return

    print("\n[3] AI SECURITY ASSESSMENT")
    print("=" * 60)

    print(f"Risk Level: {assessment.get('risk_level')}")

    print("\nSummary:")
    print(assessment.get("summary"))

    print("\nFindings:")

    findings = assessment.get("findings", [])

    if not findings:
        print("No security findings reported.")
    else:
        for i, finding in enumerate(findings, start=1):
            print(f"\nFinding #{i}")
            print(f"Title: {finding.get('title')}")
            print(f"Severity: {finding.get('severity')}")
            print(f"Description: {finding.get('description')}")
            print(f"Evidence: {finding.get('evidence')}")

    print("\nRecommendations:")

    for recommendation in assessment.get("recommendations", []):
        print(f"- {recommendation}")


if __name__ == "__main__":
    main()