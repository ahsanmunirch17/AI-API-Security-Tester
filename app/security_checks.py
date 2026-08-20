import re


def run_security_checks(response: dict) -> list[dict]:
    """
    Perform deterministic security checks on an HTTP response.

    These checks identify security-relevant indicators.
    They do not replace the AI assessment.
    """

    findings = []

    status_code = response.get("status_code")
    headers = response.get("headers", {})
    body = response.get("body", "")

    # -------------------------------------------------
    # 1. Stack trace / internal path disclosure
    # -------------------------------------------------

    stack_trace_indicators = [
        r"\bat\s+\/[A-Za-z0-9_\-./]+:\d+:\d+",
        r"/node_modules/",
        r"/build/",
        r"/src/",
        r"/app/",
        r"Stack trace",
        r"Traceback \(most recent call last\)",
    ]

    stack_trace_detected = any(
        re.search(pattern, body, re.IGNORECASE)
        for pattern in stack_trace_indicators
    )

    if stack_trace_detected:

        findings.append({
            "type": "information_disclosure",
            "title": "Detailed stack trace disclosure",
            "severity": "MEDIUM",
            "description": (
                "The HTTP response appears to expose internal "
                "stack-trace or filesystem information."
            ),
            "evidence": body[:3000],
        })


    # -------------------------------------------------
    # 2. Technology/version disclosure
    # -------------------------------------------------

    technology_indicators = [
        r"Express\s*[v^]?\d",
        r"Apache\s*[v/]?\d",
        r"nginx\s*[v/]?\d",
        r"PHP/\d",
        r"Python/\d",
        r"Node\.js",
        r"OWASP Juice Shop",
    ]

    technology_detected = any(
        re.search(pattern, body, re.IGNORECASE)
        for pattern in technology_indicators
    )

    if technology_detected:

        findings.append({
            "type": "technology_disclosure",
            "title": "Technology or version disclosure",
            "severity": "LOW",
            "description": (
                "The response exposes application technology "
                "or version information."
            ),
            "evidence": body[:1500],
        })


    # -------------------------------------------------
    # 3. Infrastructure disclosure through headers
    # -------------------------------------------------

    infrastructure_headers = [
        "server",
        "x-powered-by",
        "x-render-origin-server",
        "via",
    ]

    exposed_headers = {}

    for header_name in infrastructure_headers:

        for actual_name, value in headers.items():

            if actual_name.lower() == header_name:
                exposed_headers[actual_name] = value

    if exposed_headers:

        findings.append({
            "type": "infrastructure_disclosure",
            "title": "Infrastructure information disclosed",
            "severity": "LOW",
            "description": (
                "Response headers disclose information about "
                "the underlying server or hosting infrastructure."
            ),
            "evidence": str(exposed_headers),
        })


    # -------------------------------------------------
    # 4. Detailed error response
    # -------------------------------------------------

    error_indicators = [
        "Error:",
        "Internal Server Error",
        "Unexpected path:",
        "Unhandled",
        "Exception",
    ]

    error_detected = any(
        indicator.lower() in body.lower()
        for indicator in error_indicators
    )

    if status_code is not None and status_code >= 500 and error_detected:

        findings.append({
            "type": "error_disclosure",
            "title": "Detailed server error response",
            "severity": "MEDIUM",
            "description": (
                "The server returned a 5xx response containing "
                "detailed error information."
            ),
            "evidence": body[:2000],
        })


    # -------------------------------------------------
    # 5. CORS wildcard observation
    # -------------------------------------------------

    cors_origin = None

    for actual_name, value in headers.items():

        if actual_name.lower() == "access-control-allow-origin":
            cors_origin = value
            break

    if cors_origin == "*":

        findings.append({
            "type": "cors_configuration",
            "title": "Permissive wildcard CORS policy",
            "severity": "LOW",
            "description": (
                "The response allows requests from any origin "
                "through Access-Control-Allow-Origin: *. "
                "This is an observation and is not by itself "
                "proof of a CORS vulnerability."
            ),
            "evidence": (
                "Access-Control-Allow-Origin: *"
            ),
        })


    # -------------------------------------------------
    # 6. Missing security-related HTTP headers
    # -------------------------------------------------

    security_headers = {
        "content-security-policy": "Content-Security-Policy",
        "strict-transport-security": "Strict-Transport-Security",
        "referrer-policy": "Referrer-Policy",
    }

    present_headers = {
        actual_name.lower()
        for actual_name in headers.keys()
    }

    missing_headers = []

    for header_key, header_display_name in security_headers.items():

        if header_key not in present_headers:
            missing_headers.append(header_display_name)

    if missing_headers:

        findings.append({
            "type": "missing_security_headers",
            "title": "Missing security-related HTTP headers",
            "severity": "LOW",
            "description": (
                "The HTTP response does not include one or more "
                "common security-related headers. These headers "
                "provide additional defense-in-depth protection "
                "against common web security risks."
            ),
            "evidence": (
                "Missing headers: "
                + ", ".join(missing_headers)
            ),
        })


    return findings