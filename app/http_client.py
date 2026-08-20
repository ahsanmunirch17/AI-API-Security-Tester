from urllib.parse import urlparse

import httpx


ALLOWED_HOST = "juice-shop-security-assessment.onrender.com"

ALLOWED_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}


def validate_target(url: str) -> None:
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError("Only HTTPS targets are allowed")

    if parsed.hostname != ALLOWED_HOST:
        raise ValueError(
            f"Target host is not allowed: {parsed.hostname}"
        )


async def execute_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | list | None = None,
) -> dict:

    validate_target(url)

    method = method.upper().strip()

    if method not in ALLOWED_METHODS:
        raise ValueError(
            f"Unsupported HTTP method: {method}. "
            f"Allowed methods: {', '.join(sorted(ALLOWED_METHODS))}"
        )

    request_headers = dict(headers or {})

    # Automatically tell the target that JSON is being sent
    # when a request body exists.
    if body is not None:
        request_headers.setdefault(
            "Content-Type",
            "application/json"
        )

    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=False,
    ) as client:

        response = await client.request(
            method=method,
            url=url,
            headers=request_headers,
            json=body if body is not None else None,
        )

    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": response.text[:10000],
    }