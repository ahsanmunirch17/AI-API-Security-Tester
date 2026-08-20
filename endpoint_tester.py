import httpx


ALLOWED_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}


def test_endpoint(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | list | None = None,
) -> dict:

    method = method.upper().strip()

    if method not in ALLOWED_METHODS:
        raise ValueError(
            f"Unsupported HTTP method: {method}. "
            f"Allowed: {', '.join(sorted(ALLOWED_METHODS))}"
        )

    request_headers = dict(headers or {})

    if body is not None:

        request_headers.setdefault(
            "Content-Type",
            "application/json"
        )

    try:

        response = httpx.request(
            method=method,
            url=url,
            headers=request_headers,
            json=body,
            timeout=15,
            follow_redirects=False
        )

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:10000]
        }

    except httpx.RequestError as e:

        return {
            "status_code": 0,
            "headers": {},
            "body": "",
            "error": str(e)
        }