from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl, Field

from app.http_client import execute_request
from app.ai_analyzer import analyze_response
from app.security_checks import run_security_checks

import json
import base64
from datetime import datetime
from pathlib import Path


app = FastAPI(
    title="AI API Security Tester",
    version="0.8.0"
)


# =========================================
# Paths
# =========================================

BASE_DIR = Path(__file__).resolve().parent.parent

STATIC_DIR = BASE_DIR / "static"
REPORTS_DIR = BASE_DIR / "reports"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# =========================================
# Static frontend
# =========================================

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static"
)


# =========================================
# Request model
# =========================================

class EndpointRequest(BaseModel):

    url: HttpUrl

    method: str = Field(
        default="GET",
        description="HTTP method"
    )

    headers: dict[str, str] = Field(
        default_factory=dict,
        description="HTTP headers"
    )

    body: dict | list | None = Field(
        default=None,
        description="Optional JSON request body"
    )

    # JWT security-testing context
    jwt_payload: dict | None = Field(
        default=None,
        description="Decoded JWT payload used for security analysis"
    )

    jwt_tampered: bool = Field(
        default=False,
        description="Whether JWT payload was intentionally modified"
    )

    original_role: str | None = Field(
        default=None,
        description="Original JWT role"
    )

    tampered_role: str | None = Field(
        default=None,
        description="Modified JWT role"
    )


# =========================================
# Allowed methods
# =========================================

ALLOWED_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}


# =========================================
# JWT user ID extraction
# =========================================

def extract_authenticated_user_id(
    headers: dict[str, str]
):

    authorization = None

    for key, value in headers.items():

        if key.lower() == "authorization":

            authorization = value
            break

    if not authorization:
        return None

    if not authorization.lower().startswith("bearer "):
        return None

    token = authorization[7:].strip()

    if not token:
        return None

    try:

        parts = token.split(".")

        if len(parts) != 3:
            return None

        payload = parts[1]

        padding = "=" * (-len(payload) % 4)

        decoded = base64.urlsafe_b64decode(
            payload + padding
        )

        payload_data = json.loads(
            decoded.decode("utf-8")
        )

        data = payload_data.get("data")

        if isinstance(data, dict):

            user_id = data.get("id")

            if user_id is not None:
                return int(user_id)

        user_id = payload_data.get("id")

        if user_id is not None:
            return int(user_id)

    except Exception:
        return None

    return None


# =========================================
# Resource owner extraction
# =========================================

def extract_resource_owner_id(
    response: dict
):

    body = response.get("body", "")

    if not body:
        return None

    try:

        data = json.loads(body)

    except (json.JSONDecodeError, TypeError):

        return None

    if not isinstance(data, dict):
        return None

    resource = data.get("data")

    if not isinstance(resource, dict):
        return None

    owner_id = resource.get("UserId")

    if owner_id is None:
        return None

    try:

        return int(owner_id)

    except (TypeError, ValueError):

        return None


# =========================================
# BOLA detection
# =========================================

def determine_cross_user_access(
    authenticated_user_id,
    response_resource_owner_id,
    status_code
):

    if authenticated_user_id is None:
        return False

    if response_resource_owner_id is None:
        return False

    if status_code < 200 or status_code >= 300:
        return False

    return (
        authenticated_user_id
        != response_resource_owner_id
    )


# =========================================
# Dashboard
# =========================================

@app.get("/")
def dashboard():

    return FileResponse(
        str(STATIC_DIR / "index.html")
    )


# =========================================
# Health check
# =========================================

@app.get("/health")
def health():

    return {
        "status": "ok",
        "service": "AI API Security Tester",
        "version": "0.8.0"
    }


# =========================================
# Main security analysis endpoint
# =========================================

@app.post("/analyze")
async def analyze_endpoint(
    request: EndpointRequest
):

    try:

        method = request.method.upper().strip()

        # ---------------------------------
        # Validate HTTP method
        # ---------------------------------

        if method not in ALLOWED_METHODS:

            raise ValueError(
                f"Unsupported HTTP method: {method}. "
                f"Allowed methods: "
                f"{', '.join(sorted(ALLOWED_METHODS))}"
            )

        # ---------------------------------
        # Extract authentication context
        # ---------------------------------

        authenticated_user_id = (
            extract_authenticated_user_id(
                request.headers
            )
        )

        # ---------------------------------
        # Execute target request
        # ---------------------------------

        result = await execute_request(
            url=str(request.url),
            method=method,
            headers=request.headers,
            body=request.body,
        )

        # ---------------------------------
        # Extract resource owner
        # ---------------------------------

        response_resource_owner_id = (
            extract_resource_owner_id(
                result
            )
        )

        # ---------------------------------
        # Determine BOLA
        # ---------------------------------

        cross_user_access_observed = (
            determine_cross_user_access(
                authenticated_user_id,
                response_resource_owner_id,
                result.get("status_code")
            )
        )

        # ---------------------------------
        # Extract requested resource ID
        # ---------------------------------

        url_path = str(request.url).rstrip("/")

        last_segment = url_path.split("/")[-1]

        requested_resource_id = None

        if last_segment.isdigit():

            requested_resource_id = int(
                last_segment
            )

        # ---------------------------------
        # Build security context
        # ---------------------------------

        security_context = {

            "has_authorization":
                any(
                    key.lower() == "authorization"
                    for key in request.headers.keys()
                ),

            "authenticated_user_id":
                authenticated_user_id,

            "requested_resource_id":
                requested_resource_id,

            "response_resource_owner_id":
                response_resource_owner_id,

            "cross_user_access_observed":
                cross_user_access_observed,

            # JWT testing information
            "jwt_tampered":
                request.jwt_tampered,

            "original_role":
                request.original_role,

            "tampered_role":
                request.tampered_role,

            "jwt_payload":
                request.jwt_payload,
        }

        # ---------------------------------
        # Attach security context
        # ---------------------------------

        result["security_context"] = security_context

        # ---------------------------------
        # Deterministic security checks
        # ---------------------------------

        security_findings = run_security_checks(
            result
        )

        # ---------------------------------
        # AI analysis
        # ---------------------------------

        ai_analysis = analyze_response(
            str(request.url),
            method,
            result
        )

        # =================================
        # JWT tampering detection
        # =================================

        if (
            request.jwt_tampered
            and request.original_role
            and request.tampered_role
            and request.original_role
            != request.tampered_role
        ):

            jwt_finding = {

                "title":
                    "JWT Role Tampering Detected",

                "severity":
                    "HIGH",

                "description":
                    (
                        "The JWT security test detected a change "
                        "in the role claim from the original role "
                        "to a different role. This represents a "
                        "potential privilege-escalation scenario "
                        "if the server accepts the modified token."
                    ),

                "evidence":
                    (
                        f"Original role: "
                        f"{request.original_role}; "
                        f"Tampered role: "
                        f"{request.tampered_role}; "
                        f"JWT tampering flag: "
                        f"{request.jwt_tampered}"
                    ),

                "note":
                    (
                        "This test alone does not prove a JWT "
                        "vulnerability. A modified JWT must have "
                        "a valid signature accepted by the server "
                        "before privilege escalation is confirmed."
                    )
            }

            ai_analysis.setdefault(
                "findings",
                []
            )

            ai_analysis["findings"].insert(
                0,
                jwt_finding
            )

            # Upgrade risk because this is a security
            # testing signal, while clearly explaining
            # that exploitation is not confirmed.

            current_risk = str(
                ai_analysis.get(
                    "risk_level",
                    "LOW"
                )
            ).upper()

            if current_risk == "LOW":

                ai_analysis["risk_level"] = "MEDIUM"

            ai_analysis["summary"] = (
                "JWT role tampering was detected in the "
                "security-testing context: the role changed "
                f"from '{request.original_role}' to "
                f"'{request.tampered_role}'. "
                "This is a potential privilege-escalation "
                "condition, but the server must accept the "
                "modified signed token before the vulnerability "
                "can be confirmed."
            )

            recommendations = ai_analysis.setdefault(
                "recommendations",
                []
            )

            recommendations.insert(
                0,
                (
                    "Verify JWT signature validation and reject "
                    "any token whose signature does not match "
                    "its payload."
                )
            )

            recommendations.insert(
                1,
                (
                    "Never trust client-controlled JWT role "
                    "claims unless the token signature and "
                    "issuer are properly validated."
                )
            )

        # =================================
        # Build report
        # =================================

        report = {

            "status":
                "tested",

            "endpoint":
                str(request.url),

            "method":
                method,

            "timestamp":
                datetime.now().isoformat(),

            "request": {

                "method":
                    method,

                "has_authorization":
                    security_context[
                        "has_authorization"
                    ],

                "has_body":
                    request.body is not None,

                "body":
                    request.body,

                "authenticated_user_id":
                    authenticated_user_id,

                "requested_resource_id":
                    requested_resource_id,

                "response_resource_owner_id":
                    response_resource_owner_id,

                "cross_user_access_observed":
                    cross_user_access_observed,

                # JWT testing context
                "jwt_tampered":
                    request.jwt_tampered,

                "original_role":
                    request.original_role,

                "tampered_role":
                    request.tampered_role,

                "jwt_payload":
                    request.jwt_payload,
            },

            "response":
                result,

            "security_checks":
                security_findings,

            "ai_analysis":
                ai_analysis
        }

        # ---------------------------------
        # Save report
        # ---------------------------------

        timestamp = datetime.now().strftime(
            "%Y-%m-%d_%H-%M-%S"
        )

        report_file = REPORTS_DIR / (
            f"report_{timestamp}.json"
        )

        with open(
            report_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=2,
                ensure_ascii=False
            )

        return report

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                f"Endpoint request failed: {str(exc)}"
            )
        )