import os
import json
import re

from dotenv import load_dotenv
from groq import Groq


load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    raise RuntimeError("GROQ_API_KEY is not configured")

client = Groq(api_key=GROQ_API_KEY)


def analyze_response(
    url: str,
    method: str,
    response: dict
) -> dict:

    security_context = response.get(
        "security_context",
        {}
    )

    prompt = f"""
You are a careful API security assessment assistant.

Your job is to analyze the supplied HTTP response together with the
security-testing context calculated by the application.

Endpoint:
{url}

HTTP Method:
{method}

HTTP Status Code:
{response.get("status_code")}

Security Context:
{json.dumps(security_context, indent=2)}

Response Headers:
{json.dumps(response.get("headers", {}), indent=2)}

Response Body:
{response.get("body", "")}

IMPORTANT ANALYSIS RULES:

1. The Security Context is authoritative testing metadata calculated
by the local security-testing application.

2. Do NOT contradict the Security Context.

3. Separate OBSERVED FACTS from SECURITY CONCLUSIONS.

4. Never invent authentication state, authorization rules, database
behavior, request methods, users, roles, or application functionality.

5. A HTTP 200 response alone does NOT prove a vulnerability.

6. Predictable resource IDs alone do NOT prove BOLA/IDOR.

7. If:
   cross_user_access_observed = true

   then report a CONFIRMED BOLA/IDOR vulnerability.

8. When cross_user_access_observed is true, use these values directly:

   authenticated_user_id
   requested_resource_id
   response_resource_owner_id
   status_code

9. If authenticated_user_id is known and has_authorization is true,
describe the request as authenticated.

10. Do NOT describe an authenticated request as unauthenticated.

11. If:
    authenticated_user_id != response_resource_owner_id
    AND
    cross_user_access_observed = true
    AND
    the response status is successful,

    then the evidence supports unauthorized cross-user resource access.

12. A confirmed BOLA/IDOR finding should normally be HIGH severity
when an authenticated user receives another user's protected resource.

13. If cross_user_access_observed = false, do NOT claim that BOLA/IDOR
is confirmed.

14. If cross_user_access_observed = true, the findings MUST contain
a BOLA/IDOR finding.

15. If cross_user_access_observed = true, the BOLA/IDOR evidence MUST
mention:
    - authenticated user ID
    - requested resource ID
    - resource owner ID
    - HTTP status
    - successful resource disclosure

16. If cross_user_access_observed = true, recommendations must focus
on server-side object-level authorization.

============================================================
ADMIN AUTHORIZATION RULES
============================================================

17. Pay special attention to endpoints whose path contains an
administrative route such as:

    /rest/admin/
    /api/admin/
    /admin/

18. If the endpoint is clearly an administrative endpoint AND the
Security Context shows that the request was authenticated with a
non-admin/customer user AND the server returned successful access
such as HTTP 200, treat this as a CONFIRMED BROKEN ACCESS CONTROL /
MISSING FUNCTION-LEVEL AUTHORIZATION finding.

19. A customer token successfully accessing an endpoint under
/rest/admin/ is strong evidence of missing server-side authorization.

20. For a confirmed administrative authorization failure, the finding
should normally be HIGH severity when the endpoint exposes protected
administrative functionality or configuration.

21. The finding title should clearly identify the authorization issue,
for example:

    "Broken Access Control: Customer Can Access Administrative Endpoint"

22. Evidence for this finding MUST include:
    - HTTP method
    - endpoint
    - authenticated user or role when available
    - expected/non-admin role when available
    - HTTP status
    - description of the administrative response obtained

23. Do NOT confuse administrative endpoint access with JWT role
tampering.

24. If a customer token already receives HTTP 200 from an administrative
endpoint, changing the JWT role from customer to admin does NOT by
itself prove JWT signature bypass or JWT privilege escalation.

25. JWT role tampering should only be considered CONFIRMED if the
modified token itself is accepted AND the modified authorization state
provides access that the original valid token did not have.

26. If both the original customer token and the tampered token receive
the same administrative access, prioritize the confirmed
Broken Access Control / Missing Function-Level Authorization finding.

27. Do NOT report:
    "Insecure JWT verification leading to privilege escalation"
solely because:
    jwt_tampered = true
    AND
    HTTP status = 200.

28. A tampered JWT with an invalid/original signature should be treated
as an invalid-token test unless the server demonstrably accepts the
modified authorization state.

29. If the original customer token already has access to the
administrative endpoint, state that the primary issue is insufficient
server-side authorization rather than JWT signature verification.

============================================================
JWT TAMPERING RULES
============================================================

30. If:
    jwt_tampered = true

    and the modified token is accepted, but there is no evidence that
    the modified token gained privileges beyond the original token,
    do NOT confirm JWT privilege escalation.

31. If the original token and tampered token produce equivalent access,
the JWT tampering result should be described as unconfirmed or
non-conclusive.

32. Do not infer JWT signature bypass merely from HTTP 200.

33. Do not infer that role claims are trusted merely because a JWT
payload was modified.

34. If a valid customer token can access an admin endpoint, report the
authorization flaw separately from JWT tampering.

============================================================
CORS RULES
============================================================

35. Do NOT treat:

    Access-Control-Allow-Origin: *

    as automatically vulnerable.

36. CORS findings require evidence that the browser security boundary
is improperly configured in a meaningful way.

============================================================
INFORMATION DISCLOSURE RULES
============================================================

37. Do NOT call information sensitive merely because it exists in JSON.

38. Explain why exposed information matters.

39. Do not automatically classify normal public product/configuration
data as a vulnerability.

============================================================
RISK RULES
============================================================

40. The risk_level must reflect the strongest issue actually supported
by the evidence and Security Context.

41. Prefer accurate LOW or MEDIUM findings over unsupported HIGH
findings.

42. A confirmed authorization bypass involving administrative
functionality may be HIGH.

43. A confirmed BOLA exposing another user's protected resource may
be HIGH.

44. Unconfirmed JWT tampering should NOT automatically produce HIGH
severity.

============================================================
OUTPUT FORMAT
============================================================

Return the assessment as JSON with exactly these fields:

{{
  "risk_level": "LOW | MEDIUM | HIGH",
  "summary": "short evidence-based security summary",
  "findings": [
    {{
      "title": "finding title",
      "severity": "LOW | MEDIUM | HIGH",
      "description": "evidence-based explanation",
      "evidence": "specific evidence"
    }}
  ],
  "recommendations": [
    "recommendation 1",
    "recommendation 2"
  ]
}}

============================================================
BOLA EXAMPLE
============================================================

If the Security Context contains:

{{
  "has_authorization": true,
  "authenticated_user_id": 24,
  "requested_resource_id": 1,
  "response_resource_owner_id": 1,
  "cross_user_access_observed": true
}}

or equivalent values where the authenticated user ID differs from the
resource owner ID, report the BOLA finding based on those values.

For a confirmed BOLA case, use a summary similar in meaning to:

"Confirmed BOLA/IDOR: authenticated user X accessed resource Y,
which belongs to user Z. The server returned HTTP 200 and exposed
the resource data."

============================================================
ADMIN ACCESS EXAMPLE
============================================================

If the request is:

GET /rest/admin/application-configuration

and the Security Context shows:

has_authorization = true
role = customer
HTTP status = 200

and the response contains administrative configuration, report:

"Confirmed Broken Access Control: an authenticated customer account
successfully accessed an administrative endpoint."

Do NOT call this JWT privilege escalation unless there is separate
evidence proving that the modified JWT itself bypassed signature
validation and changed authorization privileges.

============================================================
INSUFFICIENT EVIDENCE
============================================================

If there is insufficient evidence for a vulnerability, return an empty
findings array.

Return ONLY valid JSON.
Do not use Markdown code fences.
"""

    result = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a careful API security assessment assistant. "
                    "Use the supplied Security Context as authoritative "
                    "testing metadata. Never contradict verified context. "
                    "Never present an unverified assumption as a confirmed "
                    "vulnerability. Distinguish JWT tampering from "
                    "server-side authorization failures."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0
    )

    content = result.choices[0].message.content

    content = content.strip()

    content = re.sub(
        r"^```json\s*",
        "",
        content,
        flags=re.IGNORECASE
    )

    content = re.sub(
        r"^```\s*",
        "",
        content
    )

    content = re.sub(
        r"\s*```$",
        "",
        content
    )

    content = content.strip()

    try:

        parsed = json.loads(content)

        if not isinstance(parsed, dict):

            raise json.JSONDecodeError(
                "AI response is not a JSON object",
                content,
                0
            )

        return parsed

    except json.JSONDecodeError:

        return {
            "risk_level": "UNKNOWN",
            "summary": (
                "AI returned a response that could not "
                "be parsed as JSON."
            ),
            "findings": [],
            "recommendations": [],
            "raw_ai_response": content
        }