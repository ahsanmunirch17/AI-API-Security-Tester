// =========================================
// METHOD-AWARE REQUEST BODY CONTROL
// =========================================

function updateRequestBodyState() {

    const method =
        document.getElementById("method").value;

    const requestBody =
        document.getElementById("requestBody");

    const bodyAllowed =
        ["POST", "PUT", "PATCH"].includes(method);

    if (!bodyAllowed) {

        requestBody.value = "";
        requestBody.disabled = true;

        requestBody.placeholder =
            `${method} requests normally do not require a JSON body.`;

    } else {

        requestBody.disabled = false;

        requestBody.placeholder =
`{
  "email": "test@example.com",
  "password": "test"
}`;

    }
}

document
    .getElementById("method")
    .addEventListener("change", updateRequestBodyState);

updateRequestBodyState();

async function startTest() {

    // =========================================
    // GET INPUT VALUES
    // =========================================

    const endpoint =
        document.getElementById("endpoint").value.trim();

    const method =
        document.getElementById("method").value;

    const token =
        document.getElementById("token").value.trim();

    const requestBody =
        document.getElementById("requestBody");

    const requestBodyText =
        requestBody.value.trim();


    // =========================================
    // VALIDATE ENDPOINT
    // =========================================

    if (!endpoint) {

        alert("Please enter an endpoint.");

        return;
    }


    // =========================================
    // PREPARE HEADERS
    // =========================================

    const headers = {};


    if (token) {

        headers["Authorization"] = token;

    }


    // =========================================
    // PREPARE REQUEST BODY
    // =========================================

    let body = null;


    if (requestBodyText) {

        try {

            body = JSON.parse(requestBodyText);

        } catch (error) {

            alert(
                "Invalid JSON in Request Body.\n\n" +
                "Please check your JSON syntax."
            );

            return;
        }

    }


    // =========================================
    // BUTTON / STATUS
    // =========================================

    const button =
        document.getElementById("startBtn");


    button.disabled = true;

    button.innerText =
        "⏳ TESTING...";


    document.getElementById("results")
        .style.display = "none";


    document.getElementById("status")
        .innerHTML = `

            <div class="test running">

                ⟳ Sending ${escapeHtml(method)}
                request...

            </div>

        `;


    // =========================================
    // SEND REQUEST TO FASTAPI
    // =========================================

    try {

        const response =
            await fetch("/analyze", {

                method: "POST",

                headers: {

                    "Content-Type":
                        "application/json"

                },

                body: JSON.stringify({

                    url: endpoint,

                    method: method,

                    headers: headers,

                    body: body

                })

            });


        const data =
            await response.json();


        // =========================================
        // HANDLE SERVER ERROR
        // =========================================

        if (!response.ok) {

            throw new Error(
                data.detail ||
                "Testing failed"
            );

        }


        // =========================================
        // DISPLAY RESULTS
        // =========================================

        displayResults(data);


    } catch (error) {

        document.getElementById("status")
            .innerHTML = `

                <div class="test failed">

                    ✗ ${escapeHtml(
                        error.message
                    )}

                </div>

            `;

    } finally {

        button.disabled = false;

        button.innerText =
            "🚀 START SECURITY TEST";

    }

}


/* =============================================
   DISPLAY RESULTS
   ============================================= */

function displayResults(data) {

    document.getElementById("results")
        .style.display = "block";


    document.getElementById("status")
        .innerHTML = `

            <div class="test success">

                ✓ Automated security assessment completed

            </div>

        `;


    // =========================================
    // AI ANALYSIS
    // =========================================

    const analysis =
        data.ai_analysis || {};


    // =========================================
    // RISK
    // =========================================

    document.getElementById("riskLevel")
        .innerText =
            analysis.risk_level || "UNKNOWN";


    // =========================================
    // SUMMARY
    // =========================================

    document.getElementById("summary")
        .innerText =
            analysis.summary ||
            "No summary available.";


    // =========================================
    // SECURITY CHECKS
    // =========================================

    const securityChecks =
        data.security_checks || [];


    const securityContainer =
        document.getElementById(
            "securityChecks"
        );


    securityContainer.innerHTML = "";


    if (securityChecks.length === 0) {

        securityContainer.innerHTML = `

            <div class="test success">

                ✓ No automated security
                indicators detected.

            </div>

        `;

    } else {

        securityChecks.forEach(check => {

            const div =
                document.createElement("div");


            div.className =
                "finding";


            div.innerHTML = `

                <h4>

                    ⚠ ${escapeHtml(
                        check.title ||
                        "Security Check"
                    )}

                </h4>


                <p>

                    <strong>
                        Type:
                    </strong>

                    ${escapeHtml(
                        check.type ||
                        "unknown"
                    )}

                </p>


                <p>

                    <strong>
                        Severity:
                    </strong>

                    ${escapeHtml(
                        check.severity ||
                        "UNKNOWN"
                    )}

                </p>


                <p>

                    ${escapeHtml(
                        check.description ||
                        ""
                    )}

                </p>


                ${
                    check.evidence
                    ? `

                        <div class="evidence">

                            ${escapeHtml(
                                check.evidence
                            )}

                        </div>

                    `
                    : ""
                }

            `;


            securityContainer
                .appendChild(div);

        });

    }


    // =========================================
    // AI FINDINGS
    // =========================================

    const findingsContainer =
        document.getElementById(
            "findings"
        );


    findingsContainer.innerHTML = "";


    const findings =
        analysis.findings || [];


    if (findings.length === 0) {

        findingsContainer.innerHTML =
            "<p>No AI security findings were reported.</p>";

    } else {

        findings.forEach(finding => {

            const div =
                document.createElement("div");


            div.className =
                "finding";


            div.innerHTML = `

                <h4>

                    ${escapeHtml(
                        finding.title ||
                        "Finding"
                    )}

                </h4>


                <p>

                    <strong>
                        Severity:
                    </strong>

                    ${escapeHtml(
                        finding.severity ||
                        "UNKNOWN"
                    )}

                </p>


                <p>

                    ${escapeHtml(
                        finding.description ||
                        ""
                    )}

                </p>

            `;


            findingsContainer
                .appendChild(div);

        });

    }


    // =========================================
    // EVIDENCE
    // =========================================

    const evidenceContainer =
        document.getElementById(
            "evidence"
        );


    evidenceContainer.innerHTML = "";


    findings.forEach(finding => {

        if (finding.evidence) {

            const div =
                document.createElement("div");


            div.className =
                "evidence";


            div.innerText =
                finding.evidence;


            evidenceContainer
                .appendChild(div);

        }

    });


    // =========================================
    // RECOMMENDATIONS
    // =========================================

    const recommendations =
        document.getElementById(
            "recommendations"
        );


    recommendations.innerHTML = "";


    const recommendationList =
        analysis.recommendations || [];


    if (
        recommendationList.length === 0
    ) {

        recommendations.innerHTML =
            "<li>No recommendations provided.</li>";

    } else {

        recommendationList.forEach(item => {

            const li =
                document.createElement("li");


            li.innerText =
                item;


            recommendations
                .appendChild(li);

        });

    }


    // =========================================
    // SAVE COMPLETE REPORT
    // =========================================

    window.latestReport =
        data;

}


/* =============================================
   VIEW REPORT
   ============================================= */

function viewReport() {

    if (!window.latestReport) {

        alert("No report available.");

        return;

    }


    const reportWindow =
        window.open("", "_blank");


    reportWindow.document.write(`

        <html>

        <head>

            <title>
                API Security Report
            </title>


            <style>

                body {

                    font-family: Arial;

                    max-width: 1000px;

                    margin: 40px auto;

                    line-height: 1.6;

                }


                pre {

                    background: #111827;

                    color: white;

                    padding: 20px;

                    overflow: auto;

                    border-radius: 8px;

                }

            </style>

        </head>


        <body>

            <h1>
                AI API Security Assessment Report
            </h1>


            <pre>

${escapeHtml(
    JSON.stringify(
        window.latestReport,
        null,
        2
    )
)}

            </pre>

        </body>

        </html>

    `);


    reportWindow.document.close();

}


/* =============================================
   DOWNLOAD REPORT
   ============================================= */

function downloadReport() {

    if (!window.latestReport) {

        alert("No report available.");

        return;

    }


    const blob =
        new Blob(

            [

                JSON.stringify(
                    window.latestReport,
                    null,
                    2
                )

            ],

            {
                type:
                    "application/json"
            }

        );


    const url =
        URL.createObjectURL(blob);


    const a =
        document.createElement("a");


    a.href = url;


    a.download =
        "api-security-report.json";


    document.body.appendChild(a);


    a.click();


    document.body.removeChild(a);


    URL.revokeObjectURL(url);

}


/* =============================================
   HTML ESCAPING
   ============================================= */

function escapeHtml(value) {

    const div =
        document.createElement("div");


    div.textContent =
        String(value);


    return div.innerHTML;

}