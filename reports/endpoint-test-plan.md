# OWASP Juice Shop API Endpoint Test Plan

Target:
https://juice-shop-security-assessment.onrender.com

## Endpoint 1
GET /rest/products

Purpose:
Test error handling, information disclosure, technology disclosure and CORS.

Status:
Tested

## Endpoint 2
GET /rest/basket/7

Purpose:
Test authorization and access control.

Status:
Pending

## Endpoint 3
GET /rest/basket/8

Purpose:
Test whether a different basket ID can be accessed without authorization.

Status:
Pending

## Endpoint 4
GET /rest/user/whoami

Purpose:
Test authentication state and authorization behavior.

Status:
Pending

## Endpoint 5
POST /rest/user/login

Purpose:
Test authentication error handling and SQL injection indicators.

Status:
Previously tested

## Endpoint 6
GET /api/Products

Purpose:
Test a valid product API endpoint and compare normal response behavior.

Status:
Pending