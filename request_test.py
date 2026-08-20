from endpoint_tester import test_endpoint


result = test_endpoint(
    url="https://juice-shop-security-assessment.onrender.com/api/Quantitys",
    method="GET"
)

print("STATUS:", result["status_code"])
print("BODY:")
print(result["body"])