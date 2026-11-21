# 5–7 minute judge demonstration

1. Show the architecture and explain that Juice Shop is isolated behind the gateway.
2. Open the application through HTTPS.
3. Run the benign replay; show >=20 requests and calculate pass rate.
4. Run the six-category attack replay; show status codes and WAF audit events.
5. Run the login burst; demonstrate 429 responses from the rate limiter.
6. Open the dashboard and explain the event schema, attack categories and MITRE mappings.
7. Export the acceptance summary and show the tuning/evidence directory.
8. State limitations honestly: rate limiting is IP/request based, and raw audit parsing needs validation for the pinned image.

Never claim a test passed if its recorded status does not show the expected enforcement result.
