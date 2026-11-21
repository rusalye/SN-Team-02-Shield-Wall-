# Shield Wall — Technical Report

## Executive summary
Describe the legacy-app edge protection objective and tested deployment.

## Architecture
Insert the network diagram and explain trust boundaries.

## Implementation
- Nginx TLS termination
- ModSecurity v3 + OWASP CRS
- Custom virtual patch rules
- Login rate limiting
- Centralized event handling and dashboard

## Validation results
| Attack class | Requests | Blocked | Evidence |
|---|---:|---:|---|
| SQL injection | | | |
| XSS | | | |
| Path traversal | | | |
| Command injection | | | |
| Scanner User-Agent | | | |
| Login brute force | | | |

## Benign traffic
Requests:  
Allowed:  
Pass rate:  

## False-positive tuning
Document each excluded rule, exact path/parameter scope, reason, and regression test.

## ATT&CK mapping
T1190, T1595.002, T1110.

## Limitations and future work
Document tested limitations and distinguish implemented capabilities from planned enhancements.
