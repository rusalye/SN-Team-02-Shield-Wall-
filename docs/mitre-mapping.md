# ATT&CK mapping

| Behavior | Technique | Defensive evidence |
|---|---|---|
| Exploit attempt against public-facing app | T1190 | ModSecurity/CRS or custom virtual-patch event |
| Automated scanner identification | T1595.002 | Scanner user-agent rule |
| Login brute-force burst | T1110 | Nginx rate-limit responses and authentication test evidence |

Mappings describe simulated behavior; do not claim technique attribution from a user-agent string alone.
