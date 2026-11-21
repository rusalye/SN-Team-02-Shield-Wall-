# Architecture and design decisions

## Request path
Client -> TLS listener on Nginx -> ModSecurity v3 -> OWASP CRS + Shield Wall custom rules -> Juice Shop.

The backend is attached only to the internal Docker network. The host publishes the WAF TLS port, not the application port.

## Control plane
WAF audit/access logs are retained under `logs/waf`. The analytics dashboard consumes normalized JSONL events. Replay scripts produce deterministic CSV evidence. A deployment-specific ModSecurity audit parser should convert audit records to the common event schema before the live dashboard claims real-time WAF analytics.

## Why CRS rather than a homemade WAF?
CRS provides maintained generic detection for common web attacks. Custom rules are used only for focused virtual patches and demo-specific detections. This reduces the risk of relying on brittle regex-only protection.

## Why Streamlit rather than React?
The hackathon's primary scoring is security behavior and evidence, not frontend engineering. Streamlit gives a usable analyst dashboard with less code and fewer moving parts.

## Known trade-offs
- ModSecurity IP-collection login controls count POST requests to the login endpoint, not verified failed-password responses. It can affect legitimate shared clients.
- IP-based controls can affect multiple users behind NAT.
- Juice Shop does not expose a native, dedicated command-execution endpoint for every desired test category. The team must verify that a test request triggers the intended WAF rule, not merely a generic 404.
- A self-signed certificate is suitable only for a local demonstration.
