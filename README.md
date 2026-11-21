# ShieldWall: protecting a public-facing app at the network edge (PS6)

Quickstart (Docker + Docker Compose v2, Linux/macOS/WSL2):

    make up        # generates a lab CA + cert, builds and starts juiceshop, waf, sentinel
    make demo      # baseline (WAF off) -> protected run -> reports in ./reports
    make benign    # 28 normal requests, must be >=95% allowed
    make attack    # attack replay, must be 100% blocked (exit code 1 otherwise)
    make fp        # which CRS rules blocked the benign client (tuning helper)
    make mode-detect | mode-on | mode-off

Endpoints: app https://localhost:8443 (via WAF only), dashboard http://127.0.0.1:9000.
Full documentation and deliverables are written in the next phase.
