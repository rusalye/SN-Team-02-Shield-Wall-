import os


def _s(key, default):
    return os.getenv(key, default)


def _f(key, default):
    return float(os.getenv(key, default))


MODE = _s("SHIELD_MODE", "on").lower()              # on | detect | off
AUDIT_LOG = _s("AUDIT_LOG", "/var/log/shield/modsec_audit.json")
ACCESS_LOG = _s("ACCESS_LOG", "/var/log/shield/access.json")
BLOCKLIST = _s("BLOCKLIST", "/etc/nginx/dynamic/blocklist.conf")
DB_PATH = _s("DB_PATH", "/data/sentinel.db")
PORT = int(_s("PORT", "9000"))
TOKEN = _s("SENTINEL_TOKEN", "")

BAN_STRIKES = _f("BAN_STRIKES", "20")               # weighted strikes inside the window -> ban
STRIKE_WINDOW = _f("STRIKE_WINDOW", "120")          # seconds
BAN_STEPS = [int(x) for x in _s("BAN_STEPS", "300,1800,86400").split(",") if x.strip()]
ALLOWLIST = {x.strip() for x in _s("ALLOWLIST", "127.0.0.1,::1").split(",") if x.strip()}

LOGIN_PATHS = ("/rest/user/login", "/rest/user/reset-password")
