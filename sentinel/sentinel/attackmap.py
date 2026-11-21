"""Maps OWASP CRS / ShieldWall rules to attack classes, MITRE ATT&CK, CWE and CAPEC."""

TYPES = {
    "honeypot":          dict(label="Honeypot / decoy probe",    attack=["T1595.003"],          cwe="CWE-200", capec="CAPEC-169"),
    "virtual-patch":     dict(label="Virtual patch hit",         attack=["T1190"],              cwe="CWE-693", capec=""),
    "command-injection": dict(label="OS command injection",      attack=["T1190", "T1059"],     cwe="CWE-78",  capec="CAPEC-88"),
    "sqli":              dict(label="SQL injection",             attack=["T1190"],              cwe="CWE-89",  capec="CAPEC-66"),
    "xss":               dict(label="Cross-site scripting",      attack=["T1190"],              cwe="CWE-79",  capec="CAPEC-63"),
    "path-traversal":    dict(label="Path traversal / LFI",      attack=["T1190"],              cwe="CWE-22",  capec="CAPEC-126"),
    "code-injection":    dict(label="Code / NoSQL injection",    attack=["T1190"],              cwe="CWE-94",  capec="CAPEC-242"),
    "rfi":               dict(label="Remote file inclusion",     attack=["T1190"],              cwe="CWE-98",  capec="CAPEC-193"),
    "scanner":           dict(label="Scanner / automated tool",  attack=["T1595.002"],          cwe="",        capec="CAPEC-310"),
    "brute-force":       dict(label="Login brute force",         attack=["T1110"],              cwe="CWE-307", capec="CAPEC-49"),
    "rate-limit":        dict(label="Rate limit exceeded",       attack=["T1498"],              cwe="CWE-770", capec=""),
    "session-fixation":  dict(label="Session fixation",          attack=["T1190"],              cwe="CWE-384", capec="CAPEC-61"),
    "protocol-anomaly":  dict(label="HTTP protocol anomaly",     attack=["T1190"],              cwe="CWE-444", capec=""),
    "other":             dict(label="Other",                     attack=["T1190"],              cwe="",        capec=""),
}
PRIORITY = list(TYPES)

# CRS rule files are numbered by attack family.
ID_PREFIX = {
    "913": "scanner", "920": "protocol-anomaly", "921": "protocol-anomaly",
    "930": "path-traversal", "931": "rfi", "932": "command-injection",
    "933": "code-injection", "934": "code-injection", "941": "xss",
    "942": "sqli", "943": "session-fixation", "944": "code-injection",
}
EVALUATION_PREFIXES = ("949", "959", "980", "901", "905")   # blocking-evaluation rules, not attacks
SEV_POINTS = {0: 5, 1: 5, 2: 5, 3: 4, 4: 3, 5: 2, 6: 1, 7: 1}


def info(attack_type):
    return TYPES.get(attack_type, TYPES["other"])


def classify(rules):
    """rules: [{id, sev, tags, text}] -> (primary_type, all_types, techniques, points)."""
    pts = {}
    for r in rules:
        rid = r["id"]
        if rid.startswith(EVALUATION_PREFIXES):
            continue
        tags = r.get("tags") or []
        if "shieldwall/honeypot" in tags:
            t, bonus = "honeypot", 100
        elif "shieldwall/vpatch" in tags:
            t, bonus = "virtual-patch", 100
        else:
            t, bonus = ID_PREFIX.get(rid[:3]), 0
        if t:
            pts[t] = pts.get(t, 0) + SEV_POINTS.get(r.get("sev", 5), 2) + bonus
    if not pts:
        return "other", [], [], 0
    primary = max(pts, key=lambda k: (pts[k], -PRIORITY.index(k)))
    techniques = sorted({t for k in pts for t in TYPES[k]["attack"]})
    return primary, sorted(pts), techniques, sum(pts.values())
