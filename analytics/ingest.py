"""Normalize structured replay results into JSONL for the dashboard."""
import json, os, sys
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(os.getenv("EVENT_FILE", "data/events.jsonl"))
OUT.parent.mkdir(parents=True, exist_ok=True)

def write_event(event):
    base = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "127.0.0.1",
        "action": "observed",
        "category": "unknown",
        "path": "",
        "rule_id": "",
        "mitre": "",
        "explanation": ""
    }
    base.update(event)
    with OUT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(base) + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python ingest.py event.json")
    payload = json.loads(Path(sys.argv[1]).read_text())
    for event in payload if isinstance(payload, list) else [payload]:
        write_event(event)
