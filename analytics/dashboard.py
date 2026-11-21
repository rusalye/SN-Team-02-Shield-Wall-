import json, os
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Shield Wall | Security Operations", page_icon="🛡️", layout="wide")
st.title("🛡️ SHIELD WALL")
st.caption("Web Application Defense & Explainable Security Analytics")

event_file = Path(os.getenv("EVENT_FILE", "/data/events.jsonl"))
events = []
if event_file.exists():
    for line in event_file.read_text(errors="ignore").splitlines():
        try: events.append(json.loads(line))
        except json.JSONDecodeError: pass

df = pd.DataFrame(events)
if df.empty:
    st.info("No normalized events yet. Run the replay scripts and ingest WAF audit events.")
    st.metric("Normalized events", 0)
    st.stop()

for col in ["category", "action", "source_ip", "timestamp", "path", "rule_id", "mitre"]:
    if col not in df: df[col] = "unknown"

total = len(df)
blocked = int((df["action"].astype(str).str.lower() == "blocked").sum())
c1,c2,c3,c4 = st.columns(4)
c1.metric("Events observed", total)
c2.metric("Blocked events", blocked)
c3.metric("Unique sources", df["source_ip"].nunique())
c4.metric("Attack categories", df["category"].nunique())

left,right = st.columns(2)
with left:
    st.subheader("Events by attack category")
    st.bar_chart(df["category"].value_counts())
with right:
    st.subheader("Enforcement actions")
    st.bar_chart(df["action"].value_counts())

st.subheader("Incident timeline")
if "timestamp" in df:
    timeline = df.copy()
    timeline["timestamp"] = pd.to_datetime(timeline["timestamp"], errors="coerce")
    timeline = timeline.dropna(subset=["timestamp"]).set_index("timestamp")
    if not timeline.empty: st.line_chart(timeline.resample("1min").size())

st.subheader("Explainable security events")
st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)
st.download_button("Export normalized events", df.to_csv(index=False), "shieldwall-events.csv", "text/csv")
