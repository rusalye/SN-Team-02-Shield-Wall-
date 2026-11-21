"""ShieldWall Attack Console (Streamlit): pick attacks, fire them at the WAF-protected app, watch Sentinel react."""
import time

import pandas as pd
import streamlit as st

import lab

st.set_page_config(page_title="ShieldWall Attack Console", layout="wide")
ITEMS = lab.catalog()
CLASSES = list(lab.LAYER)

# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.header("ShieldWall")
    s = lab.sentinel_get("/api/summary")
    mode = s["mode"] if s else "unknown"
    st.metric("Protection mode", {"on": "BLOCKING", "detect": "DETECT ONLY", "off": "WAF OFF"}.get(mode, mode.upper()))
    st.caption("Change mode from a terminal: `make mode-on | mode-detect | mode-off`")
    st.caption(f"Target: `{lab.BASE}` (own lab only)")
    if st.button("Unban all sources", use_container_width=True):
        st.toast("Bans cleared" if lab.sentinel_unban() else "Sentinel unreachable")
    st.divider()
    st.caption("Tip: lower the delay to see an auto-ban trigger mid-run, raise it to narrate each request.")

tab_lab, tab_live, tab_about = st.tabs(["Attack lab", "Live defense view", "How it works"])

# ------------------------------------------------------------------ attack lab
with tab_lab:
    st.subheader("1. Choose attacks")
    c1, c2 = st.columns([1, 3])
    select_all = c1.checkbox("Select all attacks", value=True)
    chosen = CLASSES if select_all else c2.multiselect("Attack classes", CLASSES, default=["SQL injection"])
    rows = pd.DataFrame([dict(Run=True, Class=i["cls"], Attack=i["name"], id=i["id"]) for i in ITEMS if i["cls"] in chosen])
    edited = st.data_editor(rows, hide_index=True, use_container_width=True, disabled=["Class", "Attack", "id"],
                            column_config={"id": None}, key="picker_" + "|".join(chosen))
    o1, o2 = st.columns(2)
    attempts = o1.slider("Brute-force attempts", 10, 60, 40, disabled="Brute force" not in chosen)
    delay = o2.slider("Pause between requests (seconds)", 0.0, 2.0, 0.3, 0.1)

    st.subheader("2. Fire")
    if st.button("Run selected attacks", type="primary", disabled=edited.empty):
        picked = [i for i in ITEMS if i["id"] in set(edited[edited.Run]["id"])]
        sess = lab.session("ShieldWall-Console/1.0")
        out, bar, table = [], st.progress(0.0), st.empty()
        for n, item in enumerate(picked, 1):
            out.append(lab.run_item(sess, item, attempts))
            table.dataframe(pd.DataFrame(out), hide_index=True, use_container_width=True)
            bar.progress(n / len(picked), text=f"{n}/{len(picked)}: {item['name']}")
            time.sleep(delay)
        res = pd.DataFrame(out)
        blocked = int((res.Verdict == "BLOCKED").sum())
        m = st.columns(4)
        m[0].metric("Blocked", f"{blocked}/{len(res)}")
        m[1].metric("Exploits that worked", int((res.Exploited == "YES").sum()))
        m[2].metric("Attacker auto-banned", "yes" if lab.ban_active(sess) else "no")
        m[3].metric("Mode", mode)
        st.download_button("Download results (CSV)", res.to_csv(index=False), "console_results.csv", "text/csv")

    with st.expander("Craft your own request (reviewer input)"):
        a, b = st.columns([1, 4])
        method = a.selectbox("Method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
        path = b.text_input("Path", "/rest/products/search")
        p1, p2 = st.columns(2)
        pname, pval = p1.text_input("Query parameter", "q"), p2.text_input("Value", "' OR 1=1--")
        body = st.text_area("JSON body (optional)", "")
        ua = st.text_input("User-Agent (optional)", "")
        if st.button("Send request"):
            r = lab.custom_request(lab.session("ShieldWall-Console/1.0"), method, path, {pname: pval} if pname else None, body, ua or None)
            if "error" in r:
                st.error(r["error"])
            else:
                (st.success if not r["blocked"] else st.warning)(f"HTTP {r['status']}  |  X-Shield-Action: {r['action']}  |  {r['ms']} ms")
                st.code(r["body"])

# ------------------------------------------------------------------ live view
@st.fragment(run_every=3)
def live():
    s = lab.sentinel_get("/api/summary")
    if not s:
        st.warning("Sentinel is not reachable.")
        return
    t = s["totals"]
    k = st.columns(5)
    for col, (label, val) in zip(k, [("Requests", t["requests"]), ("Blocked at edge", t["blocked"]), ("Attack events", t["events"]),
                                     ("Active bans", t["active_bans"]), ("Mode", s["mode"])]):
        col.metric(label, val)
    l, r = st.columns(2)
    if s["by_type"]:
        l.caption("Events by attack type")
        l.bar_chart(pd.DataFrame(s["by_type"]).set_index("label")["count"])
    tl = pd.DataFrame(s["timeline"])
    r.caption("Requests per minute (total vs blocked)")
    r.line_chart(tl.assign(time=pd.to_datetime(tl.t, unit="s")).set_index("time")[["total", "blocked"]])
    st.caption("ATT&CK techniques observed: " + (", ".join(f"{x['id']} x{x['count']}" for x in s["techniques"]) or "none yet"))
    if s["bans"]:
        st.caption("Active bans")
        st.dataframe(pd.DataFrame(s["bans"])[["ip", "offenses", "reason"]], hide_index=True, use_container_width=True)
    ev = lab.sentinel_get("/api/events?limit=25") or []
    if ev:
        st.caption("Latest events")
        df = pd.DataFrame(ev)
        df["time"] = pd.to_datetime(df.ts, unit="s").dt.strftime("%H:%M:%S")
        df["rules"] = df.rules.map(lambda x: ", ".join(x[:3]))
        st.dataframe(df[["time", "ip", "method", "uri", "ptype", "rules", "score", "action"]], hide_index=True, use_container_width=True)


with tab_live:
    live()

# ------------------------------------------------------------------ explanation
with tab_about:
    st.markdown("""
**Request path:** client → nginx (TLS 1.2/1.3, ban check) → ModSecurity v3 + OWASP CRS (PL2) → rate limit → Juice Shop on an internal network.
**Feedback loop:** WAF logs → Sentinel scores strikes per source → escalating bans (5 min, 30 min, 24 h) → nginx blocklist reload, with no Docker socket.""")
    st.dataframe(pd.DataFrame([dict(Class=k, Control=v[0], ATTCK=v[1]) for k, v in lab.LAYER.items()]), hide_index=True, use_container_width=True)
    st.caption("Attack payloads come from `lab/tests/attack_replay.py`, the same catalog `make attack` uses.")
