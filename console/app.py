
"""ShieldWall Attack Console."""
import time

import pandas as pd
import streamlit as st

import lab

st.set_page_config(
    page_title="ShieldWall Attack Console",
    page_icon="🛡️",
    layout="wide",
)

ITEMS = lab.catalog()
CLASSES = list(lab.LAYER)

# ------------------------------------------------------------------ styling
st.markdown("""

<style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1500px;
    }

    [data-testid="stAppViewContainer"] {
        background: #f3f6fa;
        color: #172b45;
    }

    [data-testid="stHeader"] {
        background: #f3f6fa;
    }

    [data-testid="stSidebar"] {
        background: #ffffff;
        border-right: 1px solid #dce4ee;
    }

    [data-testid="stSidebar"] * {
        color: #23364f;
    }

    h1, h2, h3, p, label {
        color: #172b45;
    }

    [data-testid="stMarkdownContainer"] p {
        color: #42546b;
    }

    .hero {
        padding: 25px 30px;
        border: 1px solid #d5e1ef;
        border-radius: 15px;
        background: linear-gradient(110deg, #ffffff, #eaf2fb);
        margin-bottom: 22px;
        box-shadow: 0 3px 12px rgba(30, 55, 85, 0.05);
    }

    .hero-kicker {
        color: #2477bd;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 2px;
        text-transform: uppercase;
    }

    .hero-title {
        color: #142b49;
        font-size: 2rem;
        font-weight: 800;
        margin: 5px 0;
    }

    .hero-sub {
        color: #52657c;
        font-size: 0.95rem;
    }

    .section-card {
        border: 1px solid #d8e2ed;
        border-radius: 13px;
        padding: 18px 20px;
        background: #ffffff;
        margin: 8px 0 18px 0;
        box-shadow: 0 2px 8px rgba(30, 55, 85, 0.04);
    }

    .mode-note {
        color: #52657c;
        font-size: 0.88rem;
        padding: 8px 0 2px 0;
    }

    div[data-testid="stMetric"] {
        background: #ffffff;
        border: 1px solid #d8e2ed;
        border-radius: 11px;
        padding: 14px;
    }

    div[data-testid="stMetricLabel"] {
        color: #52657c;
    }

    div[data-testid="stMetricValue"] {
        color: #173454;
    }

    div.stButton > button[kind="primary"] {
        min-height: 46px;
        border-radius: 9px;
        font-weight: 700;
        color: white;
        border: 1px solid #d83e43;
        background: linear-gradient(100deg, #dc4148, #f05252);
    }

    div.stButton > button[kind="primary"]:hover {
        background: #c9323b;
        border-color: #c9323b;
        color: white;
    }

    div.stButton > button {
        border-radius: 9px;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #d8e2ed;
        border-radius: 10px;
        overflow: hidden;
        background: white;
    }

    input, textarea {
        color: #172b45 !important;
    }
</style>

""", unsafe_allow_html=True)

# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.markdown("## 🛡️ ShieldWall")
    st.caption("SECURITY OPERATIONS CONSOLE")
    s = lab.sentinel_get("/api/summary")
    mode = s["mode"] if s else "unknown"

    mode_label = {
        "on": "🟢 BLOCKING",
        "detect": "🟡 DETECT ONLY",
        "off": "🔴 WAF OFF",
    }.get(mode, mode.upper())

    st.metric("Protection mode", mode_label)
    st.caption("Change mode from terminal:")
    st.code("make mode-on\nmake mode-detect\nmake mode-off", language="bash")
    st.divider()
    st.caption(f"Target: `{lab.BASE}`")
    st.caption("Authorized local lab traffic only.")

    if st.button("Unban all sources", use_container_width=True):
        st.toast(
            "Bans cleared" if lab.sentinel_unban()
            else "Sentinel unreachable"
        )

    st.divider()
    st.caption("Tip: use a short delay for fast replay or increase it for a narrated demo.")

# ------------------------------------------------------------------ header
st.markdown("""
<div class="hero">
    <div class="hero-kicker">Network security testing environment</div>
    <div class="hero-title">ShieldWall Attack Console</div>
    <div class="hero-sub">
        Simulate malicious and legitimate application traffic.
        Observe WAF decisions and Sentinel's automated response.
    </div>
</div>
""", unsafe_allow_html=True)

tab_lab, tab_live, tab_about = st.tabs(
    ["⚡ Attack Lab", "📡 Live Defense View", "ⓘ How It Works"]
)

# ------------------------------------------------------------------ attack lab
with tab_lab:
    st.subheader("Traffic Simulation")
    st.caption("Choose the type of traffic you want to send through ShieldWall.")

    st.markdown("### Select traffic to generate")

    tc1, tc2 = st.columns(2)

    with tc1:
        run_attacks = st.checkbox(
            "🔴 Attack simulation",
            value=True,
            key="run_attacks",
        )

    with tc2:
        run_benign = st.checkbox(
            "🟢 Benign traffic",
            value=False,
            key="run_benign",
        )

    if not run_attacks and not run_benign:
        st.info("Select at least one traffic type to continue.")


    attack_picked = []
    attack_attempts = 40
    attack_delay = 0.3
    benign_count = 50
    benign_delay = 0.1

    # -------------------------------------------------- attack configuration
    if run_attacks:
        st.markdown("""
        <div class="section-card">
            <b>🔴 Attack simulation</b>
            <div class="mode-note">
                Choose malicious scenarios to test WAF detection,
                blocking and automated response.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.subheader("1. Choose attacks")

        c1, c2 = st.columns([1, 3])
        select_all = c1.checkbox("Select all attacks", value=True, key="all_attacks")

        chosen = (
            CLASSES if select_all
            else c2.multiselect(
                "Attack classes",
                CLASSES,
                default=["SQL injection"],
                key="attack_classes",
            )
        )

        rows = pd.DataFrame([
            dict(Run=True, Class=i["cls"], Attack=i["name"], id=i["id"])
            for i in ITEMS if i["cls"] in chosen
        ])

        edited = st.data_editor(
            rows,
            hide_index=True,
            use_container_width=True,
            disabled=["Class", "Attack", "id"],
            column_config={"id": None},
            key="attack_picker_" + "|".join(chosen),
        )

        o1, o2 = st.columns(2)
        attack_attempts = o1.slider(
            "Brute-force attempts",
            10, 60, 40,
            disabled="Brute force" not in chosen,
            key="attack_attempts",
        )
        attack_delay = o2.slider(
            "Pause between attacks (seconds)",
            0.0, 2.0, 0.3, 0.1,
            key="attack_delay",
        )

        attack_picked = [
            i for i in ITEMS
            if i["id"] in set(edited[edited.Run]["id"])
        ]

    # -------------------------------------------------- benign configuration
    if run_benign:
        st.markdown("""
        <div class="section-card">
            <b>🟢 Benign traffic simulation</b>
            <div class="mode-note">
                Generate normal application traffic to measure legitimate
                request handling and identify false positives.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.subheader("Benign traffic configuration")

        bc1, bc2 = st.columns([2, 1])

        with bc1:
            benign_count = st.slider(
                "Number of benign requests",
                1, 200, 50,
                key="benign_count",
            )

            benign_delay = st.slider(
                "Pause between requests (seconds)",
                0.0, 1.0, 0.1, 0.1,
                key="benign_delay",
            )

        with bc2:
            st.metric("Requests to send", benign_count)
            st.metric(
                "Estimated delay",
                f"{max(0, benign_count - 1) * benign_delay:.1f}s",
            )

        st.caption(
            "Includes normal browsing, product searches, catalogue access "
            "and other read-only application requests."
        )

    # -------------------------------------------------- combined execution
    st.divider()
    st.subheader("2. Fire selected traffic")

    can_run = (
        (run_attacks and len(attack_picked) > 0)
        or run_benign
    )

    if st.button(
        "⚡ Run selected traffic",
        type="primary",
        use_container_width=True,
        disabled=not can_run,
    ):
        sess = lab.session("ShieldWall-Console/1.0")
        attack_results = []
        benign_results = []

        total_steps = (
            (len(attack_picked) if run_attacks else 0)
            + (benign_count if run_benign else 0)
        )

        progress = st.progress(0.0)
        result_table = st.empty()
        status = st.empty()
        completed = 0

        # Then run benign requests
        if run_benign:
            for result in lab.run_benign(sess, benign_count):
                benign_results.append(result)

                completed += 1
                progress.progress(
                    completed / total_steps,
                    text=f"Benign request {completed - len(attack_results)} "
                         f"of {benign_count}",
                )
                result_table.dataframe(
                    pd.DataFrame(attack_results + benign_results),
                    hide_index=True,
                    use_container_width=True,
                )
                status.caption(
                    f"{result['Endpoint']} | HTTP {result['Status']} | "
                    f"{result['Verdict']}"
                )
                if benign_delay and len(benign_results) < benign_count:
                    time.sleep(benign_delay)

        # Run attacks first
        if run_attacks:
            for item in attack_picked:
                result = lab.run_item(sess, item, attack_attempts)
                attack_results.append(result)

                completed += 1
                progress.progress(
                    completed / total_steps,
                    text=f"Attack: {item['name']}",
                )
                result_table.dataframe(
                    pd.DataFrame(attack_results + benign_results),
                    hide_index=True,
                    use_container_width=True,
                )
                if attack_delay:
                    time.sleep(attack_delay)


        # Results
        st.subheader("3. Simulation results")

        if attack_results:
            attack_df = pd.DataFrame(attack_results)
            blocked = int((attack_df.Verdict == "BLOCKED").sum())
            exploited = int((attack_df.Exploited == "YES").sum())

            a = st.columns(3)
            a[0].metric("Attack scenarios", len(attack_df))
            a[1].metric("Blocked attacks", blocked)
            a[2].metric("Successful exploits", exploited)

        if benign_results:
            benign_df = pd.DataFrame(benign_results)
            allowed = int((benign_df.Verdict == "ALLOWED").sum())
            blocked = int((benign_df.Verdict == "BLOCKED").sum())
            failed = int((benign_df.Verdict == "FAILED").sum())
            pct = 100 * allowed / len(benign_df)

            b = st.columns(4)
            b[0].metric("Benign requests", len(benign_df))
            b[1].metric("Allowed", allowed)
            b[2].metric("Blocked", blocked)
            b[3].metric("Failed", failed)

            st.metric("Benign traffic pass rate", f"{pct:.1f}%")

            if pct >= 95:
                st.success("Benign traffic meets the 95% pass-rate target.")
            else:
                st.warning("Benign traffic is below the 95% pass-rate target.")

        if attack_results:
            st.download_button(
                "⬇️ Download attack results",
                pd.DataFrame(attack_results).to_csv(index=False),
                "shieldwall_attack_results.csv",
                "text/csv",
            )

        if benign_results:
            st.download_button(
                "⬇️ Download benign results",
                pd.DataFrame(benign_results).to_csv(index=False),
                "shieldwall_benign_results.csv",
                "text/csv",
            )

        if attack_results and benign_results:
            combined = pd.concat(
                [
                    pd.DataFrame(attack_results).assign(Traffic="Attack"),
                    pd.DataFrame(benign_results).assign(Traffic="Benign"),
                ],
                ignore_index=True,
                sort=False,
            )

            st.download_button(
                "⬇️ Download combined results",
                combined.to_csv(index=False),
                "shieldwall_combined_results.csv",
                "text/csv",
            )git status

    # ---------------------------------------------------------- custom request
    with st.expander("🧪 Craft your own request (reviewer input)"):
        a, b = st.columns([1, 4])
        method = a.selectbox(
            "Method",
            ["GET", "POST", "PUT", "PATCH", "DELETE"],
        )
        path = b.text_input("Path", "/rest/products/search")
        p1, p2 = st.columns(2)
        pname = p1.text_input("Query parameter", "q")
        pval = p2.text_input("Value", "' OR 1=1--")
        body = st.text_area("JSON body (optional)", "")
        ua = st.text_input("User-Agent (optional)", "")

        if st.button("Send custom request"):
            r = lab.custom_request(
                lab.session("ShieldWall-Console/1.0"),
                method,
                path,
                {pname: pval} if pname else None,
                body,
                ua or None,
            )
            if "error" in r:
                st.error(r["error"])
            else:
                (st.warning if r["blocked"] else st.success)(
                    f"HTTP {r['status']} | "
                    f"X-Shield-Action: {r['action']} | {r['ms']} ms"
                )
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
    metrics = [
        ("Requests", t["requests"]),
        ("Blocked at edge", t["blocked"]),
        ("Attack events", t["events"]),
        ("Active bans", t["active_bans"]),
        ("Mode", s["mode"]),
    ]
    for col, (label, val) in zip(k, metrics):
        col.metric(label, val)

    l, r = st.columns(2)
    if s["by_type"]:
        l.caption("Events by attack type")
        l.bar_chart(
            pd.DataFrame(s["by_type"]).set_index("label")["count"]
        )

    tl = pd.DataFrame(s["timeline"])
    r.caption("Requests per minute (total vs blocked)")
    if not tl.empty:
        r.line_chart(
            tl.assign(time=pd.to_datetime(tl.t, unit="s"))
            .set_index("time")[["total", "blocked"]]
        )

    st.caption(
        "ATT&CK techniques observed: "
        + (
            ", ".join(
                f"{x['id']} x{x['count']}" for x in s["techniques"]
            )
            or "none yet"
        )
    )

    if s["bans"]:
        st.caption("Active bans")
        st.dataframe(
            pd.DataFrame(s["bans"])[["ip", "offenses", "reason"]],
            hide_index=True,
            use_container_width=True,
        )

    ev = lab.sentinel_get("/api/events?limit=25") or []
    if ev:
        st.caption("Latest events")
        df = pd.DataFrame(ev)
        df["time"] = pd.to_datetime(
            df.ts, unit="s"
        ).dt.strftime("%H:%M:%S")
        df["rules"] = df.rules.map(lambda x: ", ".join(x[:3]))
        st.dataframe(
            df[[
                "time", "ip", "method", "uri",
                "ptype", "rules", "score", "action",
            ]],
            hide_index=True,
            use_container_width=True,
        )


with tab_live:
    live()

# ------------------------------------------------------------------ explanation
with tab_about:
    st.markdown("""
**Request path:** client → nginx (TLS 1.2/1.3, ban check) → ModSecurity
v3 + OWASP CRS (PL2) → rate limit → Juice Shop on an internal network.

**Feedback loop:** WAF logs → Sentinel scores strikes per source →
escalating bans (5 min, 30 min, 24 h) → nginx blocklist reload,
with no Docker socket.
""")
    st.dataframe(
        pd.DataFrame([
            dict(Class=k, Control=v[0], ATTCK=v[1])
            for k, v in lab.LAYER.items()
        ]),
        hide_index=True,
        use_container_width=True,
    )
    st.caption(
        "Attack payloads come from `lab/tests/attack_replay.py`, "
        "the same catalog `make attack` uses."
    )
