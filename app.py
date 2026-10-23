"""Operation Quiet Ledger: intelligence-led AI security tabletop.

Participants: open the join link (?s=<session code>), read the briefing, answer each situation.
Facilitator: open ?admin and enter ADMIN_PASSWORD for the MSEL, gap analysis, framework views,
the after-action report and the technology annex.

Two exercise modes, defined in tracks.py: the technical track (16 situations, one room) and
the full engagement (16 technical plus 7 executive crisis decisions, two rooms).
"""
import hmac
import html
import io
from urllib.parse import urlencode, urlsplit, urlunsplit

import altair as alt
import pandas as pd
import qrcode
import streamlit as st

import portfolio
import store
import threat
from content import (AGENTS, ALL_BY_ID, ALL_MODULES, ARCH_DOT, BY_ID, CAP_ORDER, CAPS, CISCO,
                     DETECT, FIRST, GROUND_RULES, INJECT_IDS, INJECTS, MODULES, NOT_EXERCISED,
                     OBS, OWNER, ROLES, SCENARIO, SOURCES, SUBTITLE, SYSTEM, TITLE, cap_order,
                     caps_map, decide_label, decide_map, first_label, first_map, injects_for,
                     kind_for_role, roles_for)
from exec_track import ESCALATION_COUPLING, EXEC_CAPS, REGULATORY_CLOCKS
from frameworks import CATALOGUES, FRAMEWORK_ORDER, FRAMEWORKS
from mappings import OBJECTIVE_ORDER, OBJECTIVES
from scoring import (HOTWASH, LEVEL_WORD, MATURITY, SEVERITY_ORDER, aggregate, findings, level,
                     maturity_of, maturity_word, roadmap, sample_answers)
from tracks import TRACK_ORDER, TRACKS, plays_executive, track_def

st.set_page_config(page_title=TITLE, page_icon=":material/shield:", layout="centered")

COLORS = {"good": "#1D8A57", "warn": "#B57A06", "crit": "#C23D2C", "na": "#98A4B1"}
SOFT = {"good": "#DDF2E7", "warn": "#FBEFD3", "crit": "#F9E1DD", "na": "#ECEFF2"}

st.html("""<style>
h1,h2,h3{font-family:'Archivo','Source Sans Pro',sans-serif;letter-spacing:-.01em}
.ql-tag{font:500 .78rem ui-monospace,Menlo,monospace;color:#566576;letter-spacing:.06em;text-transform:uppercase}
.block-container{padding-top:2.2rem}
</style>""")


def esc(s):
    return html.escape(str(s), quote=True)


def pct(v):
    return "–" if v is None or pd.isna(v) else f"{round(v)}%"


SEV_COLOR = {"Critical": "red", "High": "red", "Medium": "orange", "Low": "blue", "Strength": "green"}
LEVEL_COLOR = {"good": "green", "warn": "orange", "crit": "red", "na": "gray"}


def play_injects(sess, kind=None):
    """The injects this session plays, optionally narrowed to one participant's kind."""
    return injects_for(sess.get("track", "technical"), kind)


def play_ids(sess, kind=None):
    return [i["id"] for i in play_injects(sess, kind)]


def badge(lv, value):
    return f":{LEVEL_COLOR[lv]}-badge[{LEVEL_WORD[lv]} · {pct(value)}]"


def maturity_badge(m):
    if not m:
        return ":gray-badge[Not assessed]"
    color = "red" if m <= 2 else "orange" if m == 3 else "green"
    return f":{color}-badge[L{m} {maturity_word(m)}]"


# =====================================================================
# Participant side
# =====================================================================
def track_card(track, compact=False):
    t = track_def(track)
    with st.container(border=True):
        st.markdown(f"**{t['name']}** · {t['tagline']}")
        st.write(t["what_it_is"])
        if compact:
            return
        a, b = st.columns(2)
        with a:
            st.markdown("**Who is in the room**")
            st.caption(t["who"])
            st.markdown("**Duration**")
            st.caption(t["duration"])
            st.markdown("**The question it answers**")
            st.caption(t["answers_the_question"])
        with b:
            st.markdown("**What you get out of it**")
            for o in t["outcome"]:
                st.caption(f"• {o}")
        st.markdown("**What it proves** — " + t["proves"])
        st.markdown("**What it cannot prove** — " + t["cannot_prove"])
        with st.expander("Explicitly out of scope"):
            for d in t["does_not_cover"]:
                st.caption(f"• {d}")


def intel_briefing():
    a = threat.ACTOR
    st.markdown("#### Threat intelligence")
    st.warning(f"**{a['designation']}** ({a['nickname']}) is a fictional cluster created for this exercise. "
               "Its tradecraft is drawn from publicly reported financially motivated intrusion activity and "
               "published agentic-attack research. It is not an alias for any real tracked group, and the "
               "indicators are synthetic.", icon=":material/info:")
    st.markdown(f"**Classification** — {a['classification']}")
    st.markdown(f"**Motivation** — {a['motivation']}")
    st.markdown(f"**Targeting** — {a['targeting']}")
    st.markdown(f"**Assessed sophistication** — {a['sophistication']}")
    st.caption(f"Scenario confidence: {a['confidence']}")
    st.markdown("**Tradecraft this exercise is built on**")
    st.dataframe(pd.DataFrame(threat.TRADECRAFT, columns=["Pattern", "Why it matters here"]),
                 hide_index=True, width="stretch")
    st.markdown("**Exercise assumptions**")
    for x in threat.ASSUMPTIONS:
        st.markdown(f"- {x}")


def briefing(sess=None, full=True):
    track = (sess or {}).get("track", "technical")
    st.markdown("#### How this exercise runs")
    track_card(track, compact=not full)
    st.markdown("#### Ground rules")
    for i, r in enumerate(GROUND_RULES, 1):
        st.markdown(f"{i}. {r}")
    st.markdown("#### Scenario")
    st.write(SCENARIO)
    if full:
        intel_briefing()
        st.markdown("#### System under test")
        st.write(SYSTEM)
        st.dataframe(pd.DataFrame(AGENTS, columns=["Agent", "Job", "Can act on"]), hide_index=True, width="stretch")
        st.graphviz_chart(ARCH_DOT, width="stretch")
        st.caption("Highlighted boxes are the control points the situations test: the model gateway, the agent registry and intake.")
        st.markdown("#### Attack lifecycle")
        st.write("The situations are one campaign, not sixteen incidents. Each is placed in a phase of the "
                 "Mandiant targeted attack lifecycle, so the room can see how an early miss compounds later.")
        rows = [(threat.LIFECYCLE[p][0], threat.LIFECYCLE[p][1],
                 ", ".join(i["id"] for i in injects_for(track) if i["phase"] == p))
                for p in threat.LIFECYCLE_ORDER
                if any(i["phase"] == p for i in injects_for(track))]
        st.dataframe(pd.DataFrame(rows, columns=["Phase", "Adversary or defender goal", "Situations"]),
                     hide_index=True, width="stretch")
        st.markdown("#### Objectives")
        st.write("Every situation tests one or more exercise objectives. The after-action report scores coverage "
                 "per objective, not just per situation.")
        objs = [(k, OBJECTIVES[k][0], OBJECTIVES[k][1]) for k in OBJECTIVE_ORDER
                if OBJECTIVES[k][2] == "technical" or plays_executive(track)]
        st.dataframe(pd.DataFrame(objs, columns=["ID", "Objective", "What it tests"]),
                     hide_index=True, width="stretch")
        st.markdown("#### Taxonomy and frameworks")
        st.write("Every situation is tagged with Cisco's Integrated AI Security and Safety Framework: 19 attacker "
                 "objectives (OB-001 to OB-019), 40 techniques and 111 subtechniques across the AI lifecycle. "
                 "This exercise touches 15 of the 19 objectives. Findings are additionally expressed in "
                 "MITRE ATT&CK and ATLAS, NIST CSF 2.0, NIST AI RMF with ISO/IEC 42001, and the OWASP LLM "
                 "and Agentic top tens, so each audience reads the same finding in its own language.")


def join_form(code, sess):
    roles = roles_for(sess.get("track", "technical"))
    with st.form("join"):
        st.markdown("#### Join the exercise")
        role = st.selectbox("Your role in this exercise", roles, index=None, placeholder="Choose your role")
        if plays_executive(sess.get("track", "technical")):
            st.caption("Your role decides which situations you see. Technical roles play the 16 technical "
                       "situations; executive roles play the 7 crisis decisions. Observers see the technical set.")
        name = st.text_input("Your name (optional)", max_chars=120)
        org = st.text_input("Your team or organization (optional)", max_chars=160)
        if st.form_submit_button("Start the situations", type="primary"):
            if not role:
                st.error("Choose your role to start.")
                return
            pid = store.add_participant(code, name, role, org)
            st.query_params["p"] = pid
            st.session_state.pid = pid
            st.rerun()


def unlocked(sess, iid):
    if sess["mode"] != "led":
        return True
    ids = play_ids(sess)
    if iid not in ids or sess["current_inject"] not in ids:
        return True
    return ids.index(iid) <= ids.index(sess["current_inject"])


@st.fragment(run_every=4)
def led_watcher(code):
    """Reruns the page when the facilitator moves the exercise on."""
    s = store.get_session(code)
    if not s:
        return
    snap = (s["mode"], s["current_inject"], tuple(s["revealed"]), s["is_open"])
    prev = st.session_state.get("_snap")
    st.session_state._snap = snap
    if prev is not None and prev != snap:
        if s["mode"] == "led" and (prev[1] != snap[1] or prev[0] != snap[0]):
            st.session_state.sel = s["current_inject"]
        st.rerun(scope="app")


def good_block(inj):
    caps = caps_map(inj["kind"])
    head = "Capability" if inj["kind"] == "technical" else "Governance capability"
    sig = "Expected signal" if inj["kind"] == "technical" else "What good looks like"
    with st.container(border=True):
        st.markdown("**What good looks like**")
        df = pd.DataFrame([(caps.get(c, c), s, resp) for c, s, resp in inj["good"]],
                          columns=[head, sig, "Expected outcome"])
        st.dataframe(df, hide_index=True, width="stretch")
        st.markdown("**Discuss:** " + " ".join(inj["disc"]))
        st.markdown("**Gap probe:** " + inj["probe"])
        if inj.get("target"):
            st.caption(f"**Scored against:** {inj['target']}")


def situation(inj, sess, pid, mine):
    a = mine.get(inj["id"])
    mod, stage = ALL_MODULES[inj["m"]]
    phase = threat.phase_name(inj["phase"]) if inj["phase"] else ""
    st.markdown(f"<span class='ql-tag'>Module {inj['m']} · {esc(mod)} · {esc(stage)} · {esc(inj['t'])}"
                + (f" · {esc(phase)}" if phase else "") + "</span>", unsafe_allow_html=True)
    st.subheader(f"{inj['id']} · {inj['title']}", anchor=False)
    if inj["kind"] == "executive":
        st.caption("Executive decision. Answer for the authority and process that exist today, not for what "
                   "the technical team might eventually find.")
    if not unlocked(sess, inj["id"]):
        st.info("The facilitator will open this situation soon.", icon=":material/lock:")
        return
    st.write(inj["text"])
    tags = " ".join(f":blue-badge[{o} {OBS[o]}]" for o in inj["ob"]) + " " + " ".join(f":gray-badge[{t}]" for t in inj["tech"])
    if tags.strip():
        st.markdown(tags)
    if inj.get("clocks"):
        with st.expander(f"Regulatory clocks counsel must assess here ({len(inj['clocks'])})"):
            rows = [(n, w, d, t) for n, w, d, t in REGULATORY_CLOCKS if n in inj["clocks"]]
            st.dataframe(pd.DataFrame(rows, columns=["Obligation", "Clock", "Requires", "Triggered by"]),
                         hide_index=True, width="stretch")
            st.caption("Applicability depends on jurisdiction, sector and contract. Replace with the "
                       "organization's actual obligations during scoping. Not legal advice.")

    kind = inj["kind"]
    dmap, fmap = decide_map(kind), first_map(kind)
    k = inj["id"].replace(".", "_")
    with st.form(f"f_{k}"):
        act = st.text_area("1. What do you do first?", value=(a or {}).get("act") or "", max_chars=600,
                           placeholder="Who does what, in the first 15 minutes?", key=f"act_{k}")
        dkeys = list(dmap)
        d = st.radio(decide_label(kind), dkeys, format_func=lambda x: dmap[x][0],
                     index=dkeys.index(a["d"]) if a and a["d"] in dkeys else None, key=f"d_{k}")
        fkeys = list(fmap)
        f = st.radio(first_label(kind), fkeys, format_func=lambda x: fmap[x],
                     index=fkeys.index(a["f"]) if a and a["f"] in fkeys else None, key=f"f_{k}")
        okeys = list(OWNER)
        o = st.radio("4. Who owns the decision?", okeys, format_func=lambda x: OWNER[x][0],
                     index=okeys.index(a["o"]) if a and a["o"] in okeys else None, key=f"o_{k}")
        disabled = not sess["is_open"]
        if st.form_submit_button("Update answer" if a else "Submit answer", type="primary", disabled=disabled):
            if not (d and f and o):
                st.error("Answer questions 2, 3 and 4 to submit.")
            else:
                store.save_answer(pid, sess["code"], inj["id"], act, d, f, o)
                st.session_state.flash = f"Answer to {inj['id']} saved."
                ids = play_ids(sess, kind)
                nxt = next((x for x in ids if x not in mine and x != inj["id"] and unlocked(sess, x)), None)
                if nxt and sess["mode"] != "led":
                    st.session_state.sel_next = nxt
                st.rerun()
    if disabled:
        st.caption("Submissions are closed for this session.")
    if a and (inj["id"] in sess["revealed"] or sess["mode"] != "led"):
        good_block(inj)


def go(delta):
    ids = st.session_state.get("_play_ids") or INJECT_IDS
    if st.session_state.sel not in ids:
        return
    i = ids.index(st.session_state.sel) + delta
    st.session_state.sel = ids[max(0, min(len(ids) - 1, i))]


def participant(code):
    sess = store.get_session(code)
    st.markdown(f"<span class='ql-tag'>{esc(SUBTITLE)}</span>", unsafe_allow_html=True)
    st.title(TITLE, anchor=False)
    if not sess:
        st.error("This exercise link is not valid. Ask the facilitator for the QR code again.")
        return

    pid = st.session_state.get("pid") or st.query_params.get("p")
    me = store.get_participant(pid, code) if pid else None
    if not me:
        st.markdown("##### An attacker is turning your company's AI agents against it. Would you see it, and would you stop it?")
        n_tech = len(injects_for("technical"))
        extra = (" A parallel executive track puts the same incident in front of the crisis-management group, "
                 "seeded with whatever the technical room actually escalated."
                 if plays_executive(sess.get("track", "technical")) else "")
        st.write(f"Over {n_tech} situations, a financially motivated group tries to redirect supplier payments and steal "
                 "customer data through a multi-agent application. For each one, answer for your own organization "
                 "as it runs today. Your answers go to the facilitator, who builds the room's gap analysis." + extra)
        if not sess["is_open"]:
            st.warning("This session is closed to new answers.")
            briefing(sess)
            return
        join_form(code, sess)
        briefing(sess)
        return
    st.session_state.pid = me["pid"]

    led_watcher(code)
    mine = store.my_answers(me["pid"])
    if msg := st.session_state.pop("flash", None):
        st.toast(msg, icon=":material/check_circle:")

    kind = kind_for_role(me["role"])
    my_injects = play_injects(sess, kind)
    ids = [i["id"] for i in my_injects]
    st.session_state._play_ids = ids
    by_id = {i["id"]: i for i in my_injects}

    tab_sit, tab_brief = st.tabs(["Situations", "Briefing"])
    with tab_brief:
        briefing(sess)
    with tab_sit:
        if kind == "executive":
            st.info("You are in the **executive track**. You will see 7 crisis decisions rather than the "
                    "technical situations. Decide on the information you are given, as you would in reality.",
                    icon=":material/gavel:")
        done = len([x for x in mine if x in ids])
        total = len(ids)
        st.progress(done / total if total else 0.0,
                    text=f"You have answered {done} of {total} situations.")
        if total and done == total:
            st.success(f"All {total} answered. Thank you. You can still change any answer until the "
                       "facilitator closes the session.")
        if sess["mode"] == "led":
            st.caption("The facilitator opens situations one at a time. Answer the open one, then discuss as a room.")
        else:
            st.caption("Work at your own pace. After you submit, \"what good looks like\" opens for that situation.")

        if "sel_next" in st.session_state:
            st.session_state.sel = st.session_state.pop("sel_next")
        if st.session_state.get("sel") not in ids:
            if sess["mode"] == "led" and sess["current_inject"] in ids:
                st.session_state.sel = sess["current_inject"]
            else:
                st.session_state.sel = next((x for x in ids if x not in mine), ids[0])

        def label(x):
            mark = "✓ " if x in mine else ("🔒 " if not unlocked(sess, x) else "")
            return f"{mark}{x} · {by_id[x]['title']}"

        st.selectbox("Situation", ids, format_func=label, key="sel")
        situation(by_id[st.session_state.sel], sess, me["pid"], mine)
        c1, c2 = st.columns(2)
        c1.button("Previous", on_click=go, args=(-1,), width="stretch", disabled=st.session_state.sel == ids[0])
        c2.button("Next", on_click=go, args=(1,), width="stretch", disabled=st.session_state.sel == ids[-1])


# =====================================================================
# Facilitator side
# =====================================================================
def admin_login():
    try:
        pw = st.secrets.get("ADMIN_PASSWORD")
    except Exception:
        pw = None
    if not pw:
        st.error("The facilitator view is disabled until ADMIN_PASSWORD is set in the app's secrets.")
        return False
    if st.session_state.get("admin_ok"):
        return True
    st.title("Facilitator sign-in", anchor=False)
    with st.form("login"):
        entered = st.text_input("Password", type="password")
        if st.form_submit_button("Sign in", type="primary"):
            if hmac.compare_digest(entered.encode(), str(pw).encode()):
                st.session_state.admin_ok = True
                st.rerun()
            st.error("Wrong password.")
    return False


def base_url():
    try:
        configured = st.secrets.get("APP_URL")
    except Exception:
        configured = None
    if configured:
        return configured.rstrip("/")
    u = st.context.url or ""
    p = urlsplit(u)
    return urlunsplit((p.scheme, p.netloc, p.path, "", "")).rstrip("/")


def qr_png(url):
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=12, border=3)
    q.add_data(url)
    q.make()
    buf = io.BytesIO()
    q.make_image(fill_color="#122030", back_color="white").save(buf, "PNG")
    return buf.getvalue()


def bar_chart(df, label_col, value_col):
    df = df.copy()
    df["lv"] = df[value_col].map(level)
    # to_numeric first: a column of all-None arrives as object dtype, and fillna on that
    # silently downcasts, which pandas 3 will stop doing.
    df["shown"] = pd.to_numeric(df[value_col], errors="coerce").fillna(0.0)
    df["txt"] = df[value_col].map(pct)
    base = alt.Chart(df).encode(y=alt.Y(f"{label_col}:N", sort=None, title=None, axis=alt.Axis(labelLimit=320)))
    bars = base.mark_bar(cornerRadiusEnd=3, height=14).encode(
        x=alt.X("shown:Q", scale=alt.Scale(domain=[0, 100]), title="Readiness (%)"),
        color=alt.Color("lv:N", scale=alt.Scale(domain=list(COLORS), range=list(COLORS.values())), legend=None),
        tooltip=[label_col, "txt"])
    txt = base.mark_text(align="left", dx=4, fontSize=11).encode(x="shown:Q", text="txt:N")
    rule = alt.Chart(pd.DataFrame({"x": [40, 70]})).mark_rule(strokeDash=[3, 3], color="#A9B5C2").encode(x="x:Q")
    return (bars + txt + rule).properties(height=max(120, 26 * len(df)))


def heatmap(A):
    tiles = []
    for o, name in OBS.items():
        if o in NOT_EXERCISED:
            tiles.append(f"<div class='t off' title='{esc(NOT_EXERCISED[o])}'><b>{o}</b><span>{esc(name)}</span><i>Not exercised</i></div>")
            continue
        v = A["ob"][o]["avg"]
        lv = level(v)
        tiles.append(f"<div class='t' style='background:{SOFT[lv]};border-color:{COLORS[lv]}'><b>{o}</b><span>{esc(name)}</span>"
                     f"<em>{pct(v)}</em><i>{LEVEL_WORD[lv]} · {', '.join(A['ob'][o]['injects'])}</i></div>")
    legend = "".join(f"<span><i style='background:{COLORS[k]}'></i>{w}</span>" for k, w in
                     [("good", "Ready, 70%+"), ("warn", "Partial, 40-69%"), ("crit", "Gap, under 40%"), ("na", "No answers yet")])
    st.html(f"""<style>
.hm{{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px;font-family:'Source Sans Pro',system-ui,sans-serif;color:#122030}}
.hm .t{{border:1px solid;border-radius:8px;padding:9px 11px;display:flex;flex-direction:column;gap:3px;min-height:100px}}
.hm b{{font:600 .72rem ui-monospace,Menlo,monospace}} .hm span{{font-size:.82rem;font-weight:600;line-height:1.25}}
.hm em{{font-style:normal;font-weight:700;font-size:1.15rem;margin-top:auto}} .hm i{{font-style:normal;font-size:.72rem;color:#3d4a58}}
.hm .off{{background:repeating-linear-gradient(135deg,#ECEFF2 0 6px,#fff 6px 12px);border-color:#D4DBE3;color:#7d8b99}}
.lg{{display:flex;gap:14px;flex-wrap:wrap;font-size:.8rem;color:#566576;margin:4px 0 10px;font-family:system-ui,sans-serif}}
.lg i{{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:5px;vertical-align:-1px}}
</style><div class='lg'>{legend}</div><div class='hm'>{''.join(tiles)}</div>""")


def data_for(sess):
    if st.session_state.get("sample"):
        return sample_answers(injects=play_injects(sess))
    return store.session_frames(sess["code"])


def analysis(sess):
    parts, ans = data_for(sess)
    return parts, ans, aggregate(ans, injects=play_injects(sess))


def gap_view(sess):
    parts, ans, A = analysis(sess)
    injects = A["injects"]
    if st.session_state.get("sample"):
        st.warning("Showing example answers from six fictional participants. Not real data.", icon=":material/science:")
    if not A["answers"]:
        st.info("No answers yet. As participants submit, readiness by objective, situation and capability appears here.")
        return
    c = st.columns(6)
    c[0].metric("Participants", A["people"])
    c[1].metric("Answers", A["answers"])
    c[2].metric("Overall readiness", pct(A["overall"]))
    c[3].metric("Maturity", f"L{A['maturity']}" if A["maturity"] else "–",
                help="; ".join(f"L{k} {v[0]}: {v[1]}" for k, v in MATURITY.items()))
    c[4].metric("Situations below 40%", A["gaps"])
    c[5].metric("Include \"don't know\"", pct(A["dk"]))
    st.caption(f"Coverage: {round(A['coverage'])}% of the situations in this track have at least one answer. "
               "Readiness = 70% detection or decision-readiness + 30% decision ownership.")

    st.subheader("Readiness by exercise objective", anchor=False)
    st.caption("The objectives the exercise was scoped to test. This is the table a Mandiant after-action "
               "report opens with, because it answers what was assessed rather than what was discussed.")
    rows = []
    for k in OBJECTIVE_ORDER:
        if k not in A["objectives"]:
            continue
        o = A["objectives"][k]
        rows.append({"ID": k, "Objective": OBJECTIVES[k][0], "Track": OBJECTIVES[k][2].title(),
                     "Readiness": pct(o["avg"]), "Maturity": f"L{o['maturity']} {maturity_word(o['maturity'])}" if o["maturity"] else "–",
                     "Status": LEVEL_WORD[level(o["avg"])], "Situations": ", ".join(o["injects"]),
                     "_v": -1 if o["avg"] is None else o["avg"]})
    st.dataframe(pd.DataFrame(rows).sort_values("_v").drop(columns="_v"), hide_index=True, width="stretch")

    st.subheader("Readiness by Cisco taxonomy objective", anchor=False)
    st.caption("Cisco Integrated AI Security and Safety Framework: the taxonomy the situations are authored against.")
    heatmap(A)

    st.subheader("Readiness by attack-lifecycle phase", anchor=False)
    st.caption("Where in the campaign the organization is weakest. A low score in an early phase means every "
               "later phase was reached in reality.")
    prows = [{"Phase": threat.LIFECYCLE[p][0], "v": A["phase"][p]["avg"]}
             for p in threat.LIFECYCLE_ORDER if p in A["phase"]]
    st.altair_chart(bar_chart(pd.DataFrame(prows), "Phase", "v"), width="stretch")

    st.subheader("Readiness by situation, weakest first", anchor=False)
    rows = []
    for inj in injects:
        s = A["per"][inj["id"]]
        flags = []
        if s["spread"] >= 30:
            flags.append("room disagrees")
        if s["n"] and s["dk"] / s["n"] >= .3:
            flags.append(f"{round(s['dk'] / s['n'] * 100)}% don't know")
        rows.append({"Situation": f"{inj['id']} {inj['title']}" + (f"  [{'; '.join(flags)}]" if flags else ""), "v": s["avg"]})
    df = pd.DataFrame(rows).sort_values("v", na_position="last")
    st.altair_chart(bar_chart(df, "Situation", "v"), width="stretch")
    st.caption("\"Room disagrees\" means answers are far apart: people have different pictures of the same control.")

    for kind, head in (("technical", "Readiness by control capability"),
                       ("executive", "Readiness by governance capability")):
        cs = [c for c in cap_order(kind) if c in A["cap"] and A["cap"][c]["kind"] == kind]
        if not cs:
            continue
        st.subheader(head, anchor=False)
        caps = caps_map(kind)
        cdf = pd.DataFrame([{"Capability": caps[c], "v": A["cap"][c]["avg"]} for c in cs]).sort_values("v", na_position="last")
        st.altair_chart(bar_chart(cdf, "Capability", "v"), width="stretch")
        st.dataframe(pd.DataFrame([{"Capability": caps[c], "Readiness": pct(A["cap"][c]["avg"]),
                                    "Maturity": f"L{A['cap'][c]['maturity']} {maturity_word(A['cap'][c]['maturity'])}"
                                    if A["cap"][c]["maturity"] else "–",
                                    "Situations": ", ".join(A["cap"][c]["injects"])} for c in cs]),
                     hide_index=True, width="stretch")

    st.subheader("What would act first: room vs. design", anchor=False)
    fr = []
    for inj in injects:
        s = A["per"][inj["id"]]
        if not s["n"]:
            continue
        caps, fmap = caps_map(inj["kind"]), first_map(inj["kind"])
        top = max(s["first"], key=s["first"].get)
        fr.append({"Situation": f"{inj['id']} {inj['title']}", "Room's most common answer": fmap.get(top, top),
                   "Share": f"{round(s['first'][top] / s['n'] * 100)}%", "Designed first catch": caps.get(inj["primary"], inj["primary"]),
                   "Match": "Yes" if top == inj["primary"] else "No"})
    st.dataframe(pd.DataFrame(fr), hide_index=True, width="stretch")
    st.caption("A mismatch is a finding on its own: the room is watching a layer that was not designed to catch this.")

    if plays_executive(sess.get("track", "technical")):
        st.subheader("Escalation path: where the two rooms diverge", anchor=False)
        st.caption("Each executive decision depends on a technical situation. Where the technical readiness is "
                   "high and the executive readiness is low, detection is working and escalation is not. "
                   "Where both are low, the executives were deciding blind.")
        rows = []
        for tech_id, exec_id, why in ESCALATION_COUPLING:
            t = A["per"].get(tech_id, {})
            e = A["per"].get(exec_id, {})
            tv, ev = t.get("avg"), e.get("avg")
            if tv is None and ev is None:
                continue
            if tv is not None and ev is not None:
                verdict = ("Escalation gap" if tv >= 60 and ev < 50 else
                           "Deciding blind" if tv < 50 and ev < 50 else
                           "Chain holds" if tv >= 60 and ev >= 60 else "Partial")
            else:
                verdict = "Incomplete"
            rows.append({"Technical": f"{tech_id} {ALL_BY_ID[tech_id]['title']}", "Readiness": pct(tv),
                         "Executive": f"{exec_id} {ALL_BY_ID[exec_id]['title']}", "Decision readiness": pct(ev),
                         "Verdict": verdict, "Dependency": why})
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def msel_view(sess):
    """Master Scenario Events List: the facilitator's run sheet."""
    injects = play_injects(sess)
    st.caption("The Master Scenario Events List. Run the exercise from this: each row is an event, when it "
               "lands, how it is delivered, and which objectives it is there to test.")
    rows = []
    for i in injects:
        mod, stage = ALL_MODULES[i["m"]]
        rows.append({"Time": i["t"], "ID": i["id"], "Track": i["kind"].title(),
                     "Phase": threat.phase_name(i["phase"]) if i["phase"] else "–",
                     "Event": i["title"], "Delivery": i.get("delivery", ""),
                     "Objectives": ", ".join(i["objs"]),
                     "Scored against": i.get("target", ""), "Module": f"{i['m']} {mod}"})
    df = pd.DataFrame(rows)
    st.dataframe(df, hide_index=True, width="stretch")
    st.download_button("Download MSEL (CSV)", df.to_csv(index=False).encode(),
                       f"ttx_{sess['code']}_msel.csv", "text/csv")

    st.subheader("Evaluator criteria", anchor=False)
    st.caption("What to record while the room talks. These are observable behaviours, not opinions, and they "
               "are what turns a discussion into a finding.")
    for i in injects:
        if not i.get("evaluate"):
            continue
        with st.expander(f"{i['id']} · {i['title']}"):
            for e in i["evaluate"]:
                st.markdown(f"- {e}")
            if i.get("target"):
                st.caption(f"**Scored against:** {i['target']}")

    if plays_executive(sess.get("track", "technical")):
        st.subheader("Room coupling", anchor=False)
        st.caption("Seed each executive inject with what the technical room actually produced, not with the "
                   "ground truth. This is what makes the escalation path testable.")
        st.dataframe(pd.DataFrame([{"Technical": t, "Feeds executive": e, "Dependency": w}
                                   for t, e, w in ESCALATION_COUPLING]), hide_index=True, width="stretch")

    st.subheader("Synthetic indicators", anchor=False)
    st.caption("Use these to ask \"could you search for this?\", which is a better question than \"do you have the IOC\".")
    st.dataframe(pd.DataFrame(threat.INDICATORS, columns=["Type", "Indicator", "Where you would look"]),
                 hide_index=True, width="stretch")


def frameworks_view(sess):
    parts, ans, A = analysis(sess)
    st.caption("The same findings, expressed in each framework. The Cisco taxonomy is the spine: situations are "
               "authored against it, and every other view is derived from the same answers.")
    tabs = st.tabs([FRAMEWORKS[f]["name"] for f in FRAMEWORK_ORDER])
    for tab, f in zip(tabs, FRAMEWORK_ORDER):
        with tab:
            meta = FRAMEWORKS[f]
            st.markdown(f"**{meta['name']}** · {meta['version']}")
            st.caption(f"**Purpose** {meta['purpose']}  \n**Audience** {meta['audience']}  \n**Role here** {meta['role']}")
            if f == "csf" and not plays_executive(sess.get("track", "technical")):
                st.info("GOVERN and RESPOND cannot be fully evidenced on the technical track alone. Run the full "
                        "engagement to rate them.", icon=":material/info:")
            rolled = A["fw"].get(f, {})
            if not rolled:
                st.info("No mappings in play for this track.")
                continue
            rows = []
            for ident, v in rolled.items():
                label = v["name"] or ident
                if f == "csf":
                    fn = ident.split(".")[0]
                    label = f"{fn} · {label}"
                rows.append({"ID": ident, "Name": label, "Readiness": pct(v["avg"]),
                             "Maturity": f"L{v['maturity']} {maturity_word(v['maturity'])}" if v["maturity"] else "–",
                             "Status": LEVEL_WORD[level(v["avg"])],
                             "Situations": ", ".join(v["injects"]),
                             "_v": -1 if v["avg"] is None else v["avg"]})
            df = pd.DataFrame(rows).sort_values("_v").drop(columns="_v")
            st.dataframe(df, hide_index=True, width="stretch")
            st.download_button(f"Download {meta['name']} mapping (CSV)", df.to_csv(index=False).encode(),
                               f"ttx_{sess['code']}_{f}.csv", "text/csv", key=f"dl_fw_{f}")
            if f == "csf":
                st.subheader("Maturity by function", anchor=False)
                frows = []
                from frameworks import CSF_FUNCTION_ORDER, CSF_FUNCTIONS
                for fn in CSF_FUNCTION_ORDER:
                    vals = [v["avg"] for i, v in rolled.items() if i.startswith(fn + ".") and v["avg"] is not None]
                    avg = sum(vals) / len(vals) if vals else None
                    frows.append({"Function": f"{fn} {CSF_FUNCTIONS[fn][0]}", "v": avg})
                st.altair_chart(bar_chart(pd.DataFrame(frows), "Function", "v"), width="stretch")
            if f == "cisco":
                st.caption("Objectives not exercised in this scenario: " +
                           "; ".join(f"{o} ({why})" for o, why in NOT_EXERCISED.items()))
            with st.expander("Full catalogue reference"):
                for label, cat in CATALOGUES.get(f, []):
                    st.markdown(f"**{label}**")
                    st.dataframe(pd.DataFrame([{"ID": k, "Name": v} for k, v in cat.items()]),
                                 hide_index=True, width="stretch")
                if f == "cisco":
                    st.dataframe(pd.DataFrame([{"ID": k, "Objective": v} for k, v in OBS.items()]),
                                 hide_index=True, width="stretch")


def aar_view(sess):
    """The after-action report: findings, maturity, roadmap."""
    parts, ans, A = analysis(sess)
    t = track_def(sess.get("track", "technical"))
    if not A["answers"]:
        st.info("The after-action report is generated from the room's answers. It fills in once answers arrive.")
        return
    fs = findings(A)
    st.markdown(f"### After-action report · {t['name']}")
    st.caption(f"Generated from {A['answers']} answers by {A['people']} participants, covering "
               f"{round(A['coverage'])}% of the situations in this track.")

    counts = {s: sum(1 for f in fs if f["severity"] == s) for s in SEVERITY_ORDER}
    c = st.columns(len(SEVERITY_ORDER) + 1)
    for i, s in enumerate(SEVERITY_ORDER):
        c[i].metric(s, counts[s])
    c[-1].metric("Overall maturity", f"L{A['maturity']} {maturity_word(A['maturity'])}" if A["maturity"] else "–")

    st.subheader("Executive summary", anchor=False)
    crit = [f for f in fs if f["severity"] in ("Critical", "High")]
    strengths = [f for f in fs if f["severity"] == "Strength"]
    weakest_phase = min(((p, v["avg"]) for p, v in A["phase"].items() if v["avg"] is not None),
                        key=lambda x: x[1], default=None)
    lines = [
        f"The exercise assessed {len(A['injects'])} situations against {len(A['objectives'])} objectives. "
        f"Overall readiness is {pct(A['overall'])}, which corresponds to maturity level "
        f"{A['maturity']} ({maturity_word(A['maturity'])}).",
        f"{len(crit)} finding(s) are rated Critical or High and are scheduled inside 30 days.",
    ]
    if weakest_phase:
        lines.append(f"The weakest point in the attack lifecycle is "
                     f"**{threat.phase_name(weakest_phase[0])}** at {pct(weakest_phase[1])}. "
                     "A miss there means every later phase was reached in reality.")
    if A["dk"] and A["dk"] >= 20:
        lines.append(f"{pct(A['dk'])} of answers included \"don't know\". That is a knowledge gap as much as a "
                     "control gap: no single participant could answer for the whole system.")
    if strengths:
        lines.append(f"{len(strengths)} area(s) scored as a strength and should be protected during remediation.")
    for ln in lines:
        st.markdown(f"- {ln}")
    st.info("Every finding below records what the room **said**. A tabletop evidences belief, not efficacy. "
            "Findings should be confirmed by technical validation before they are closed.", icon=":material/warning:")

    st.subheader("Findings", anchor=False)
    for f in fs:
        if f["severity"] == "Strength":
            continue
        with st.container(border=True):
            l, r = st.columns([2, 3])
            with l:
                st.markdown(f"**{f['id']} · {f['title']}**")
                st.markdown(f":{SEV_COLOR[f['severity']]}-badge[{f['severity']}] "
                            f"{maturity_badge(f['maturity'])} :gray-badge[{f['horizon']}]")
                st.caption(f"Readiness {pct(f['readiness'])} from {f['responses']} responses · "
                           f"{f['kind'].title()} track · {threat.phase_name(f['phase']) if f['phase'] else '–'}")
                st.caption(f"**Capability** {f['capability']}")
                st.caption(f"**Objectives** {', '.join(f['objectives']) or '–'}")
            with r:
                st.markdown(f"**Recommendation** {f['recommendation']}")
                if f["outcome"]:
                    st.caption(f"**Expected outcome** {f['outcome']}")
                if f["target"]:
                    st.caption(f"**Scored against** {f['target']}")
                for fl in f["flags"]:
                    st.caption(f"• Observation: {fl}")
                mapped = [f"{k}: {', '.join(v)}" for k, v in f["frameworks"].items() if v]
                if mapped:
                    st.caption("**Mapped to** " + " · ".join(mapped))

    if strengths:
        st.subheader("Strengths to protect", anchor=False)
        st.dataframe(pd.DataFrame([{"Situation": f"{f['inject']} {f['title']}", "Readiness": pct(f["readiness"]),
                                    "Capability": f["capability"]} for f in strengths]),
                     hide_index=True, width="stretch")

    st.subheader("Remediation plan", anchor=False)
    st.caption("Grouped by the horizon each finding's severity implies. Owners are assigned in the hotwash, "
               "not by the tool.")
    for horizon, items in roadmap(fs):
        st.markdown(f"**{horizon}** — {len(items)} item(s)")
        st.dataframe(pd.DataFrame([{"Finding": f"{f['id']} {f['title']}", "Severity": f["severity"],
                                    "Capability": f["capability"], "Action": f["recommendation"],
                                    "Owner": "", "Status": ""} for f in items]),
                     hide_index=True, width="stretch")

    flat = pd.DataFrame([{"id": f["id"], "situation": f["inject"], "title": f["title"], "track": f["kind"],
                          "severity": f["severity"], "horizon": f["horizon"], "readiness": f["readiness"],
                          "maturity": f["maturity"], "responses": f["responses"], "capability": f["capability"],
                          "objectives": ";".join(f["objectives"]), "phase": f["phase"],
                          "recommendation": f["recommendation"], "observations": " | ".join(f["flags"]),
                          **{f"map_{k}": ";".join(v) for k, v in f["frameworks"].items()}} for f in fs])
    st.download_button("Download findings (CSV)", flat.to_csv(index=False).encode(),
                       f"ttx_{sess['code']}_findings.csv", "text/csv")


def hotwash_view(sess):
    code = sess["code"]
    st.caption("Run this immediately after play, while the room is still together. A Mandiant hotwash is not a "
               "retrospective on the exercise; it is the last data-collection step, and it is where owners "
               "get attached to findings.")
    saved = store.get_hotwash(code)
    for n, (q, why) in enumerate(HOTWASH):
        with st.container(border=True):
            st.markdown(f"**{n + 1}. {q}**")
            st.caption(why)
            note = st.text_area("Notes", value=saved.get(n, "") or "", key=f"hw_{code}_{n}",
                                label_visibility="collapsed", height=100)
            if st.button("Save", key=f"hwb_{code}_{n}"):
                store.save_hotwash(code, n, note)
                st.toast("Hotwash note saved.", icon=":material/check_circle:")
    if saved:
        out = pd.DataFrame([{"question": HOTWASH[n][0], "notes": saved.get(n, "")} for n in range(len(HOTWASH))])
        st.download_button("Download hotwash notes (CSV)", out.to_csv(index=False).encode(),
                           f"ttx_{code}_hotwash.csv", "text/csv")


def portfolio_view(sess):
    parts, ans, A = analysis(sess)
    st.caption("Technology annex. The findings and framework views come first deliberately: this page answers "
               "\"what would close the gap\", not \"what did the exercise find\". Capabilities are ranked by how "
               "much of the room's measured gap they would close, weighted 1.5x where the capability is the "
               "designed first catch.")
    if not A["answers"]:
        st.info("This view ranks capabilities and products by the room's gaps. It fills in once answers arrive.")

    tech_caps = [c for c in CAP_ORDER if c in A["cap"]]
    ranked = sorted(tech_caps, key=lambda c: -A["cap"][c]["gap"])
    st.subheader("Priority by measured gap", anchor=False)
    for i, c in enumerate(ranked, 1):
        s = A["cap"][c]
        with st.container(border=True):
            l, r = st.columns([2, 3])
            with l:
                st.caption(f"Priority {i}")
                st.markdown(f"**{CAPS[c]}**")
                st.markdown(badge(level(s["avg"]), s["avg"]) + " " + maturity_badge(s["maturity"]))
                st.caption("Situations " + ", ".join(s["injects"]))
            with r:
                for pk in portfolio.products_for_cap(c):
                    p = portfolio.PRODUCTS[pk]
                    st.markdown(f"**{p['name']}** · _{p['vendor']}_  \n{p['does']}")
                    if p.get("note"):
                        st.caption(f"Note: {p['note']}")
                if s["obs"]:
                    st.markdown(" ".join(f":blue-badge[{o} {OBS[o]}]" for o in s["obs"]))

    st.subheader("Secure AI Factory by layer", anchor=False)
    st.caption("The full stack, so the architecture conversation is not limited to the AI-specific controls.")
    for lk in portfolio.LAYER_ORDER:
        lname, ldesc = portfolio.LAYERS[lk]
        with st.expander(f"{lname} — {ldesc}"):
            rows = []
            for pk, p in portfolio.PRODUCTS.items():
                if p["layer"] != lk:
                    continue
                caps = ", ".join(CAPS.get(c, EXEC_CAPS.get(c, c)) for c in p["caps"])
                rows.append({"Product": p["name"], "Vendor": p["vendor"], "Capability": caps,
                             "What it does": p["does"], "Situations it covers": ", ".join(p.get("covers", [])),
                             "Note": p.get("note", "")})
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

    st.subheader("Staging", anchor=False)
    st.caption("The honest answer to \"what do we buy first\". Each stage is only worth starting once the "
               "previous one is in place.")
    for name, keys, why in portfolio.STACK_STAGES:
        with st.container(border=True):
            st.markdown(f"**{name}**")
            st.caption(why)
            for pk in keys:
                p = portfolio.PRODUCTS[pk]
                st.markdown(f"- {p['name']} · _{p['vendor']}_")

    st.subheader("By Cisco taxonomy objective", anchor=False)
    rows = []
    for o in OBS:
        if o in NOT_EXERCISED:
            continue
        v = A["ob"][o]["avg"]
        caps = [c for c in CAP_ORDER if any(o in i["ob"] and c in i["caps"] for i in INJECTS)]
        prods = sorted({portfolio.PRODUCTS[pk]["name"] for c in caps for pk in portfolio.products_for_cap(c)
                        if portfolio.PRODUCTS[pk]["vendor"] != "Customer-owned"})
        rows.append({"Objective": f"{o} {OBS[o]}", "Readiness": pct(v), "Status": LEVEL_WORD[level(v)],
                     "_v": -1 if v is None else v, "Products that address it": "; ".join(prods)})
    st.dataframe(pd.DataFrame(rows).sort_values("_v").drop(columns="_v"), hide_index=True, width="stretch")
    st.markdown("**Sources:** " + " · ".join(f"[{n}]({u})" for n, u in SOURCES))


def responses_view(code):
    parts, ans = store.session_frames(code)
    if parts.empty:
        st.info("Nobody has joined this session yet.")
        return
    counts = ans.groupby("pid").size() if not ans.empty else pd.Series(dtype=int)
    p = parts.assign(answered=parts["pid"].map(counts).fillna(0).astype(int),
                     track=parts["role"].map(kind_for_role).str.title(),
                     joined=pd.to_datetime(parts["created_at"], unit="s").dt.strftime("%Y-%m-%d %H:%M UTC"))
    p["name"] = p["name"].replace("", "(no name)")
    st.markdown(f"**{len(p)} joined**")
    st.dataframe(p[["name", "role", "track", "org", "answered", "joined"]], hide_index=True, width="stretch")
    if not ans.empty:
        def _kind(i):
            return ALL_BY_ID[i]["kind"] if i in ALL_BY_ID else "technical"

        who = parts.set_index("pid")
        out = ans.assign(name=ans["pid"].map(who["name"]), role=ans["pid"].map(who["role"]), org=ans["pid"].map(who["org"]),
                         situation=ans["inject"].map(lambda x: f"{x} {ALL_BY_ID[x]['title']}" if x in ALL_BY_ID else x),
                         track=ans["inject"].map(_kind).str.title(),
                         detect_or_decide=ans.apply(lambda r: decide_map(_kind(r["inject"])).get(r["d"], (r["d"], 0))[0], axis=1),
                         first_catch=ans.apply(lambda r: first_map(_kind(r["inject"])).get(r["f"], r["f"]), axis=1),
                         owner=ans["o"].map(lambda x: OWNER.get(x, (x, 0))[0]), first_action=ans["act"])
        out = out.sort_values(["inject", "role"])[["situation", "track", "name", "role", "org",
                                                   "detect_or_decide", "first_catch", "owner", "first_action"]]
        st.dataframe(out, hide_index=True, width="stretch")
        st.download_button("Download all answers (CSV)", out.to_csv(index=False).encode(), f"ttx_{code}_answers.csv", "text/csv")
    with st.expander("Remove a participant"):
        opts = {r.pid: f"{r.name or '(no name)'} · {r.role} · {r.answered} answers" for r in p.itertuples()}
        victim = st.selectbox("Participant", list(opts), format_func=opts.get, index=None)
        if st.button("Remove participant and their answers", disabled=not victim):
            store.delete_participant(victim)
            st.rerun()


def facilitator_view(sess):
    code = sess["code"]
    link = f"{base_url()}/?{urlencode({'s': code})}"
    with st.container(border=True):
        l, r = st.columns([1, 2])
        png = qr_png(link)
        l.image(png, width=220)
        with r:
            st.markdown("**Participants scan this to join.** No sign-in needed.")
            st.code(link, language=None)
            st.download_button("Download QR code (PNG)", png, f"ttx_{code}_qr.png", "image/png")
    ids = play_ids(sess)
    with st.container(border=True):
        st.markdown("**Exercise mode**")
        track = st.segmented_control("Track", TRACK_ORDER, default=sess.get("track", "technical"),
                                     key=f"track_{code}", format_func=lambda k: TRACKS[k]["name"])
        if track and track != sess.get("track", "technical"):
            store.update_session(code, track=track)
            st.rerun()
        track_card(sess.get("track", "technical"))
    with st.container(border=True):
        st.markdown("**Pace**")
        mode = st.segmented_control("Mode", ["self", "led"], default=sess["mode"], key=f"mode_{code}",
                                    format_func={"self": "Self-paced: all situations open", "led": "Facilitator-led: one at a time"}.get)
        if mode and mode != sess["mode"]:
            store.update_session(code, mode=mode)
            st.rerun()
        cur = ids.index(sess["current_inject"]) if sess["current_inject"] in ids else 0
        c1, c2, c3 = st.columns([3, 1, 1])
        pick = c1.selectbox("Open up to", ids, index=cur, format_func=lambda x: f"{x} · {ALL_BY_ID[x]['title']}", key=f"cur_{code}_{cur}")
        if pick != sess["current_inject"]:
            store.update_session(code, current_inject=pick)
            st.rerun()
        if c2.button("Previous", disabled=cur == 0, width="stretch"):
            store.update_session(code, current_inject=ids[cur - 1])
            st.rerun()
        if c3.button("Next", type="primary", disabled=cur == len(ids) - 1, width="stretch"):
            store.update_session(code, current_inject=ids[cur + 1], mode="led")
            st.rerun()
        b1, b2, b3 = st.columns(3)
        if b1.button(f"Reveal answers for {sess['current_inject']}", width="stretch"):
            store.update_session(code, revealed=sess["revealed"] + [sess["current_inject"]])
            st.rerun()
        if b2.button("Reveal all", width="stretch"):
            store.update_session(code, revealed=ids)
            st.rerun()
        if b3.button("Hide all", width="stretch"):
            store.update_session(code, revealed=[])
            st.rerun()
        st.caption(f"Revealed: {', '.join(sess['revealed']) or 'none'}. In self-paced mode, each participant sees "
                   "\"what good looks like\" after they submit, regardless of this setting.")
    with st.container(border=True):
        st.markdown("**Submissions**")
        open_ = st.toggle("Accept answers", value=sess["is_open"], key=f"open_{code}")
        if open_ != sess["is_open"]:
            store.update_session(code, is_open=open_)
            st.rerun()
        with st.expander("Reset or delete this session"):
            sure = st.checkbox("I understand this permanently deletes every answer in this session")
            d1, d2 = st.columns(2)
            if d1.button("Clear all answers", disabled=not sure, width="stretch"):
                store.reset_session(code)
                st.rerun()
            if d2.button("Delete session", disabled=not sure or code == "main", width="stretch"):
                store.delete_session(code)
                st.session_state.admin_code_next = "main"
                st.rerun()


def admin():
    if not admin_login():
        return
    sessions = store.list_sessions()
    codes = [s["code"] for s in sessions]
    names = {s["code"]: f"{s['name']} ({s['code']})" for s in sessions}
    with st.sidebar:
        st.markdown(f"**{TITLE}**  \nFacilitator")
        if "admin_code_next" in st.session_state:
            st.session_state.admin_code = st.session_state.pop("admin_code_next")
        if st.session_state.get("admin_code") not in codes:
            st.session_state.admin_code = codes[0]
        st.selectbox("Session", codes, format_func=names.get, key="admin_code")
        with st.form("newsess", clear_on_submit=True):
            nm = st.text_input("New session name", placeholder="e.g. Acme Bank, 4 Nov")
            nt = st.radio("Exercise mode", TRACK_ORDER, format_func=lambda k: TRACKS[k]["name"],
                          captions=[TRACKS[k]["tagline"] for k in TRACK_ORDER])
            if st.form_submit_button("Create session") and nm.strip():
                st.session_state.admin_code_next = store.create_session(nm, track=nt or "technical")
                st.rerun()
        st.toggle("Auto-refresh dashboards", value=True, key="auto")
        st.toggle("Preview with example answers", key="sample", help="Fictional answers, never saved.")
        if not store.persistent():
            st.warning("No DATABASE_URL set: answers are kept in a local SQLite file that Streamlit Cloud wipes on restart.")
        if st.button("Sign out"):
            st.session_state.admin_ok = False
            st.rerun()

    sess = store.get_session(st.session_state.admin_code)
    t = track_def(sess.get("track", "technical"))
    st.title(sess["name"], anchor=False)
    st.markdown(f"<span class='ql-tag'>{esc(t['name'])} · {esc(t['tagline'])}</span>", unsafe_allow_html=True)
    tabs = st.tabs(["Facilitator", "MSEL", "Gap analysis", "Frameworks",
                    "After-action report", "Hotwash", "Technology annex", "Responses"])
    every = 10 if st.session_state.get("auto") else None

    @st.fragment(run_every=every)
    def live_gaps():
        gap_view(sess)

    @st.fragment(run_every=every)
    def live_frameworks():
        frameworks_view(sess)

    @st.fragment(run_every=every)
    def live_aar():
        aar_view(sess)

    @st.fragment(run_every=every)
    def live_portfolio():
        portfolio_view(sess)

    @st.fragment(run_every=every)
    def live_resp():
        responses_view(sess["code"])

    with tabs[0]:
        facilitator_view(sess)
    with tabs[1]:
        msel_view(sess)
    with tabs[2]:
        live_gaps()
    with tabs[3]:
        live_frameworks()
    with tabs[4]:
        live_aar()
    with tabs[5]:
        hotwash_view(sess)
    with tabs[6]:
        live_portfolio()
    with tabs[7]:
        live_resp()


# =====================================================================
if "admin" in st.query_params:
    admin()
else:
    participant(st.query_params.get("s", "main"))
