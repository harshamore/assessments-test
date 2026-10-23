"""Readiness scoring, capability maturity and after-action findings.

Per answer: 70% detection (or, on the executive track, decision readiness) plus 30%
decision ownership. Under 40 is a gap, 40-69 partial, 70+ ready.

The exercise reports three ways, and they answer different questions:
  readiness  what the room says it can do, 0-100, per situation and capability
  maturity   what that implies about the control's state, on a 5-level scale
  findings   the after-action report: a defect, its evidence, and what to do in 30/60/90 days
"""
import random

import numpy as np
import pandas as pd

from content import (ALL_BY_ID, ALL_INJECTS, ALL_ROLES, BY_ID, CAP_ORDER, CAPS, DETECT,
                     INJECTS, OBS, OWNER, ROLES, cap_order, caps_map, decide_map)
from frameworks import FIELD, FRAMEWORK_ORDER, name_for
from mappings import OBJECTIVES


def level(v):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "na"
    return "good" if v >= 70 else "warn" if v >= 40 else "crit"


LEVEL_WORD = {"good": "Ready", "warn": "Partial", "crit": "Gap", "na": "No answers"}

# Capability maturity. Deliberately conservative: a room that believes it would
# detect something is not the same as a control that is measured and improved.
MATURITY = {
    1: ("Initial", "Ad hoc. No defined process; outcomes depend on individuals."),
    2: ("Developing", "A process exists in places but is inconsistent and undocumented."),
    3: ("Defined", "Documented and consistently applied, but not measured."),
    4: ("Managed", "Measured against thresholds, with an accountable owner."),
    5: ("Optimised", "Continuously improved, largely automated, and evidenced on demand."),
}


def maturity_of(v):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    return 1 if v < 20 else 2 if v < 40 else 3 if v < 65 else 4 if v < 85 else 5


def maturity_word(m):
    return MATURITY[m][0] if m else "Not assessed"


def _value_map(kind):
    """{answer key: points} for the decision/detection question of a given kind."""
    return {k: v[1] for k, v in decide_map(kind).items()}


def score_rows(ans: pd.DataFrame) -> pd.DataFrame:
    if ans.empty:
        return ans.assign(score=pd.Series(dtype=float), dk=pd.Series(dtype=bool),
                          kind=pd.Series(dtype=object))
    a = ans.copy()
    a["kind"] = a["inject"].map(lambda i: ALL_BY_ID[i]["kind"] if i in ALL_BY_ID else "technical")
    tech_vals, exec_vals = _value_map("technical"), _value_map("executive")

    def dval(row):
        table = exec_vals if row["kind"] == "executive" else tech_vals
        return table.get(row["d"], 0)

    a["score"] = a.apply(dval, axis=1) * 0.7 + a["o"].map(lambda x: OWNER.get(x, ("", 0))[1]) * 0.3
    a["dk"] = (a["d"] == "dk") | (a["f"] == "dk")
    return a


def aggregate(ans: pd.DataFrame, injects=None):
    """Roll answers up per inject, Cisco objective, capability, exercise objective and framework.

    injects: the inject set in play, so a technical-only session is not scored as if it
    had failed to answer the executive track.
    """
    injects = list(injects) if injects is not None else list(ALL_INJECTS)
    a = score_rows(ans)
    ids = [i["id"] for i in injects]
    if not a.empty:
        a = a[a["inject"].isin(ids)]

    per = {}
    for inj in injects:
        rows = a[a["inject"] == inj["id"]] if not a.empty else a
        n = len(rows)
        per[inj["id"]] = dict(
            n=n,
            avg=float(rows["score"].mean()) if n else None,
            spread=float(rows["score"].std(ddof=0)) if n > 1 else 0.0,
            dk=int(rows["dk"].sum()) if n else 0,
            first=rows["f"].value_counts().to_dict() if n else {},
            kind=inj["kind"],
        )

    def _avg(id_list):
        vals = [per[x]["avg"] for x in id_list if x in per and per[x]["n"]]
        return float(np.mean(vals)) if vals else None

    # Cisco taxonomy objectives (the spine).
    ob = {o: dict(avg=_avg([i["id"] for i in injects if o in i["ob"]]),
                  injects=[i["id"] for i in injects if o in i["ob"]])
          for o in OBS}

    # Control capabilities, per kind, since the two tracks have different capability sets.
    cap = {}
    for kind in ("technical", "executive"):
        ks = [i for i in injects if i["kind"] == kind]
        if not ks:
            continue
        for c in cap_order(kind):
            ins = [i for i in ks if c in i["caps"]]
            answered = [i for i in ins if per[i["id"]]["n"]]
            gap = sum((100 - per[i["id"]]["avg"]) * (1.5 if i["primary"] == c else 1) for i in answered)
            cap[c] = dict(avg=_avg([i["id"] for i in ins]), gap=gap, kind=kind,
                          injects=[i["id"] for i in ins],
                          obs=sorted({o for i in ins for o in i["ob"]}),
                          maturity=maturity_of(_avg([i["id"] for i in ins])))

    # Exercise objectives.
    objectives = {}
    for key, (name, _desc, _kind) in OBJECTIVES.items():
        ins = [i["id"] for i in injects if key in i["objs"]]
        if ins:
            objectives[key] = dict(avg=_avg(ins), injects=ins, maturity=maturity_of(_avg(ins)))

    # Framework rollups: identifier -> readiness across every inject carrying it.
    fw = {}
    for f in FRAMEWORK_ORDER:
        field = FIELD[f]
        idents = {}
        for i in injects:
            for ident in i.get(field, []):
                idents.setdefault(ident, []).append(i["id"])
        fw[f] = {ident: dict(avg=_avg(inj_ids), injects=inj_ids,
                             maturity=maturity_of(_avg(inj_ids)),
                             name=(OBS.get(ident) if f == "cisco" else name_for(f, ident)))
                 for ident, inj_ids in sorted(idents.items())}

    # Lifecycle phases.
    phases = {}
    for i in injects:
        phases.setdefault(i["phase"], []).append(i["id"])
    phase = {p: dict(avg=_avg(v), injects=v) for p, v in phases.items()}

    total = len(a)
    answered_ids = [i for i in ids if per[i]["n"]]
    return dict(
        people=int(a["pid"].nunique()) if total else 0,
        answers=total,
        overall=float(a["score"].mean()) if total else None,
        dk=float(a["dk"].mean() * 100) if total else None,
        gaps=sum(1 for s in per.values() if s["n"] and s["avg"] < 40),
        coverage=len(answered_ids) / len(ids) * 100 if ids else 0.0,
        maturity=maturity_of(float(a["score"].mean()) if total else None),
        per=per, ob=ob, cap=cap, objectives=objectives, fw=fw, phase=phase,
        injects=injects,
    )


# ------------------------------------------------------------------ findings
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Strength"]
SEV_RANK = {s: n for n, s in enumerate(SEVERITY_ORDER)}


def _severity(avg, dk_rate, spread):
    if avg is None:
        return None
    if avg < 25:
        return "Critical"
    if avg < 40:
        return "High"
    if avg < 60:
        return "Medium"
    if avg < 75:
        return "Low"
    if dk_rate >= .3 or spread >= 30:
        return "Low"
    return "Strength"


HORIZON = {"Critical": "30 days", "High": "30 days", "Medium": "60 days",
           "Low": "90 days", "Strength": "Maintain"}


def findings(A):
    """Turn the aggregate into an after-action finding list, most severe first.

    One finding per situation that scored below the strength threshold, carrying its
    evidence, the frameworks it touches and the recommendation drawn from that
    situation's own "what good looks like" for the capability that should have caught it.
    """
    out = []
    for inj in A["injects"]:
        s = A["per"][inj["id"]]
        if not s["n"]:
            continue
        dk_rate = s["dk"] / s["n"]
        sev = _severity(s["avg"], dk_rate, s["spread"])
        if sev is None:
            continue
        primary = inj["primary"]
        recs = [g for g in inj["good"] if g[0] == primary] or list(inj["good"])
        caps = caps_map(inj["kind"])
        flags = []
        if dk_rate >= .3:
            flags.append(f"{round(dk_rate * 100)}% answered \"don't know\"")
        if s["spread"] >= 30:
            flags.append("the room disagreed sharply")
        if s["first"]:
            top = max(s["first"], key=s["first"].get)
            if top != primary and sev not in ("Strength",):
                flags.append(f"the room expected {caps.get(top, top)} to catch it first, "
                             f"not {caps.get(primary, primary)}")
        out.append(dict(
            id=f"F-{inj['id']}",
            inject=inj["id"],
            kind=inj["kind"],
            title=inj["title"],
            severity=sev,
            horizon=HORIZON[sev],
            readiness=s["avg"],
            maturity=maturity_of(s["avg"]),
            responses=s["n"],
            capability=caps.get(primary, primary),
            objectives=inj["objs"],
            phase=inj["phase"],
            flags=flags,
            recommendation=recs[0][1] if recs else "",
            outcome=recs[0][2] if recs else "",
            frameworks={f: inj.get(FIELD[f], []) for f in FRAMEWORK_ORDER},
            target=inj.get("target", ""),
        ))
    out.sort(key=lambda f: (SEV_RANK[f["severity"]], f["readiness"] if f["readiness"] is not None else 0))
    return out


def roadmap(fs):
    """Findings grouped into the 30/60/90-day plan an after-action report closes with."""
    plan = {}
    for f in fs:
        if f["severity"] == "Strength":
            continue
        plan.setdefault(f["horizon"], []).append(f)
    return [(h, plan[h]) for h in ("30 days", "60 days", "90 days") if h in plan]


HOTWASH = [
    ("What surprised you?", "The answer most often names a control everyone assumed someone else owned."),
    ("Where did we disagree about our own environment?", "Disagreement is a finding in itself: it means no single person can answer for the system."),
    ("Which decision would we have made differently with ten more minutes?", "Separates a capability gap from a decision-speed gap."),
    ("What did we claim that we could not evidence?", "Everything here becomes an 'unverified' finding needing technical validation."),
    ("What is the single change that would have broken this attack chain earliest?", "Drives the first item of the 30-day plan."),
]


def sample_answers(n_people=6, seed=7, injects=None):
    """Fictional answers for previewing the dashboards. Never written to the database."""
    injects = list(injects) if injects is not None else list(INJECTS)
    rnd = random.Random(seed)
    bias = {"1.1": .6, "1.2": .3, "2.1": .5, "2.2": .35, "3.1": .25, "3.2": .2, "3.3": .15, "4.1": .2,
            "4.2": .25, "5.1": .45, "5.2": .4, "6.1": .4, "6.2": .55, "7.1": .3, "7.2": .35, "7.3": .4,
            "E1": .35, "E2": .3, "E3": .2, "E4": .25, "E5": .3, "E6": .2, "E7": .15}
    parts, rows = [], []
    for p in range(n_people):
        pid = f"sample{p}"
        role = ALL_ROLES[p % len(ALL_ROLES)]
        parts.append(dict(pid=pid, code="sample", name=f"Example {p + 1}", role=role, org="", created_at=0))
        for inj in injects:
            b = bias.get(inj["id"], .3)
            r = rnd.random() * .6 + b * .8
            dkeys = list(decide_map(inj["kind"]))
            # dkeys run best -> worst, with "don't know" last.
            d = (dkeys[0] if r > .85 else dkeys[1] if r > .6 else dkeys[2] if r > .4
                 else (dkeys[3] if rnd.random() > .5 else dkeys[-1]))
            o = "runbook" if rnd.random() < b else ("owner" if rnd.random() < .5 else "none")
            f = inj["primary"] if rnd.random() < b + .2 else ("none" if rnd.random() < .5 else "dk")
            rows.append(dict(pid=pid, code="sample", inject=inj["id"], act="", d=d, f=f, o=o, at=0))
    return pd.DataFrame(parts), pd.DataFrame(rows)
