"""The two ways this exercise can be run, and what each one produces.

A Mandiant tabletop is scoped before it is delivered: who is in the room decides
which injects are played, how long it takes, and what the after-action report can
conclude. These two definitions are what a facilitator picks between at setup, and
what participants read so they know what they are being asked to do.
"""

TRACK_TECHNICAL = "technical"
TRACK_FULL = "full"

TRACKS = {
    TRACK_TECHNICAL: dict(
        name="Technical track",
        tagline="One room of practitioners, 16 technical situations, 4 hours.",
        what_it_is=(
            "A control-validation exercise. Practitioners walk the attack from build-time supply "
            "chain through runtime to recovery, and answer for each step whether the organization "
            "would detect it, what would catch it first, and who owns the decision. The adversary "
            "is played by the facilitator; the room does not have to improvise a response, it has "
            "to say what exists today."
        ),
        who=(
            "AI platform and security engineering, agent and reliability engineering, cloud and "
            "infrastructure, SOC, data and knowledge owners, and a CISO delegate. 6 to 14 people "
            "in one room."
        ),
        duration="Half day: 4 hours of play plus a 45-minute hotwash.",
        answers_the_question=(
            "\"If this attack ran against our agents today, which layer would see it, and could we "
            "stop it before money moved or data left?\""
        ),
        outcome=[
            "Readiness score per situation, per Cisco taxonomy objective and per capability, with the "
            "room's disagreement and \"don't know\" rate made visible.",
            "A detection-coverage map: where the room believes the first catch sits versus where the "
            "architecture actually puts it.",
            "Capability maturity ratings across the eight control capabilities.",
            "An after-action report with prioritized technical findings and a 30/60/90-day plan.",
        ],
        does_not_cover=[
            "Regulatory notification clocks and who starts them.",
            "Crisis communications, legal privilege and board reporting.",
            "Whether an executive would actually authorize the containment the engineers propose.",
        ],
        proves=(
            "Technical detection and response capability against agentic attack techniques."
        ),
        cannot_prove=(
            "That the organization can run the incident. A room that detects everything can still "
            "miss a 72-hour notification deadline or contradict itself in public."
        ),
    ),
    TRACK_FULL: dict(
        name="Full engagement",
        tagline="Technical room plus an executive room, 16 + 7 situations, two sessions.",
        what_it_is=(
            "The technical track, plus a parallel executive track in which the crisis-management "
            "group receives the same incident as it would in reality: partial, late and contested. "
            "The two rooms are deliberately coupled. Executives decide on what the technical room "
            "escalated, not on the ground truth, so the exercise tests the escalation path itself "
            "and not just the two rooms separately."
        ),
        who=(
            "Everyone in the technical track, plus CISO, CIO or CTO, General Counsel or privacy "
            "counsel, Communications, Finance, the business process owner for payments, Risk and "
            "Compliance, and an executive sponsor. 12 to 25 people across two rooms."
        ),
        duration=(
            "Two sessions: a 4-hour technical session, then a 2.5-hour executive session seeded "
            "with what the technical room actually produced. Joint 60-minute hotwash."
        ),
        answers_the_question=(
            "\"Would we detect it, would the right people hear about it in time, and would we make "
            "defensible decisions on money, disclosure and customers while it was still running?\""
        ),
        outcome=[
            "Everything the technical track produces.",
            "Decision-readiness per executive situation: notification clocks, authority to contain, "
            "disclosure thresholds and the evidence each decision depends on.",
            "An escalation-path finding: what the technical room knew, what it escalated, what the "
            "executive room believed, and where those three diverged.",
            "Maturity ratings against NIST CSF 2.0 GOVERN and RESPOND, which the technical track "
            "alone cannot evidence.",
            "A combined after-action report separating technical remediation from governance actions, "
            "each with an owner and a 30/60/90-day horizon.",
        ],
        does_not_cover=[
            "Live systems. Nothing is executed against production; this remains a discussion-based exercise.",
            "Individual performance. Observations are recorded against processes, never against people.",
        ],
        proves=(
            "Whether detection, escalation and executive decision-making hold together as one chain "
            "under a live agentic incident."
        ),
        cannot_prove=(
            "Technical efficacy of a specific control. A tabletop records what the room believes and "
            "can evidence; it is not a purple-team test. Findings marked \"unverified\" need a "
            "follow-up technical validation."
        ),
    ),
}

TRACK_ORDER = [TRACK_TECHNICAL, TRACK_FULL]

# Which inject families each track plays.
TRACK_PLAYS = {
    TRACK_TECHNICAL: dict(technical=True, executive=False),
    TRACK_FULL: dict(technical=True, executive=True),
}


def plays_executive(track):
    return TRACK_PLAYS.get(track, TRACK_PLAYS[TRACK_TECHNICAL])["executive"]


def track_def(track):
    return TRACKS.get(track, TRACKS[TRACK_TECHNICAL])
