"""The executive track, played only in the full engagement.

Design principle, and the reason this is not just "more questions": the executive room is
seeded with what the technical room actually escalated, not with ground truth. If the
technical room never escalated the memory poisoning, the executives decide on disclosure
without knowing about it. That mismatch is the finding most organizations have never seen,
and it is invisible if the two groups are exercised separately.

Regulatory clocks below are the ones counsel is most often required to assess. Which apply
depends entirely on jurisdiction, sector and contract, and the facilitator is expected to
replace this list with the customer's actual obligations during scoping. They are stated as
assessment triggers, not as legal advice.
"""

EXEC_ROLES = [
    "CISO or deputy", "CIO or CTO", "General Counsel or privacy counsel",
    "Communications lead", "CFO or finance lead", "Business process owner (payments)",
    "Risk and compliance lead", "CEO or executive sponsor", "Board or audit committee observer",
]

# Governance capabilities, the executive-track equivalent of the technical capability set.
EXEC_CAPS = {
    "escalate": "Escalation and incident classification",
    "authority": "Decision authority and delegation",
    "legal": "Legal and regulatory assessment",
    "comms": "Communications and disclosure",
    "business": "Business continuity trade-off",
    "evidence": "Evidence and record-keeping",
    "external": "Law enforcement, insurer and third parties",
}
EXEC_CAP_ORDER = list(EXEC_CAPS)

# Answer scales for the executive track. Same three-question shape as the technical track,
# so storage and scoring are unchanged, but the questions are decision questions.
EXEC_DECIDE = {
    "documented": ("Yes, against a documented process", 100),
    "improvised": ("Probably, but we would improvise it", 60),
    "late": ("Not inside the time available", 30),
    "no": ("No", 0),
    "dk": ("Don't know", 0),
}
EXEC_FIRST = {
    "ciso": "CISO or security leadership",
    "legal": "General Counsel or privacy counsel",
    "comms": "Communications",
    "cfo": "CFO or finance",
    "business": "Business process owner",
    "risk": "Risk and compliance",
    "ceo": "CEO or executive sponsor",
    "board": "Board or audit committee",
    "none": "No one owns this today",
    "dk": "Don't know",
}

REGULATORY_CLOCKS = [
    ("GDPR Art. 33", "72 hours from awareness", "Notify the supervisory authority of a personal data breach.",
     "EU/UK personal data in the leaked report or telemetry."),
    ("GDPR Art. 34", "Without undue delay", "Notify affected data subjects where risk to them is high.",
     "Card data and customer records exposed."),
    ("SEC Form 8-K Item 1.05", "4 business days from the materiality determination",
     "Disclose a material cybersecurity incident.", "US-listed registrant. Note the clock starts at the "
     "materiality decision, not at discovery, which makes the decision itself the controlled event."),
    ("PCI DSS", "Promptly, per acquirer and brand rules", "Notify acquirer and card brands of account-data compromise.",
     "A primary account number appeared in an agent-written report."),
    ("US state breach statutes", "Varies: 'without unreasonable delay' to fixed 30-60 day caps",
     "Notify residents and sometimes attorneys general.", "Customer residency determines which apply."),
    ("NIS2", "24-hour early warning, 72-hour notification", "Notify the competent authority.",
     "EU essential or important entity."),
    ("DORA", "Within hours of classification", "Report a major ICT-related incident.",
     "EU financial entity. Tightest clock in this list."),
    ("Customer and supplier contracts", "Often 24-48 hours", "Contractual breach-notice obligations.",
     "Usually the earliest real deadline, and the one most often missed."),
]

EXEC_MODULES = {
    8: ("Escalation and first decisions", "Executive track"),
    9: ("Disclosure and obligation", "Executive track"),
    10: ("Pressure and public account", "Executive track"),
    11: ("Authority, recovery and attestation", "Executive track"),
}

EXEC_INJECTS = [
    dict(id="E1", kind="executive", m=8, t="T+1:10", title="An escalation you cannot yet confirm",
         text="The SOC lead calls: the AI assistant may have been manipulated into changing supplier bank "
              "details. Eleven records are implicated. Nothing is confirmed, no customer data is known to be "
              "involved, and the engineers are still reading traces. They want to know whether to treat this "
              "as an incident, and they are asking you to decide with roughly 40% of the picture.",
         caps=["escalate", "authority"], primary="escalate",
         phase="response", objs=["EX-9"],
         delivery="A phone call, played live by the facilitator, with deliberately incomplete information.",
         csf=["RS.MA", "GV.RR", "DE.AE"], airmf=["GOVERN 2", "MANAGE 1", "A.3"], owasp=["A:T8"],
         clocks=[],
         good=[("escalate", "A severity classification exists that does not require confirmation to assign",
                "Incident declared on suspicion; clocks noted as provisional"),
               ("authority", "A named person can declare an incident without assembling a committee first",
                "Crisis group convened inside 30 minutes"),
               ("evidence", "The time of awareness is recorded deliberately, because several clocks start from it",
                "Defensible timeline from the first minute")],
         disc=["Who can declare this an incident at 40% confidence, and do they need anyone's permission?",
               "Does your classification scheme have a severity that fits 'AI agent may have been manipulated'?",
               "What is recorded as the moment of awareness, and who records it?"],
         probe="If this turns out to be nothing, was declaring it an incident the wrong call? Does your process punish a false positive?",
         evaluate=["Whether an incident is declared at all during this inject, or deferred for more information.",
                   "Whether anyone identifies that awareness-time starts regulatory clocks.",
                   "Whether the classification scheme accommodates AI-specific incidents.",
                   "Time from inject to a stated decision."],
         target="Incident declared and crisis group convened within 30 minutes, on incomplete information."),

    dict(id="E2", kind="executive", m=8, t="T+1:50", title="The payment run is in six hours",
         text="Eleven supplier bank records may be wrong. The month-end payment run executes in six hours and "
              "covers 2,400 payments worth £18m, of which the 11 suppliers account for £310k. Holding the whole "
              "run breaches payment terms with every supplier and will be visible. Releasing it may send £310k "
              "to an attacker. Finance wants a decision now; engineering cannot yet confirm which records changed.",
         caps=["business", "authority", "evidence"], primary="business",
         phase="response", objs=["EX-9", "EX-11"],
         delivery="The CFO participant is handed the payment-run summary and asked for a go/no-go.",
         csf=["RS.MI", "GV.RR", "RS.MA"], airmf=["MANAGE 1", "MANAGE 2", "GOVERN 2", "A.9"], owasp=["LLM06"],
         clocks=[],
         good=[("business", "A partial hold is possible: suppress named payees without stopping the run",
                "£310k held, 2,389 payments proceed"),
               ("authority", "The authority to hold a payment run is pre-agreed and does not need the CEO",
                "Decision inside the window"),
               ("evidence", "The 11 records can be listed with before-and-after values",
                "Hold is targeted rather than precautionary")],
         disc=["Can you suppress specific payees inside a run, or is it all or nothing?",
               "Who authorises holding an £18m run, and what if they are unreachable?",
               "If you release and are wrong, can the payments be recalled, and within what window?"],
         probe="Your ERP cannot suppress individual payees mid-run. What is the decision now?",
         evaluate=["Whether a partial hold is technically available, or assumed to be.",
                   "Whether the decision-maker is identified without debate.",
                   "Whether anyone asks about payment recall windows.",
                   "Whether the business impact is quantified or asserted."],
         target="A targeted hold decision inside the six-hour window, with the affected payees enumerated."),

    dict(id="E3", kind="executive", m=9, t="T+2:30", title="Customer data is in scope, and the clocks start",
         text="Engineering confirms the Reporter agent wrote a customer's primary account number and a live API "
              "key into a report distributed to 14 internal recipients, and that full prompts, including customer "
              "records, have been retained in agent traces for eleven months. Counsel must now determine what "
              "has been triggered, and the materiality assessment for disclosure has to begin.",
         caps=["legal", "evidence", "comms"], primary="legal",
         phase="response", objs=["EX-10"],
         delivery="A written engineering findings summary handed to counsel, with the retention detail buried in paragraph four.",
         csf=["RS.CO", "GV.PO", "PR.DS", "RS.AN"],
         airmf=["GOVERN 1", "MAP 5", "MANAGE 4", "A.5", "A.8"], owasp=["LLM02", "A:T8"],
         clocks=["GDPR Art. 33", "GDPR Art. 34", "SEC Form 8-K Item 1.05", "PCI DSS",
                 "US state breach statutes", "Customer and supplier contracts"],
         good=[("legal", "A named owner for the materiality determination, and a documented method",
                "Determination made and dated, starting the disclosure clock deliberately"),
               ("evidence", "The set of affected data subjects can be established from logs",
                "Notification scoped to fact rather than to worst case"),
               ("comms", "Draft notifications exist as templates before the incident",
                "Hours saved on the tightest clock")],
         disc=["Who determines materiality here, and is the method written down?",
               "Eleven months of prompts in telemetry: is that a second breach, and who is its data controller?",
               "Which of your clocks is shortest, and does anyone know it without looking it up?"],
         probe="The 72-hour clock started at the first escalation, not at this confirmation. How much of it is left?",
         evaluate=["Whether the room identifies the retention finding as a separate exposure.",
                   "Whether materiality ownership is clear or contested.",
                   "Whether anyone correctly identifies which clock is tightest for this organization.",
                   "Whether awareness-time from E1 is carried forward correctly."],
         target="Obligations enumerated and materiality owner named within the session; shortest clock identified correctly."),

    dict(id="E4", kind="executive", m=10, t="T+3:00", title="Extortion, with a sample attached",
         text="The CFO receives an email containing 50 genuine customer records and a demand: $2.4m in bitcoin "
              "within 48 hours, or the full set, said to be 240,000 records, goes to customers, the regulator and "
              "a journalist already named in the email. The sender knows the payment run was held, which means "
              "they still have visibility into something.",
         caps=["external", "legal", "authority", "comms"], primary="external",
         phase="mission", objs=["EX-9", "EX-11"],
         delivery="The email is read aloud to the executive room, attachments described.",
         csf=["RS.MA", "RS.CO", "GV.RR"], airmf=["MANAGE 1", "GOVERN 2", "A.3", "A.10"], owasp=[],
         clocks=["Customer and supplier contracts", "US state breach statutes"],
         good=[("external", "Law enforcement contact, insurer notification and a ransom position all pre-decided",
                "No improvisation under a 48-hour deadline"),
               ("legal", "Sanctions screening and privilege handled before any contact",
                "Engagement, if any, is lawful and privileged"),
               ("authority", "A standing position on payment, and who may depart from it",
                "Decision does not escalate to an emergency board call"),
               ("comms", "The fact that they know about the payment hold is treated as an intelligence problem",
                "Containment reassessed; comms channel assumed compromised")],
         disc=["Do you have a documented position on paying, and who can override it?",
               "Who contacts law enforcement, and does your cyber policy require the insurer first?",
               "They know you held the payment run. Which of your channels do you now treat as compromised?"],
         probe="Your crisis bridge runs on the same email and collaboration platform the agents can read. Where do you move?",
         evaluate=["Whether anyone notices the leak of the payment-hold decision and acts on it.",
                   "Whether a ransom position exists before the question is asked.",
                   "Whether insurer and law-enforcement sequencing is known.",
                   "Whether the 240,000 figure is challenged or accepted."],
         target="Standing extortion position applied without a new decision; out-of-band comms established."),

    dict(id="E5", kind="executive", m=10, t="T+3:20", title="One public account, four audiences",
         text="A journalist emails Communications: \"Can you confirm your AI system exposed customer payment "
              "data and that you paid suppliers into fraudulent accounts?\" Deadline is two hours. Separately, a "
              "supplier has posted on LinkedIn that Meridian redirected their payment, and the post is being shared. "
              "Customers are beginning to call. The board chair asks to be briefed before anything is said publicly.",
         caps=["comms", "legal", "authority"], primary="comms",
         phase="mission", objs=["EX-11", "EX-10"],
         delivery="Two injects 10 minutes apart: the journalist email, then the LinkedIn post on screen.",
         csf=["RS.CO", "RC.CO", "GV.RR"], airmf=["GOVERN 5", "MAP 5", "A.8"], owasp=["LLM09"],
         clocks=["GDPR Art. 34", "SEC Form 8-K Item 1.05"],
         good=[("comms", "A holding statement exists and is approved for release without a new drafting cycle",
                "Public account inside the two-hour deadline"),
               ("legal", "What can be said without prejudicing privilege or pre-empting the materiality determination",
                "No admission that constrains the disclosure decision"),
               ("authority", "One named spokesperson; everyone else declines",
                "No contradictory accounts from staff or suppliers")],
         disc=["Who speaks, and who has explicitly agreed not to?",
               "Does anything you say to the journalist pre-empt the 8-K determination?",
               "The supplier is telling the truth publicly. Do you confirm, decline, or correct?"],
         probe="An engineer posts a technically accurate thread defending the architecture. What happens in the next hour?",
         evaluate=["Whether a holding statement exists already or is drafted live.",
                   "Whether the interaction between public statements and the materiality clock is recognised.",
                   "Whether a single spokesperson is named.",
                   "Whether internal communications to staff are considered at all."],
         target="Approved holding statement released inside the deadline, consistent with the disclosure position."),

    dict(id="E6", kind="executive", m=11, t="T+3:40", title="Engineering wants to shut it down",
         text="The technical room has asked for authority to take the whole assistant offline. It handles 70% of "
              "supplier correspondence and all first-line customer service; month-end close starts in three days. "
              "Engineering cannot promise that a narrower containment is sufficient, because the memory and "
              "knowledge-base contamination has not been fully scoped. The CISO is on a flight for the next two hours.",
         caps=["authority", "business", "escalate"], primary="authority",
         phase="response", objs=["EX-9", "EX-8"],
         delivery="A written containment request from the technical room, with its stated confidence level.",
         csf=["RS.MI", "GV.RR", "RS.MA"], airmf=["MANAGE 1", "MANAGE 2", "GOVERN 2", "A.9"], owasp=["LLM06"],
         clocks=[],
         good=[("authority", "Documented delegation for containment when the CISO is unreachable",
                "Decision in minutes, by a named deputy"),
               ("business", "The cost of a full shutdown per hour is already known",
                "Trade-off made on numbers, not instinct"),
               ("escalate", "A pre-agreed threshold at which business continuity stops outranking containment",
                "No negotiation during the incident")],
         disc=["Who decides this in the next ten minutes, with the CISO unreachable?",
               "Is there a pre-agreed threshold where containment automatically wins?",
               "What does an hour of the assistant being offline actually cost, and who holds that number?"],
         probe="You authorise a partial containment and it proves insufficient. Who is accountable for having chosen it?",
         evaluate=["Whether delegated authority is documented or assumed.",
                   "Whether the hourly cost of downtime is known to anyone present.",
                   "Whether a pre-agreed containment threshold exists.",
                   "Time from request to authorisation."],
         target="Containment authorised within 15 minutes by a named delegate, against a pre-agreed threshold."),

    dict(id="E7", kind="executive", m=11, t="T+4:10", title="Attest to it",
         text="A week on. The audit committee wants three things in writing: that the environment is clean, that "
              "disclosure obligations were met, and that controls have been remediated. The external auditor has "
              "asked whether the AI system's decisions can be reconstructed for the affected period. Your cyber "
              "insurer has requested the full incident timeline as a condition of the claim.",
         caps=["evidence", "legal", "comms", "external"], primary="evidence",
         phase="recovery", objs=["EX-10", "EX-11"],
         delivery="A written request from the audit committee chair, copied to the external auditor.",
         csf=["RC.CO", "RS.CO", "ID.IM", "GV.OV"],
         airmf=["GOVERN 1", "MANAGE 4", "MEASURE 4", "A.5", "A.8"], owasp=["A:T8"],
         clocks=["SEC Form 8-K Item 1.05"],
         good=[("evidence", "Agent decisions for the affected period can be reconstructed from retained traces",
                "Auditable answer rather than an assurance"),
               ("legal", "What was notified, when, and on what basis, all dated",
                "Disclosure defensible on the record"),
               ("comms", "One narrative that matches what was said publicly and to the regulator",
                "No inconsistency for the auditor to find"),
               ("external", "The insurer's timeline requirement was known before the incident",
                "Claim not prejudiced by missing records")],
         disc=["Can you reconstruct what the agents decided for every affected transaction?",
               "Who signs the statement that the environment is clean, and on what evidence?",
               "Does the account you gave the journalist still match the one you are about to give the auditor?"],
         probe="Trace retention was reduced to 30 days during the clean-up. The affected period is 11 weeks. What do you attest to now?",
         evaluate=["Whether reconstruction is possible, and whether anyone knows the retention period.",
                   "Whether a single consistent account survives contact with four audiences.",
                   "Whether signing authority for the attestation is clear.",
                   "Whether the insurer's evidentiary requirements were known in advance."],
         target="Attestation supported by retained evidence, consistent with every prior public and regulatory statement."),
]

EXEC_INJECT_IDS = [i["id"] for i in EXEC_INJECTS]
EXEC_BY_ID = {i["id"]: i for i in EXEC_INJECTS}

# The coupling between the rooms. Each pairing is a question the hotwash must answer.
ESCALATION_COUPLING = [
    ("3.1", "E1", "The invoice injection is what the SOC is escalating. Did the technical room detect it, and what did it say?"),
    ("3.2", "E2", "The 11 bank records come from the agent-to-agent escalation. Did the technical room scope them?"),
    ("5.2", "E3", "Counsel's data-exposure scope depends entirely on what the technical room found in the report and traces."),
    ("3.3", "E4", "The extortion sample's plausibility depends on whether the rogue agent's exfiltration succeeded."),
    ("7.1", "E5", "Communications can only be accurate if one timeline exists. 7.1 is where that is tested."),
    ("7.2", "E6", "The containment options offered to executives are exactly those the technical room said it could execute."),
    ("7.3", "E7", "The attestation rests on the eviction evidence from 7.3. If that was weak, this inject exposes it."),
]
