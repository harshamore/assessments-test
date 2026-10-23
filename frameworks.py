"""Framework catalogues used to report the exercise.

The Cisco Integrated AI Security and Safety Framework stays the spine: every inject
carries its OB objective and AITech identifiers, and each framework below is a lens
over that same set of injects rather than a competing taxonomy. A finding is written
once and then expressed in whichever framework the audience governs by.

ID accuracy: ATT&CK, CSF 2.0, AI RMF and OWASP identifiers here are stable and were
chosen conservatively. MITRE ATLAS is versioned more aggressively than the others, so
ATLAS technique IDs should be re-checked against the current matrix before a report
leaves the building; where a precise sub-technique was uncertain, the parent technique
is used instead of inventing a number.
"""

FRAMEWORKS = {
    "cisco": dict(
        name="Cisco AI Security Framework",
        body="Cisco",
        version="Integrated AI Security and Safety Framework (arXiv 2512.12921)",
        purpose="The exercise's native taxonomy: 19 adversary objectives (OB) and the techniques beneath them.",
        audience="AI platform and security engineering",
        role="Spine. Injects are authored against this, and every other view is derived from it.",
    ),
    "attack": dict(
        name="MITRE ATT&CK",
        body="MITRE",
        version="Enterprise",
        purpose="Places the agentic activity inside the intrusion the SOC already knows how to reason about.",
        audience="SOC, detection engineering, threat hunting",
        role="Shows which parts of this attack existing detections could plausibly cover, and which fall outside them.",
    ),
    "atlas": dict(
        name="MITRE ATLAS",
        body="MITRE",
        version="Adversarial Threat Landscape for AI Systems",
        purpose="Covers the AI-specific steps ATT&CK does not model: prompt injection, model poisoning, inference abuse.",
        audience="AI security engineering, red team",
        role="Pairs with ATT&CK. Where both apply, ATLAS describes the AI mechanism and ATT&CK the resulting action.",
    ),
    "csf": dict(
        name="NIST CSF 2.0",
        body="NIST",
        version="2.0",
        purpose="Rates organizational capability across GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND and RECOVER.",
        audience="CISO, risk committee, board",
        role="Carries the maturity ratings in the after-action report. GOVERN and RESPOND are only evidenced when the executive track is played.",
    ),
    "airmf": dict(
        name="NIST AI RMF + ISO/IEC 42001",
        body="NIST / ISO",
        version="AI RMF 1.0 and ISO/IEC 42001:2023",
        purpose="Frames the findings as AI governance obligations rather than security controls.",
        audience="Risk, compliance, internal audit, AI governance board",
        role="Translates gaps into management-system language for organizations certifying or reporting against these.",
    ),
    "owasp": dict(
        name="OWASP LLM + Agentic Top 10",
        body="OWASP",
        version="Top 10 for LLM Applications 2025; Agentic AI Threats and Mitigations",
        purpose="The taxonomy application and platform engineers already build against.",
        audience="Application and agent developers",
        role="Turns findings into backlog items a development team can act on without translation.",
    ),
}
FRAMEWORK_ORDER = ["cisco", "attack", "atlas", "csf", "airmf", "owasp"]

# ---------------------------------------------------------------- MITRE ATT&CK
ATTACK_TACTICS = {
    "TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access",
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access", "TA0007": "Discovery",
    "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0011": "Command and Control",
    "TA0010": "Exfiltration", "TA0040": "Impact",
}
ATTACK_TECHNIQUES = {
    "T1195": "Supply Chain Compromise",
    "T1195.001": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
    "T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",
    "T1204": "User Execution",
    "T1059": "Command and Scripting Interpreter",
    "T1059.006": "Command and Scripting Interpreter: Python",
    "T1505": "Server Software Component",
    "T1546": "Event Triggered Execution",
    "T1036": "Masquerading",
    "T1027": "Obfuscated Files or Information",
    "T1070": "Indicator Removal",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1528": "Steal Application Access Token",
    "T1550": "Use Alternate Authentication Material",
    "T1078": "Valid Accounts",
    "T1098": "Account Manipulation",
    "T1213": "Data from Information Repositories",
    "T1119": "Automated Collection",
    "T1114": "Email Collection",
    "T1534": "Internal Spearphishing",
    "T1071": "Application Layer Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1567": "Exfiltration Over Web Service",
    "T1565": "Data Manipulation",
    "T1565.001": "Data Manipulation: Stored Data Manipulation",
    "T1657": "Financial Theft",
    "T1499": "Endpoint Denial of Service",
    "T1499.003": "Endpoint Denial of Service: Application Exhaustion Flood",
    "T1496": "Resource Hijacking",
    "T1486": "Data Encrypted for Impact",
}

# ---------------------------------------------------------------- MITRE ATLAS
ATLAS_TACTICS = {
    "AML.TA0002": "Reconnaissance", "AML.TA0003": "Resource Development",
    "AML.TA0004": "Initial Access", "AML.TA0000": "AI Model Access",
    "AML.TA0005": "Execution", "AML.TA0006": "Persistence",
    "AML.TA0012": "Privilege Escalation", "AML.TA0007": "Defense Evasion",
    "AML.TA0008": "Discovery", "AML.TA0009": "Collection",
    "AML.TA0001": "AI Attack Staging", "AML.TA0010": "Exfiltration", "AML.TA0011": "Impact",
}
ATLAS_TECHNIQUES = {
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0018": "Manipulate AI Model",
    "AML.T0020": "Poison Training Data",
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0025": "Exfiltration via Cyber Means",
    "AML.T0029": "Denial of AI Service",
    "AML.T0034": "Cost Harvesting",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0070": "RAG Poisoning",
}

# ---------------------------------------------------------------- NIST CSF 2.0
CSF_FUNCTIONS = {
    "GV": ("GOVERN", "Strategy, expectations and policy for managing cybersecurity risk"),
    "ID": ("IDENTIFY", "Understanding assets, suppliers and risks"),
    "PR": ("PROTECT", "Safeguards to manage risk"),
    "DE": ("DETECT", "Finding and analysing adverse events"),
    "RS": ("RESPOND", "Acting on a detected incident"),
    "RC": ("RECOVER", "Restoring assets and operations"),
}
CSF_FUNCTION_ORDER = ["GV", "ID", "PR", "DE", "RS", "RC"]
CSF_CATEGORIES = {
    "GV.RR": "Roles, Responsibilities and Authorities",
    "GV.PO": "Policy",
    "GV.OV": "Oversight",
    "GV.SC": "Cybersecurity Supply Chain Risk Management",
    "GV.RM": "Risk Management Strategy",
    "ID.AM": "Asset Management",
    "ID.RA": "Risk Assessment",
    "ID.IM": "Improvement",
    "PR.AA": "Identity Management, Authentication and Access Control",
    "PR.DS": "Data Security",
    "PR.PS": "Platform Security",
    "PR.IR": "Technology Infrastructure Resilience",
    "DE.CM": "Continuous Monitoring",
    "DE.AE": "Adverse Event Analysis",
    "RS.MA": "Incident Management",
    "RS.AN": "Incident Analysis",
    "RS.CO": "Incident Response Reporting and Communication",
    "RS.MI": "Incident Mitigation",
    "RC.RP": "Incident Recovery Plan Execution",
    "RC.CO": "Incident Recovery Communication",
}

# ------------------------------------------------- NIST AI RMF 1.0 and ISO/IEC 42001
AIRMF_FUNCTIONS = {
    "GOVERN": "A culture of AI risk management is cultivated and present",
    "MAP": "Context is recognised and risks related to context are identified",
    "MEASURE": "Identified risks are assessed, analysed and tracked",
    "MANAGE": "Risks are prioritised and acted upon based on projected impact",
}
AIRMF_CATEGORIES = {
    "GOVERN 1": "Policies, processes and procedures for AI risk are in place and transparent",
    "GOVERN 2": "Accountability structures are in place; roles and responsibilities are documented",
    "GOVERN 4": "Organizational teams are committed to a culture that considers AI risk",
    "GOVERN 5": "Processes are in place for robust stakeholder engagement and feedback",
    "GOVERN 6": "Policies address AI risks from third-party software, data and supply chain",
    "MAP 1": "Context is established and understood",
    "MAP 2": "Categorization of the AI system is performed",
    "MAP 4": "Risks and benefits are mapped for all third-party components",
    "MAP 5": "Impacts to individuals, groups and society are characterised",
    "MEASURE 1": "Appropriate methods and metrics are identified and applied",
    "MEASURE 2": "AI systems are evaluated for trustworthy characteristics",
    "MEASURE 3": "Mechanisms for tracking identified AI risks over time are in place",
    "MEASURE 4": "Feedback about efficacy of measurement is gathered and assessed",
    "MANAGE 1": "AI risks are prioritised, responded to and managed",
    "MANAGE 2": "Strategies to maximise benefits and minimise negative impacts are planned",
    "MANAGE 3": "AI risks from third-party entities are managed",
    "MANAGE 4": "Risk treatments are documented and monitored over time",
}
ISO42001_CONTROLS = {
    "A.2": "AI policy",
    "A.3": "Internal organization: roles and responsibilities for AI",
    "A.4": "Resources for AI systems",
    "A.5": "Assessing impacts of AI systems",
    "A.6": "AI system life cycle: responsible development and deployment",
    "A.7": "Data for AI systems",
    "A.8": "Information for interested parties",
    "A.9": "Use of AI systems",
    "A.10": "Third-party and customer relationships",
}

# ---------------------------------------------------------------- OWASP
OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}
OWASP_AGENTIC = {
    "T1": "Memory Poisoning",
    "T2": "Tool Misuse",
    "T3": "Privilege Compromise",
    "T4": "Resource Overload",
    "T5": "Cascading Hallucination Attacks",
    "T6": "Intent Breaking and Goal Manipulation",
    "T7": "Misaligned and Deceptive Behaviours",
    "T8": "Repudiation and Untraceability",
    "T9": "Identity Spoofing and Impersonation",
    "T10": "Overwhelming Human-in-the-Loop",
    "T11": "Unexpected Code Execution",
    "T12": "Agent Communication Poisoning",
    "T13": "Rogue Agents in Multi-Agent Systems",
    "T14": "Human Attacks on Multi-Agent Systems",
    "T15": "Human Manipulation",
}

# Catalogue lookup per framework key: (label, {id: name}) pairs shown in that tab.
CATALOGUES = {
    "attack": [("Tactics", ATTACK_TACTICS), ("Techniques", ATTACK_TECHNIQUES)],
    "atlas": [("Tactics", ATLAS_TACTICS), ("Techniques", ATLAS_TECHNIQUES)],
    "csf": [("Categories", CSF_CATEGORIES)],
    "airmf": [("AI RMF categories", AIRMF_CATEGORIES), ("ISO/IEC 42001 Annex A", ISO42001_CONTROLS)],
    "owasp": [("Top 10 for LLM Applications", OWASP_LLM), ("Agentic AI threats", OWASP_AGENTIC)],
}

# Which inject field holds each framework's identifiers.
FIELD = {
    "cisco": "ob", "attack": "attack", "atlas": "atlas",
    "csf": "csf", "airmf": "airmf", "owasp": "owasp",
}


def name_for(framework, ident):
    """Human name for an identifier, tolerant of sub-technique and unknown IDs."""
    for _, cat in CATALOGUES.get(framework, []):
        if ident in cat:
            return cat[ident]
    if framework == "csf":
        return CSF_CATEGORIES.get(ident, ident)
    if framework == "airmf":
        return AIRMF_CATEGORIES.get(ident) or ISO42001_CONTROLS.get(ident, ident)
    if framework == "owasp":
        # Agentic threat IDs are stored with an "A:" prefix so T1..T15 cannot collide
        # with ATT&CK-style identifiers elsewhere in the inject.
        if ident.startswith("A:"):
            key = ident[2:]
            return f"Agentic: {OWASP_AGENTIC.get(key, key)}"
        return OWASP_LLM.get(ident) or OWASP_AGENTIC.get(ident, ident)
    base = ident.split(".")[0]
    for _, cat in CATALOGUES.get(framework, []):
        if base in cat:
            return f"{cat[base]} (sub-technique {ident})"
    return ident
