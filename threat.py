"""Threat intelligence underpinning the scenario.

A Mandiant tabletop is intel-led: the scenario is not invented to be dramatic, it is
assembled from tradecraft a named cluster has actually been observed using, so that
every inject can be defended as "this is what they do" rather than "this could happen".

UNC-QL is a FICTIONAL cluster created for this exercise. Its tradecraft is drawn from
patterns publicly reported across financially motivated intrusion and business email
compromise activity, and from published research on agentic and LLM attack techniques.
It is not an alias for any real tracked group, and the indicators below are synthetic.
"""

ACTOR = dict(
    designation="UNC-QL",
    nickname="\"Quiet Ledger\" operators",
    fictional=True,
    classification=(
        "Uncategorized cluster. Financially motivated. Assessed as a single operating group "
        "rather than an affiliate programme, on the basis of consistent tooling and a stable "
        "payment-redirection playbook across intrusions."
    ),
    motivation="Financial gain through supplier payment redirection, resold customer data, and extortion if redirection fails.",
    sophistication=(
        "Moderate to high. The group is not building novel exploits. Its advantage is that it has "
        "moved its tradecraft up a layer: it attacks the AI application's trust assumptions rather "
        "than the network perimeter, which keeps it inside behaviour that most security stacks "
        "still treat as legitimate application traffic."
    ),
    targeting=(
        "Mid-market and enterprise organizations that have put generative AI agents in the path of "
        "finance, procurement or customer-service workflows, and that grant those agents write access "
        "to ERP, CRM or payment systems. Sector-agnostic; selection is driven by agent capability, "
        "not industry."
    ),
    first_observed="Q2 2026 (exercise timeline)",
    confidence=(
        "Scenario confidence: high that these techniques are feasible against the architecture in "
        "scope; moderate that a single group chains all of them in one intrusion. The chain is "
        "deliberately compressed so a half-day exercise can cover build-time through recovery."
    ),
)

# What the group is known for, and why each matters here. Mapped to ATT&CK / ATLAS in content.py.
TRADECRAFT = [
    ("Supply-chain entry over network entry",
     "Prefers a poisoned model artifact or a look-alike tool integration to a phishing campaign. "
     "Lowers noise: the malicious component is installed by the victim's own engineers through an "
     "approved process."),
    ("Patience across the release boundary",
     "Publishes a benign component, waits for adoption and review to complete, then pushes a "
     "malicious update. Defeats intake-only review."),
    ("Instructions hidden in business documents",
     "Delivers payloads as text inside invoices, contracts and email threads, so that the agent "
     "retrieving the document executes the instruction. No malware on an endpoint."),
    ("Abuse of inter-agent trust",
     "Impersonates orchestration or approval messages so that one compromised agent escalates "
     "another. Where agents trust each other's output, one foothold becomes system-wide authority."),
    ("Durable persistence in memory and knowledge",
     "Writes false authorizations into long-term agent memory and edits policy sources the agents "
     "cite. Survives session end, model restart and credential rotation, which is what makes "
     "eviction hard to prove."),
    ("Living off the agent's own permissions",
     "Exfiltrates using the agent's sanctioned email and API tools rather than attacker "
     "infrastructure, so egress looks like normal application behaviour."),
    ("Extortion as the fallback",
     "If payment redirection is blocked, pivots to pressure: contacts the victim with evidence of "
     "the data it holds, and where regulators or customers can be alarmed, uses that as leverage."),
]

# Mandiant Targeted Attack Lifecycle. Each inject declares the phase it sits in, so the
# facilitator can show the room that this is one campaign, not sixteen unrelated incidents.
LIFECYCLE = {
    "recon": ("Initial reconnaissance", "Identify the target's agents, tools and the humans in the approval path"),
    "compromise": ("Initial compromise", "Get malicious capability inside the trust boundary"),
    "foothold": ("Establish foothold", "Gain reliable, repeatable influence over agent behaviour"),
    "privesc": ("Escalate privileges", "Acquire authority the agent was not granted"),
    "internal-recon": ("Internal reconnaissance", "Learn the business process, the limits and the data"),
    "lateral": ("Move laterally", "Spread influence from one agent or system to others"),
    "persist": ("Maintain presence", "Survive restart, rotation and remediation"),
    "mission": ("Complete mission", "Move money, take data, or apply pressure"),
    # Defender-side phases. Not part of the adversary lifecycle: these are the control
    # points where the organization acts, and they are scored like any other inject.
    "gate": ("Release gate (defender)", "A decision point where the organization chooses to ship or hold"),
    "response": ("Response (defender)", "Detection, correlation, escalation and containment while the attack runs"),
    "recovery": ("Recovery (defender)", "Eviction, proof of clean state and account to stakeholders"),
}
ADVERSARY_PHASES = ["recon", "compromise", "foothold", "privesc", "internal-recon", "lateral", "persist", "mission"]
DEFENDER_PHASES = ["gate", "response", "recovery"]
LIFECYCLE_ORDER = ADVERSARY_PHASES + DEFENDER_PHASES


def phase_name(key):
    return LIFECYCLE.get(key, (key, ""))[0]

# Intelligence the group would need, and what the defender can deny it. Drives the
# "what did we make hard for them" half of the hotwash.
COLLECTION_REQUIREMENTS = [
    ("Which agents hold write access to ERP or payment systems",
     "Published agent cards, verbose error messages, system prompts leaked in responses"),
    ("The auto-approval threshold and who can change it",
     "Knowledge-base policy pages the agents will quote on request"),
    ("Which tools an agent will accept without review",
     "Tool descriptions returned by MCP discovery; capability claims in A2A agent cards"),
    ("Whether anyone reviews agent memory",
     "Behavioural probing: write a benign false note and test whether it persists and is honoured"),
]

# Synthetic indicators. Present so the exercise can ask "could you search for this?",
# which is a far better question than "do you have the IOC".
INDICATORS = [
    ("Model artifact", "community fine-tune distributed as a .pkl/.bin with a custom loader", "Intake scan, model registry"),
    ("MCP server name", "single-character variant of an internal server name (crm-sync vs crm_sync)", "Tool allow-list, agent config diff"),
    ("A2A agent card", "unregistered card claiming validation capability, requesting peer system prompts", "Agent registry, A2A traces"),
    ("Memory artifact", "authorization note citing a control reference that does not exist (FIN-4120)", "Memory store audit"),
    ("Document payload", "instruction text split across pages or hidden in cell comments", "Gateway injection verdicts"),
    ("Egress", "agent email tool addressing a domain one edit away from a supplier domain", "Egress allow-list, flow logs"),
]

ASSUMPTIONS = [
    "The adversary has no credentialed access to the corporate network at T+0 and never obtains any.",
    "Every control the room claims is in place is assumed to work as described, until the exercise asks for evidence.",
    "The agents are in production and acting on live business systems, not in a pilot.",
    "No security tooling is assumed to be AI-aware unless a participant states that it is.",
]
