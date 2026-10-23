"""Technology options mapped to the capability gaps the exercise finds.

This is an annex, not the headline. A Mandiant-style after-action report leads with the
capability gap and the framework obligation; product selection is a later conversation.
The app keeps that order: findings first, this view second.

Vendor note. Cisco Secure AI Factory with NVIDIA spans Cisco UCS compute, Nexus /
Hyperfabric networking and NVIDIA systems, with storage from NetApp, Pure Storage,
VAST Data and Hitachi Vantara.

In August 2026 Cisco expanded the Secure AI Factory "for the rack-scale era" and added
Supermicro: Supermicro's liquid- and air-cooled rack-scale and dense GPU systems are
validated and sold as part of the broader Cisco AI infrastructure portfolio, available
through Cisco and its authorised channel partners from October 2026. Supermicro
complements rather than replaces Cisco UCS, as an additional high-density compute option.
  https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2026/m08/cisco-secure-ai-factory-nvidia-rack-scale.html
"""

LAYERS = {
    "infra": ("AI infrastructure", "GPU compute, storage and the platform open-weight models run on"),
    "network": ("Data centre networking", "Fabric, segmentation and egress control between workloads"),
    "runtime": ("Workload runtime security", "Kernel, process, file and identity-based enforcement inside the cluster"),
    "aisec": ("AI-specific security", "Controls that understand models, prompts, tools and agents"),
    "observe": ("Observability and SOC", "Agent-level and infrastructure telemetry, correlation and response"),
    "identity": ("Identity and access", "Who and what may call a model, a tool or a business system"),
}
LAYER_ORDER = ["aisec", "observe", "runtime", "network", "infra", "identity"]

# caps are the eight capability keys from content.CAPS.
PRODUCTS = {
    "aidefense-supply": dict(
        name="Cisco AI Defense: AI Supply Chain Risk Management", vendor="Cisco", layer="aisec",
        caps=["scan"],
        does="Scans model files, repositories, MCP servers and agent cards before they load: malicious code, "
             "unsafe deserialization, backdoors, name collisions and changed tool descriptions on rescan.",
        covers=["1.1", "1.2", "3.3", "7.3"],
    ),
    "aidefense-validate": dict(
        name="Cisco AI Defense: AI Model and Application Validation", vendor="Cisco", layer="aisec",
        caps=["redteam"],
        does="Algorithmic red teaming across roughly 200 threat categories, mapped to OWASP, MITRE and NIST, "
             "and generates guardrails tuned to the weaknesses it finds.",
        covers=["2.1", "7.3"],
    ),
    "aidefense-runtime": dict(
        name="Cisco AI Defense: AI Runtime Protection", vendor="Cisco", layer="aisec",
        caps=["guard"],
        does="Guardrails at the LLM gateway for prompt injection, jailbreak and sensitive data, in monitor, "
             "block or rewrite mode, per application and per agent.",
        covers=["2.1", "3.1", "3.2", "5.2", "6.2", "7.1", "7.2"],
    ),
    "splunk-agent-obs": dict(
        name="Splunk Agent Observability", vendor="Cisco (Splunk)", layer="observe",
        caps=["trace", "guard"],
        does="Traces every agent step, tool call and handoff with inputs and outputs. Evals such as Tool "
             "Selection Quality, Context Adherence and Action Completion; experiments that gate releases; "
             "token and cost tracking per workflow. Luna-2 guardrails turn evals into runtime controls.",
        covers=["1.2", "2.1", "2.2", "3.1", "3.2", "3.3", "4.1", "4.2", "6.1", "6.2", "7.1", "7.2", "7.3"],
    ),
    "splunk-es": dict(
        name="Splunk Enterprise Security", vendor="Cisco (Splunk)", layer="observe",
        caps=["soc"],
        does="Risk-based alerting that correlates AI Defense verdicts, agent traces, kernel events and network "
             "flows onto one entity, so an agentic incident arrives as one investigation rather than twelve alerts.",
        covers=["3.3", "5.1", "7.1", "7.2"],
    ),
    "splunk-obs-cloud": dict(
        name="Splunk Observability Cloud", vendor="Cisco (Splunk)", layer="observe",
        caps=["platform", "soc"],
        does="GPU, model-serving and service health on the same timeline as agent behaviour: saturation, queue "
             "depth and latency, so capacity abuse is separable from a model regression.",
        covers=["6.1", "6.2"],
    ),
    "isovalent": dict(
        name="Isovalent Enterprise for Cilium: Tetragon and Hubble", vendor="Cisco (Isovalent)", layer="runtime",
        caps=["net"],
        does="eBPF enforcement in the kernel: process execution, file access such as a sandbox reading its "
             "service-account token, identity-based and L7 network policy, egress allow-lists, and full flow logs.",
        covers=["1.1", "1.2", "3.1", "3.3", "5.1", "6.2", "7.1", "7.2", "7.3"],
    ),
    "secure-workload": dict(
        name="Cisco Secure Workload", vendor="Cisco", layer="runtime",
        caps=["net"],
        does="Workload segmentation and policy across VMs, bare metal and containers, with dependency mapping "
             "to show which agent workloads actually talk to which business systems before policy is tightened.",
        covers=["5.1", "6.2", "7.2"],
        note="Add where agent workloads span more than Kubernetes, or where an existing segmentation estate must stay authoritative.",
    ),
    "hypershield": dict(
        name="Cisco Hypershield", vendor="Cisco", layer="runtime",
        caps=["net", "platform"],
        does="Distributed enforcement in the kernel, in the fabric and on DPUs, with autonomous segmentation "
             "and compensating controls applied without waiting for a patch window.",
        covers=["5.1", "7.2"],
    ),
    "hybrid-mesh-fw": dict(
        name="Cisco Hybrid Mesh Firewall", vendor="Cisco", layer="network",
        caps=["net"],
        does="Enforcement between agent workloads, MCP servers and the internet, including on NVIDIA BlueField "
             "DPUs inside the AI factory, so egress policy is applied where the GPU traffic actually leaves.",
        covers=["1.1", "3.1", "3.3", "6.2"],
    ),
    "nexus": dict(
        name="Cisco Nexus 9000 / N9100 Series and Nexus Hyperfabric AI", vendor="Cisco", layer="network",
        caps=["platform"],
        does="Lossless, low-latency fabric for GPU east-west traffic, with the telemetry to tell a congested "
             "fabric apart from a model problem or an agent loop. Liquid-cooled N9000 switches interoperate "
             "with liquid-cooled rack-scale compute for a rack-to-fabric liquid-cooled AI factory.",
        covers=["6.1"],
        note="Cisco Silicon One on the front end and Spectrum-X based switching on the back end, under the "
             "Nexus One unified networking architecture.",
    ),
    "ucs-gpu": dict(
        name="Cisco UCS C885A M8 (NVIDIA HGX)", vendor="Cisco", layer="infra",
        caps=["platform"],
        does="Dense GPU compute for the on-premises open-weight model that handles customer and financial data, "
             "managed through Intersight with node identity that ties an inference event to a host and model version.",
        covers=["1.1", "6.1"],
    ),
    "secure-ai-factory": dict(
        name="Cisco Secure AI Factory with NVIDIA", vendor="Cisco + NVIDIA", layer="infra",
        caps=["platform"],
        does="The validated design that packages the above: Cisco UCS and Supermicro rack-scale compute, "
             "Nexus fabric, NVIDIA systems and BlueField DPUs, storage from NetApp, Pure Storage, VAST Data "
             "or Hitachi Vantara, with AI Defense and Splunk integrated rather than bolted on.",
        covers=["1.1", "5.1", "6.1", "7.3"],
        note="Expanded for the rack-scale era in August 2026, adding Supermicro compute and NVIDIA Vera Rubin "
             "NVL72 / HGX Rubin NVL8 platforms.",
    ),
    "supermicro-rack": dict(
        name="Supermicro rack-scale GPU systems (in Cisco Secure AI Factory)", vendor="Cisco + Supermicro + NVIDIA", layer="infra",
        caps=["platform"],
        does="Liquid- and air-cooled rack-scale and dense GPU systems, validated and sold as part of the Cisco "
             "AI infrastructure portfolio since the August 2026 rack-scale expansion of Secure AI Factory. "
             "Supports NVIDIA Vera Rubin NVL72 and HGX Rubin NVL8 for trillion-parameter training and "
             "high-throughput inference. Complements Cisco UCS rather than replacing it.",
        covers=["1.1", "6.1"],
        note="Available through Cisco and authorised channel partners from October 2026. Pairs with "
             "liquid-cooled Cisco N9000 Series switches for rack-to-fabric liquid cooling: at 200 kW+ per "
             "rack, liquid cooling is a system-level requirement rather than an option.",
    ),
    "agenticops": dict(
        name="AgenticOps via Cisco Cloud Control", vendor="Cisco", layer="observe",
        caps=["platform", "soc"],
        does="End-to-end observability across the AI factory that correlates job health with compute, NIC, "
             "optics and network performance, so a stalled agent workload can be separated from a fabric or "
             "thermal problem.",
        covers=["6.1", "6.2"],
    ),
    "duo-identity": dict(
        name="Cisco Duo and Identity Intelligence", vendor="Cisco", layer="identity",
        caps=["app", "net"],
        does="Strong authentication and behavioural identity analytics on the human approval path, and on the "
             "contractor accounts that edit knowledge-base policy pages.",
        covers=["4.2", "7.2"],
    ),
    "app-team": dict(
        name="Your application and platform team", vendor="Customer-owned", layer="aisec",
        caps=["app"],
        does="Approvals outside the agent channel, per-agent kill switches and read-only modes, tool scopes, "
             "memory provenance, and step, spend and time limits. No vendor supplies these; the controls above "
             "can only enforce and evidence them.",
        covers=["2.2", "3.1", "3.2", "4.1", "4.2", "5.2", "6.1", "7.1", "7.2", "7.3"],
        note="Consistently the largest single gap in this exercise, and the one no purchase closes.",
    ),
}

# The honest staging answer when a customer asks "what do we buy first".
STACK_STAGES = [
    ("Stage 1: see the agents at all",
     ["splunk-agent-obs", "aidefense-runtime"],
     "Without agent traces and gateway guardrails, most of this exercise's situations have no detection at all. "
     "This pair turns an invisible system into an observable one and is the floor, not the goal."),
    ("Stage 2: control what gets in",
     ["aidefense-supply", "aidefense-validate"],
     "Stops poisoned models, look-alike MCP servers and rogue agent cards at intake, and gives the release gate "
     "evidence to decide on. Addresses the build-time half of the attack."),
    ("Stage 3: contain what gets through",
     ["isovalent", "hybrid-mesh-fw", "secure-workload"],
     "Kernel and network enforcement for the cases where the AI layer is bypassed: credential theft in a sandbox, "
     "egress to a paste site, a stolen credential used from the wrong workload."),
    ("Stage 4: run it as one incident",
     ["splunk-es", "splunk-obs-cloud"],
     "Correlation so agent, kernel, network and infrastructure signals arrive as a single incident with one "
     "timeline. This is what situation 7.1 tests and what the executive track depends on."),
    ("Stage 5: own the platform",
     ["secure-ai-factory", "ucs-gpu", "supermicro-rack", "nexus", "agenticops", "hypershield", "duo-identity"],
     "Relevant when open-weight models handling regulated data are moving on-premises, or when the fabric and "
     "GPU estate are being built rather than rented. At rack-scale densities the thermal and network design "
     "stops being a procurement detail and becomes part of the security architecture: shared GPU capacity is "
     "what situation 6.1 abuses."),
]

SOURCES = [
    ("Cisco Expands Secure AI Factory with NVIDIA for the Rack-Scale Era (August 2026)",
     "https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2026/m08/cisco-secure-ai-factory-nvidia-rack-scale.html"),
    ("Supermicro: Bringing Rack-Scale AI to the Enterprise Together with Cisco",
     "https://learn-more.supermicro.com/data-center-stories/supermicro-cisco-secure-ai-factory-nvidia"),
]


def products_for_cap(cap):
    return [k for k, p in PRODUCTS.items() if cap in p["caps"]]


def products_for_inject(inject_id):
    return [k for k, p in PRODUCTS.items() if inject_id in p.get("covers", [])]
