# Operation Quiet Ledger: intelligence-led AI security tabletop

A Streamlit app for running an AI security tabletop exercise with a room of participants,
structured the way a Mandiant engagement is: intelligence-led scenario, a Master Scenario
Events List, evaluator criteria, a hotwash, and an after-action report with capability
maturity ratings and a 30/60/90-day plan.

* **Participants** scan the QR code, read the briefing, pick a role and answer the situations
  for their track. No sign-in. They never see other people's answers, the gap analysis,
  the framework views or the technology annex.
* **Facilitator** opens `<app URL>/?admin`, enters the password and gets eight views:
  pace controls and the QR code, the MSEL, the live gap analysis, six framework mappings,
  the after-action report, hotwash capture, the technology annex and every response with CSV export.
* Several sessions (one per customer or workshop) each get their own join link, mode and results.

## The two exercise modes

Picked when the session is created, and changeable from the facilitator view. Both are
defined in full in `tracks.py`, and the definition is shown to participants in the briefing.

| | **Technical track** | **Full engagement** |
| --- | --- | --- |
| Situations | 16 technical | 16 technical + 7 executive |
| Rooms | One room of practitioners | Technical room + executive room |
| Duration | 4 hours + 45-min hotwash | 4 hours + 2.5 hours + 60-min joint hotwash |
| People | 6–14 | 12–25 |
| Answers | "If this ran against our agents today, which layer would see it, and could we stop it before money moved or data left?" | "Would we detect it, would the right people hear in time, and would we make defensible decisions on money, disclosure and customers while it was still running?" |
| Proves | Technical detection and response against agentic techniques | Whether detection, escalation and executive decision-making hold together as one chain |
| Cannot prove | That the organization can *run* the incident: a room that detects everything can still miss a 72-hour notification deadline | Technical efficacy of a specific control — a tabletop evidences belief, not efficacy |
| NIST CSF 2.0 | Rates PROTECT, DETECT, RECOVER | Adds GOVERN and RESPOND, which the technical track cannot evidence |

The two rooms are deliberately coupled: **executives are seeded with what the technical room
actually escalated, not with ground truth.** If the technical room never escalated the memory
poisoning, the executives decide on disclosure without knowing about it. That divergence is
reported as an escalation finding, and it is invisible if the two groups are exercised separately.

**To switch modes:** facilitator view → *Exercise mode*, the first panel in the Facilitator tab.
The current mode is shown in the sidebar on every tab. Sessions created before this feature
existed default to the technical track, so the executive injects stay hidden until you switch.
Switching takes effect immediately for everyone and keeps answers already given.

### Which session a participant gets

The mode belongs to the **session**, not to the app, so the URL decides what someone sees:

| URL | What loads |
| --- | --- |
| `/?s=<code>` | That session, in the mode the facilitator chose for it. This is what the QR code and join link produce — always prefer it. |
| `/` (no parameters) | The **mode chooser**: both modes side by side with what each covers and does not, and a button to enter the standing session for that mode. |
| `/?admin` | Facilitator view. |

Two standing sessions are seeded so the chooser always has somewhere to send someone:
`main` (technical track) and `mainfull` (full engagement). Neither can be deleted.
Picking a mode in the chooser sets `?s=` and so produces a shareable URL.

### Managing sessions

The Facilitator tab's **Sessions** panel lists every session with its mode, participant count,
answer count and hotwash notes, and deletes any number of them at once. Deletion removes the
session's participants, answers and hotwash notes, needs an explicit confirmation that states
exactly how many records will go, and cannot be undone — export from the Responses tab first.
The two standing sessions are excluded from the list. Deleting the session you are currently
viewing redirects you to `main`. A single session can also be reset (answers cleared, session
kept) or deleted from *Submissions → Reset or delete this session*.

Note the earlier behaviour this replaced: the bare URL used to serve `main` silently, which is
the technical track, so opening the app's plain address showed the technical track no matter
which sessions existed.

## Frameworks

The Cisco Integrated AI Security and Safety Framework stays the spine: situations are authored
against its 19 adversary objectives, and every other view is derived from the same answers.
Each framework gets its own tab so each audience reads the same finding in its own language.

| Framework | Audience | Role here |
| --- | --- | --- |
| Cisco AI Security Framework | AI platform and security engineering | Spine: OB objectives and AITech identifiers |
| MITRE ATT&CK (Enterprise) | SOC, detection engineering | Places agentic activity in the intrusion the SOC already reasons about |
| MITRE ATLAS | AI security engineering, red team | The AI-specific steps ATT&CK does not model |
| NIST CSF 2.0 | CISO, risk committee, board | Carries the maturity ratings in the after-action report |
| NIST AI RMF + ISO/IEC 42001 | Risk, compliance, internal audit | Findings as AI governance obligations |
| OWASP LLM + Agentic Top 10 | Application and agent developers | Backlog items a dev team can act on |

ATT&CK, CSF, AI RMF and OWASP identifiers were chosen conservatively. **MITRE ATLAS is
versioned more aggressively, so re-check ATLAS technique IDs against the current matrix before
a report leaves the building.**

## Files

| File | What it holds |
| --- | --- |
| `app.py` | Participant and facilitator screens |
| `content.py` | Scenario, 16 technical situations, Cisco taxonomy, capability definitions. Merges in the mappings at import |
| `mappings.py` | Per-inject framework IDs, MSEL delivery detail, evaluator criteria, exercise objectives |
| `exec_track.py` | The 7 executive injects, governance capabilities, regulatory clocks, room coupling |
| `tracks.py` | The two exercise modes: what each means, who attends, and what it produces |
| `threat.py` | Threat-intelligence profile, tradecraft, attack lifecycle, synthetic indicators |
| `frameworks.py` | Framework catalogues and identifier lookup |
| `portfolio.py` | Cisco Secure AI Factory technology annex, by layer and by capability gap, including the August 2026 rack-scale expansion with Supermicro |
| `scoring.py` | Readiness, capability maturity, framework rollups, findings and the 30/60/90 roadmap |
| `store.py` | Database access (Postgres in production, SQLite locally) |

Edit scenario prose in `content.py` and `exec_track.py`; edit framework mappings in `mappings.py`.

## Scoring

Per answer: **70% detection** (or, on the executive track, decision readiness) **+ 30% decision
ownership.** Under 40 is a gap, 40–69 partial, 70+ ready. Readiness maps to a deliberately
conservative 5-level maturity scale (`scoring.MATURITY`), because a room *believing* it would
detect something is not the same as a control that is measured and improved.

Findings are generated per situation, carry their evidence (readiness, response count,
"don't know" rate, room disagreement, and whether the room expected the wrong layer to catch
it), and take their recommendation from that situation's own "what good looks like" for the
capability that should have caught it. Severity sets the horizon: Critical/High → 30 days,
Medium → 60, Low → 90.

## Two caveats the app states in its own output

1. **A tabletop evidences belief, not efficacy.** Findings record what the room said. They
   should be confirmed by technical validation before being closed.
2. **The threat actor is fictional.** `UNC-QL` is built for this exercise from publicly
   reported financially motivated tradecraft and agentic-attack research. It is not an alias
   for any real tracked group, and the indicators are synthetic. Regulatory clocks are stated
   as assessment triggers, not legal advice, and should be replaced with the customer's actual
   obligations during scoping.

## Deploy on Streamlit Community Cloud
1. **Database.** Create a free Postgres database on [Neon](https://neon.tech) or [Supabase](https://supabase.com) and copy its connection string.
   On Supabase use the *Session pooler* URI, since Streamlit Cloud has no IPv6 and the direct URI will hang the app at startup.
   Appending `?connect_timeout=10` turns an unreachable host into a visible error instead of an indefinite hang.
   Tables are created automatically on first run, and the `track` column is added by an idempotent migration.
2. **Repository.** Push this folder to a GitHub repository (private is fine). Do not commit `.streamlit/secrets.toml`.
3. **App.** At [share.streamlit.io](https://share.streamlit.io): *Create app* → pick the repo, branch and `app.py`.
   Under *Advanced settings → Secrets*, paste the three values from `.streamlit/secrets.example.toml`.
   After the first deploy, set `APP_URL` to the app's real address.
4. **Sharing.** In the app's *Settings → Sharing*, make the app **public** so participants can join without a Streamlit account.
   Results stay behind `ADMIN_PASSWORD`.
5. **Before each session.** Open the app a few minutes early: Community Cloud puts idle apps to sleep.
   In the facilitator view, create a session, pick the mode, and put its QR code on screen.

Dependencies are pinned with upper bounds on purpose. An unpinned `sqlalchemy>=2.0` previously
let a redeploy pick up 2.1, which changed the default driver for `postgresql://` and broke the
app at startup; `store.py` now names `psycopg2` explicitly as well. Note that altair 5 cannot be
imported on Python 3.14, which is what Streamlit Cloud runs, so altair 6 must stay reachable.
`streamlit` is pinned **exactly**, for the reason in the next section.

## Troubleshooting

### `Failed to fetch dynamically imported module: .../static/js/DataFrame.<hash>.js`

A browser-side asset error, not a Python one: no traceback, and the app's own logs stay clean.
Streamlit's frontend loads parts of itself lazily, and the dataframe component is fetched the
first time an `st.dataframe` renders — which is why it tends to appear on the facilitator
panel, the most dataframe-heavy page. The request returned something other than that
JavaScript file. Causes, in the order worth checking:

1. **Reload the page first** (Cmd/Ctrl + Shift + R). If the chunk is present on the server,
   this fixes it immediately and nothing else needs doing.
2. **The app was asleep or restarting.** Community Cloud spins idle apps down, and asset
   requests then get a holding redirect instead of the file. Open the app a few minutes before
   a session.
3. **The sign-in session expired.** If the app is private, an expired auth cookie makes asset
   requests redirect to the login page, and an HTML redirect is not a JavaScript module.
   Reloading re-authenticates.
4. **A redeploy changed the Streamlit version.** Each version ships its own content-hashed
   chunks, so an open tab can ask for a filename that no longer exists. This is why
   `streamlit` is pinned exactly rather than range-capped: the bundle then stays identical
   across redeploys and open tabs survive them.

### Participants are asked to sign in

The app is private. *Settings → Sharing* → make it **public** so participants can join without
a Streamlit account. Results stay behind `ADMIN_PASSWORD` either way. A private app also adds
the auth-expiry failure mode above.

## Run locally
```
pip install -r requirements.txt
echo 'ADMIN_PASSWORD = "test"' > .streamlit/secrets.toml
streamlit run app.py          # participants: http://localhost:8501   facilitator: http://localhost:8501/?admin
```
Without `DATABASE_URL` it uses a local `ttx.db` SQLite file, which Streamlit Cloud wipes on
restart. Use the facilitator view's **Preview with example answers** toggle to see every
dashboard populated without running a real session.
