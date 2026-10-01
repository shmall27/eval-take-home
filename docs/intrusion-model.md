# How a real intrusion works, and whether kill-chain stages are the right seams

**Purpose.** This is a design reference for the branching-range spec
([`specs/branching-range-spec.md`] in the exploration workspace). It exists to
answer one question before we build on it: are "kill-chain stages" the right
places to fork a trajectory? It maps a canonical Active Directory intrusion,
marks where the genuinely hard steps are and what gates them, and scores the
candidate branch seams against the two risks the spec names: §8 (are stages
Markov?) and §9 (is failure driven by missing search or missing tradecraft?).

**Scope and altitude.** This is eval design, not an attack manual. Techniques
are named at the level of their class and what they gate, not as operational
procedure. It assumes an **assumed-breach** posture: initial access is granted,
because in a real network it is the hardest and noisiest step and measuring from
a foothold is both cheaper and more reproducible.

**Caveat.** The AD attack landscape moves. Technique names here were checked
against current references (see end). Treat specifics as current-as-of-writing,
not permanent.

---

## 1. An intrusion is a loop, not a line

ATT&CK tactics and the Lockheed kill chain are taxonomies, not a state machine.
A real intrusion does not march through foothold → privesc → lateral → objective
once. It loops:

> get a foothold → see what this identity can reach → take whatever credentials
> are reachable → use them to reach one more host or identity → see again →
> repeat until something grants the objective.

Privilege escalation is interleaved into that loop, not a station passed through.
Credential access and lateral movement alternate many times.

The consequence for branching is the whole point of this document: **the stage
index is not the state. The state is the capability set** — the credentials and
tickets you hold, the hosts you have footholds on, the privilege tier you have
reached, and the segments those let you touch. Everything downstream is a
function of that set. Your nodes should snapshot it and your seams should trigger
on changes to it.

## 2. A canonical AD intrusion, as loop iterations

A representative path to domain dominance, assuming a foothold on a user
workstation:

1. **Local situational awareness.** Whoami, local admin status, reachable hosts,
   cached credentials, running sessions.
2. **First credential access.** Dump credentials the current privilege allows:
   LSASS memory if local admin, SAM/registry hives, DPAPI-protected secrets,
   browser and cached domain credentials.
3. **Domain reconnaissance.** Enumerate users, groups, ACLs, delegation settings,
   certificate templates, and sessions. This is where graph tooling enters.
4. **Pick a path.** Choose a route to a higher-privilege identity: a roastable
   service account, a delegation misconfiguration, a certificate-template abuse,
   or an access-control-list chain.
5. **Execute one pivot.** Walk one edge of that path to obtain new credential
   material or a new foothold.
6. **Loop** back to step 1 with the enlarged capability set.
7. **Objective.** Reach the target data or host, or obtain domain-replication
   rights and the krbtgt key for persistent control.

## 3. The hard-step map: what gates each class

The hard steps are not evenly spread. They cluster, and they are gated by
different things. This table is the §9 evidence in concrete form. "Gate" is the
scarce thing that decides success.

| Step class | What it is (altitude) | Gate | Does more search help? |
|---|---|---|---|
| LSASS / hive credential dump | pull secrets from a host you admin | access (need local admin) | no |
| Kerberoast / AS-REP roast | request tickets for weakly-protected accounts, crack offline | knowledge + a weak account existing | barely |
| DCSync | replicate the directory to dump hashes | access (replication rights) | no |
| Delegation abuse (unconstrained / constrained / RBCD) | impersonate via misconfigured delegation | knowledge + a specific ACL/host | no |
| ADCS abuse (ESC1–ESC16) | mint an authentication certificate via a template or CA misconfig | knowledge (deep) + the misconfig existing | no |
| ACL path (GenericAll/Write, WriteDacl, etc.) | chain object-permission edges to a target | enumeration, but **graph-solved** | no — compute the graph |
| Local privilege escalation | abuse a local service/path/kernel flaw | mixed knowledge + search | sometimes |
| Pass-the-hash / ticket, token theft | reuse credential material you hold | knowledge (common) + holding the material | no |

Three gates, and only one of them is what fan-out moves:

- **Knowledge-gated.** Success needs knowing a technique or misconfiguration
  class exists. ADCS and delegation abuse are the sharpest cases. More agents
  with the same priors do not clear a knowledge wall.
- **Enumeration-gated, but graph-solved.** The AD search space looks enormous and
  is the thing BloodHound exists for. It is solved by computing a graph, not by
  open-ended exploration. So this looks like search but is really "know to run
  the tool." That is the §9 reference point stated plainly.
- **Access- and position-gated.** Success needs holding a specific credential or
  reaching a specific host or segment. This is the capability set. **This is the
  only gate branching actually moves**, because given the set, whether the agent
  finds and uses what it holds is stochastic and search-responsive.

**§9 verdict.** Most hard steps are knowledge- or access-gated, not open-search-
gated. Naive fan-out buys little on knowledge walls. It pays at access/position
deltas, where the outcome is genuinely variable given the state. This is a
testable claim, not a conclusion: see §5.

## 4. Do the seams screen off the path? (the §8 test)

A seam is good if three things hold: it **partitions** trajectories cleanly, it
**screens off** the path that led to it so the conditional rate is well-defined,
and it lands where **quiescence** is reachable so we can snapshot.

| Candidate seam | Partition | Screens off path? | Quiescence | Verdict |
|---|---|---|---|---|
| New validated credential | clean, discrete | **no on the delta alone** — which credential, plus the full set held, dominates | good | trigger on it, but snapshot the full set |
| New host foothold | clean | weak alone — what you hold on arrival dominates | good | trigger, snapshot full set |
| Privilege tier up (user→admin→DA) | clean, few tiers | moderate — tier plus location | good | strong, coarse seam |
| New reachable segment | clean | weak alone | ok | trigger, snapshot full set |
| First contact with high-value target | clean | moderate | variable | good for objective-stage measurement |

The pattern is consistent. The **delta** is the right trigger for *when* to
branch. The **state you must snapshot is the full capability set**, not the
delta and not a milestone label. A node reconstructed from a lossy summary loses
exactly the information that makes the conditional valid.

What actively breaks screening, and therefore M2:

- **An adaptive defender.** If a blue team or endpoint defense is present,
  detection state conditions everything downstream and is path-dependent. Screen-
  off fails. Keep v1 defender-free, or make defender state part of the node.
- **Artifacts with lifetimes.** Kerberos tickets you minted earlier expire. The
  snapshot must capture ticket caches and a consistent clock, or two restores of
  the "same" node differ. This ties directly to the range-wide virtual-time
  problem flagged earlier: independent per-host instruction-count clocks cannot
  agree, and Kerberos demands agreement.
- **Accumulated soft knowledge.** What the agent learned lives in its context.
  Discarding context (spec §2) makes the node measure "a fresh agent from this
  state," which is cleaner for counterfactuals but is a different quantity than
  "this agent continuing."

**§8 verdict.** Screening-off is *plausible* only under a specific scope:
assumed breach, no adaptive defender, full-capability-set snapshots, and a
pinned consistent clock. State those as preconditions or M2 will fail for reasons
unrelated to the method. Capability-state deltas screen off better than ATT&CK
tactic labels because they carry more of the state, which is why the spec's own
trigger signals are better than its framing.

## 5. Implications for the branching spec

- **Rename the seams.** The spec's triggers — shell obtained, credential
  validated, privilege tier — are capability-state deltas, and they are the right
  triggers. Drop the implication that they are monotone ATT&CK stages. The loop
  is not monotone.
- **Snapshot the set, not the summary.** Because creds live in LSASS memory and
  in ticket caches with lifetimes, the active frontier needs machine-state
  snapshots, not action-log replay alone. Log-for-archive, snapshot-for-frontier
  (spec §2) is right, and this is the reason.
- **Branch where fan-out pays.** Put branch points at access/position deltas,
  where post-branch variance is real and search-responsive. Do not expect fan-out
  to crack knowledge-gated steps.
- **Build the §9 test explicitly.** From one frozen node, compare a thinly-tooled
  tree search against a single well-tooled trajectory at matched compute. "Well-
  tooled" means graph enumeration and the known technique tooling are available.
  If the single rich trajectory wins, branching is solving the wrong problem for
  that step, and the finding itself is valuable.
- **Scope M2 honestly.** Measure screening empirically: compare the conditional
  success from a branched node against the conditional from an independent cold
  run that reached the same capability set. If they diverge, the state is
  entangled and the per-stage profile is not a valid decomposition, even if the
  weighted end-to-end estimate still is.
- **Add a two-host time gate before M1.** Single-host M0 will pass and hide the
  hardest determinism problem, which is multi-host clock agreement under a time-
  dependent protocol like Kerberos.

## 6. What this does and does not settle

It settles the shape question: seams should be capability-state deltas, the node
must carry the full set, and the valid-scope for a stage decomposition is
narrow. It does not settle the empirical questions, which only the range can
answer: how often screening actually holds, and whether search or tradecraft
dominates failure. Those are M2 and the §9 test, now specified concretely enough
to run.

---

## References (checked at time of writing)

- ADCS ESC1–ESC16 catalog: GhostPack Certify wiki; HackTricks AD CS domain
  escalation; the ESC1–ESC16 attack references by xbz0n and PacketWanderer.
- BloodHound Community Edition edge model and delegation (unconstrained /
  constrained / RBCD) coverage: The Hacker Recipes BloodHound page; BloodHound
  CE practical guides.
- Kerberos delegation classes: current delegation audit and attack write-ups.
