# Pivot: design

Status: **draft, nothing built yet.** This document fixes the data shapes and the moving parts
so that the first build, and every data source after it, plugs into the same contracts.

## 1. What problem this solves

An investigation starts with a seed (an IP, a cookie, a JA4, a hostname, a report) and a
question ("is this an actor on my network, and who?"). It ends with an **assessment**: a claim,
a confidence, and the evidence for it.

In between is a search through linked material. Two facts make this hard:

1. **There are many routes to the same assessment.** An IP can be tied to an actor through
   DNS → domain → MISP tag, through TLS fingerprint → honeypot session → known tooling, through
   a CTI report that names it, through an IRIS case from last month, and so on. Twenty routes
   is realistic. An analyst usually finds two or three of them.
2. **The material lives in many places.** Synapse today; the Iceberg lake (Zeek, Suricata,
   Wazuh, honeypot, CAPE) through Trino; IntelOwl, MISP, DFIR-IRIS; a corpus of reports and
   notes; and other sources later that do not exist yet.

So the tool needs three things, and they are kept separate on purpose:

| Thing | Question it answers | Where it lives |
|---|---|---|
| **Vocabulary** | what *kinds* of things exist (IP, domain, JA4, cookie, actor…) | the Synapse data model |
| **Pivot catalog** | from a thing of kind A, *which sources can take me to which kinds*, at what cost | generated + declared files in this repo (`catalog/`) |
| **Investigation graph** | what we actually found in *this* case, from where, and why we believe it | one forked Synapse view per investigation |

The pivot catalog is the "where are all the touch points" map. Because it is a graph of kinds
(not of data), "every route from an IP to an actor attribution" is a path enumeration over a
few hundred nodes, done before running any query.

## 2. Vocabulary: Synapse forms are the canonical types

Every node in pivot is a Synapse form and value (`inet:ipv4=1.2.3.4`,
`inet:tls:ja4=t13d...`, `inet:http:cookie=...`, `risk:threat=(volt_typhoon,)`). A source that
is not Synapse maps its output **into** Synapse forms at its connector boundary. Nothing
downstream ever sees a source's native field names.

Why Synapse's model rather than our own or STIX:

- It is already the primary store and already populated (MISP bulk, cti-agent actor graph).
- It is large and network-aware. The model shipped in **Synapse 2.247.0** (the version on
  siem-core) has **584 forms, 1,982 property→form links and 88 light-edge definitions**,
  measured from the installed package, not quoted from docs. It already has
  `inet:tls:ja4`, `inet:tls:ja4s`, `inet:tls:ja3:sample`, `inet:tls:handshake`, `inet:http:cookie`,
  `inet:flow` (with `:src:ssh:key`, `:src:handshake`, `:dst:ssl:cert`), `inet:dns:request`,
  `it:host`, `it:exec:proc`, `risk:alert` and `media:news`.
- Natural-key forms dedupe across sources for free: two sources reporting the same IP land on
  one node (`dev/synapse-analytic-standard.md` §0.1 in homelab-infra).
- STIX 2.1 stays an **export** format (§7), because other tools speak it, but it is too coarse
  to be the working model (it has no JA4, no cookie, no flow).

When a source produces something the model genuinely lacks, add an extended form
(`_pivot:...`, Synapse's `_` prefix for custom model elements) through a reviewed model
extension. Do not hide it in a free-text property, because no pivot can reach it there.

The analytic conventions already set in homelab-infra's `dev/synapse-analytic-standard.md`
apply unchanged: `#rep.<source>` for third-party claims, `#cno.*` for our assessments,
`#tlp.*` for handling, `#cti.conf.*` for confidence, and `meta:source` plus `-(seen)>` for
provenance on every node.

## 3. The pivot catalog: the touch-point map

The catalog is a directed multigraph:

- **node** = a form (`inet:ipv4`)
- **edge** = a *pivot*: "given form A, connector C with method M returns form B (and maybe an
  edge verb)". There are many parallel edges between the same two forms, one per source.

It is built from two inputs.

### 3.1 Native pivots (generated)

Inside Synapse, every property whose type is another form is a pivot (`inet:dns:a:ipv4` takes
you from `inet:ipv4` to `inet:dns:a`), and so is every light-edge definition.
`tools/derive_native_pivots.py` reads these straight out of the model, so the in-graph half of
the catalog is never hand-maintained and tracks Synapse upgrades. For `inet:ipv4` alone that is
47 inbound property pivots in 2.247.0.

Native pivots cost nothing to declare, but **they only find what is already in the graph.**
Most of the telemetry is not, and should not be (§5).

### 3.2 Connector pivots (declared)

Every other source ships a **connector manifest** (`schemas/connector-manifest.schema.json`,
examples in `catalog/connectors/`). The manifest declares, per pivot method:

| Field | Why it exists |
|---|---|
| `accepts` / `emits` (forms, edge verbs) | puts the method into the catalog graph |
| `kind`: graph, lake, api, corpus | how it runs |
| `egress`: internal, external | **the TLP gate**: an internal-only value (our own IPs, anything `#tlp.amber`+) is never sent to an `external` connector. The engine enforces this, the connector does not get a say. |
| `interaction`: passive, active | active means the target can notice (some IntelOwl analyzers fetch the URL). Off by default. |
| `independence_group` | which upstream truth this ultimately derives from (§6.2) |
| `cost` (queries, expected latency, rate limit) | the planner's budget currency |
| `time_semantics` | point-in-time, windowed (needs a time range), or current-state only |
| `max_results` and truncation behaviour | a truncated answer has to be *marked* truncated, never silently partial |

### 3.3 What the catalog gives you before any query runs

- **Route enumeration.** "All routes from `inet:http:cookie` to `risk:threat` within 5 hops",
  with each route's sources and cost. This is the "20 ways" list, produced up front.
- **Coverage gaps.** Forms that nothing in your data can reach. Example found while writing
  this: `inet:http:cookie` has **zero** inbound property pivots in the Synapse model, and the
  lake's `ocsf.http_activity` table has no cookie column. Today there is no route from a cookie
  to anything (§9).
- **Planner input.** The engine ranks the next pivot by distance-to-goal in this graph divided
  by cost.

## 4. Inbound data shape: the observation batch

Every connector call returns exactly one **observation batch**
(`schemas/observation-batch.schema.json`). This is the only thing a new source has to produce.

```json
{
  "schema": "pivot.observation-batch/1",
  "connector": {"id": "lake.zeek-dns", "version": "0.1.0", "method": "ipv4_to_fqdn"},
  "request": {
    "inputs": [{"form": "inet:ipv4", "value": "203.0.113.7"}],
    "window": {"start": "2026-10-27T00:00:00Z", "end": "2026-11-03T00:00:00Z"},
    "fingerprint": "sha256:…"
  },
  "executed_at": "2026-11-03T17:02:11Z",
  "stats": {"rows_scanned": 18211, "results": 3, "truncated": false, "duration_ms": 640},
  "nodes": [
    {"ref": "n1", "form": "inet:fqdn", "value": "cdn-update.example",
     "props": {}, "tags": [],
     "seen": {"first": "2026-10-29T03:10:00Z", "last": "2026-11-02T22:41:09Z", "count": 41},
     "prevalence": {"distinct_internal_hosts": 1, "window_days": 7}}
  ],
  "edges": [
    {"n1": {"form": "inet:ipv4", "value": "203.0.113.7"}, "verb": "resolved_from",
     "n2": {"ref": "n1"}, "seen": {"first": "…", "last": "…", "count": 41}}
  ],
  "evidence": [
    {"ref": "n1", "source_record": {"system": "trino",
     "locator": "iceberg.ocsf.dns_activity", "keys": {"connection_uid": "C9x…"}}}
  ],
  "handling": {"tlp": "amber"},
  "errors": []
}
```

Rules:

- **Nodes are addressed by `(form, value)`**, the Synapse natural key. Guid forms (`inet:flow`,
  `risk:alert`) use a deterministic list of seed values, the same `(a, b, …)` syntax the
  existing writers use, so re-running a pivot is idempotent.
- **Provenance is mandatory.** Every node and edge traces to a `source_record` pointer back
  into the system it came from (a table plus key, an API object id, a document offset). The
  raw record stays where it is; pivot stores the pointer, not a copy.
- **`seen` and `prevalence` are first-class.** Pruning (§6.1) and confidence (§6.2) both need
  them. A connector that cannot compute prevalence says so (`null`), it does not omit the field.
- **Edge verbs** are Synapse light-edge verbs where one fits (`refs`, `uses`, `targets`,
  `seen`, `linked`). New verbs are allowed but must be listed in the connector manifest so the
  catalog knows about them.
- **Unsupported inputs are an error entry, not an empty result.** An empty result has to mean
  "looked, found nothing", because the engine treats it as negative evidence.

## 5. Where the data sits during an investigation

```
 seeds ─▶ ┌──────────── pivot engine ─────────────┐
          │ planner ─▶ executor ─▶ normaliser      │
          │    ▲                       │            │
          │    └── goal check ◀── prune◀┘           │
          └───────────────┬──────────────────────────┘
                          │ observation batches
                          ▼
     Synapse view  "inv-<id>"  = fork of the `analyst` view
     (only what this investigation touched; tagged, with provenance)
                          │ on close, operator approves
                          ▼
     merge selected conclusions into `curated`   +   case in DFIR-IRIS
```

- **One forked Synapse view per investigation.** Synapse views fork and merge natively, so
  an investigation can write freely without touching the shared graph. Nothing it finds is
  visible to anyone else until a person merges it. Throwing away a dead-end investigation is
  deleting the fork.
- **Telemetry is queried, never bulk-loaded.** The lake holds billions of rows. A lake pivot
  returns **aggregates** (one `inet:flow`-shaped summary per src/dst/day, with counts and
  first/last seen), and only rows the investigation actually touches get materialised.
  The 847k MISP indicators are already in Synapse, so they are pivoted natively.
- **Writing to the shared graph is a live-system write.** Merging a fork into `curated` goes
  through the vault approval gate like any other change; pivot proposes it, it does not do it.

## 6. The loop

```
frontier := seeds
while frontier and budget remains and not goal_met:
    candidates := for each frontier node, each catalog pivot that accepts its form
    rank by (closeness to goal form in the catalog) × (novelty) ÷ (cost)
    run the top-k, under budget, honouring egress/interaction rules
    normalise → materialise into the fork
    prune; add the survivors to the frontier
    evaluate goal predicates against the fork
```

Three modes, same engine: **manual** (the analyst clicks "expand"; the engine only lists
ranked options), **assisted** (the engine runs one ranked step and waits), **auto** (bounded
run). An LLM may rank candidates; it never decides that the goal is met and it never invents
nodes. Every node comes from a connector.

Budgets are not optional: hop limit, query count, wall-clock and per-connector rate. Hermes
rule 7 records an agent spending 241 Trino queries and its whole 40-minute window "talking to
itself". An unbounded expand-until-goal loop fails the same way.

### 6.1 Pruning: the part that decides whether this works at all

Without pruning, two hops from any real IP reaches half the internet through a CDN address,
a public resolver or a common user agent. A node is **not expanded** (it stays visible, marked
pruned with a reason) when:

- its prevalence is above a threshold (seen from more than N internal hosts, or more than M
  distinct counterparts), computed by the lake connectors;
- it is on an allowlist (the lake already has `iceberg.cti.nrd_allowlist`; add cloud/CDN
  ranges and public resolvers);
- it is a known-benign infrastructure form (sinkholes, our own scanners).

### 6.2 Many routes means confidence, if they are independent

Reaching the goal once is a lead. Reaching it along routes that do **not** share an upstream
source is evidence. After the first hit the engine switches to **corroboration mode**: it
looks for further routes to the same goal node that use a different
`independence_group`. MISP feed data, our own Zeek capture, a honeypot session and a vendor
report are independent. Three MISP feeds republishing one vendor's list are not, so they share
a group.

The assessment records every route found, and the confidence band (`cti.conf.low|moderate|high`)
is driven by the number of independent groups, not the number of routes. Contradicting
evidence (for example a sinkhole tag, or a benign IntelOwl verdict) is recorded on the
assessment, never dropped.

### 6.3 Goal predicates

A goal is a Storm query evaluated inside the investigation's fork, so goals use the same
language as the rest of Synapse:

- reach a tag: the seed links within N hops to anything tagged `#cno.threat` or `#rep.misp`;
- reach a form: any `risk:threat` node is reachable;
- corroboration: at least K independent routes to the same `risk:threat`;
- exhaustion: the frontier is empty under the budget, which is a valid "nothing found" result
  and is reported as one.

## 7. Outbound data shape: investigation and assessment

`schemas/investigation.schema.json` is the record of the whole case: question, seeds, goals,
budget, Synapse view, linked IRIS case, and the **step log**. Each executed pivot is one
step: connector, inputs, batch fingerprint, result count, duration, pruned count. The step log
makes an investigation replayable and auditable. Re-running it later against fresh data shows
what changed.

`schemas/assessment.schema.json` is what the investigation concludes:

```json
{
  "schema": "pivot.assessment/1",
  "claim": {"subject": {"form": "inet:ipv4", "value": "203.0.113.7"},
            "predicate": "attributed_to",
            "object": {"form": "risk:threat", "value": "(volt_typhoon,)"}},
  "confidence": "moderate",
  "routes": [
    {"independence_group": "own-network-capture",
     "hops": [ {"from": "inet:ipv4=…", "via": "lake.zeek-dns/ipv4_to_fqdn", "to": "inet:fqdn=…"},
               {"from": "inet:fqdn=…", "via": "synapse/native:tag", "to": "#cno.threat.prc.volt_typhoon"} ]},
    {"independence_group": "honeypot", "hops": ["…"]}
  ],
  "contradictions": [],
  "proposed_tags": ["cno.threat.prc.volt_typhoon", "cti.conf.moderate"],
  "tlp": "amber"
}
```

Exports, in order of priority:

1. **DFIR-IRIS**: the case, its IOCs, and a note per assessment linking back to the pivot
   investigation. IRIS stays the case-management system; pivot does not rebuild it.
2. **Synapse merge**: proposed tags and nodes, merged from the fork into `curated` after approval.
3. **STIX 2.1 bundle**: for any future tool that only speaks STIX. This is a lossy view and is
   produced from the assessment, never used as an input format.

## 8. Planning for sources beyond Synapse

A new source is three files and one function:

1. a **manifest** in `catalog/connectors/<id>.yaml` (validates against the schema; this alone
   adds its routes to the catalog and the coverage report);
2. a **mapping** from its native fields to Synapse forms (inside the connector, tested with
   golden files);
3. a **fake** that returns canned batches, so the engine and the UI can be tested without the
   real source (the homelab-next convention: every adapter ships a fake);
4. `pivot(method, inputs, window) -> ObservationBatch`.

Connectors run as separate processes behind one small HTTP or MCP interface, so a source can
live on another host or in another language, and a broken connector cannot take the engine
down. Synapse's native MCP endpoint (`/api/v1/mcp`, read-only role) is the graph connector's
transport. The engine never talks to a source directly.

If pivot later moves beyond this lab, the manifest and the two data shapes are the public
contract. That fits homelab-next's model, where a capability is a contract plus conformance
tests plus swappable adapters, so the connector interface can become a homelab-next capability
without changing either shape.

## 9. Touch points in this lab today

From the homelab-infra code (OCSF writer schemas, honeypot report, architecture.md), not
from documentation. Each row becomes a connector manifest.

| Source | Reaches (forms) | Notes / gaps |
|---|---|---|
| Synapse (native) | everything already in the graph: MISP indicators `#rep.misp`, actors, tools, campaigns, ATT&CK techniques, CVEs | 1,982 property pivots and 88 edge definitions. Read through MCP as `hermes-mcp-ro`. |
| Lake `ocsf.dns_activity` | ipv4 ↔ fqdn (`src_endpoint_ip`, `query_hostname`, `query_type`) | Answers are not a column; resolved IPs need `ocsf_json`. |
| Lake `ocsf.network_activity` | ipv4 ↔ ipv4/port (flows), `tls_server_name` → fqdn | **JA3/JA3S/JA4/JA4S are only inside `ocsf_json`**, not columns. Promote them to columns before JA4 becomes a cheap pivot. |
| Lake `ocsf.http_activity` | ipv4 → fqdn (`http_request_host`), url, user agent | **No cookie column.** Zeek does not log cookie values unless a policy script enables it, and HTTPS hides them anyway without TLS interception. |
| Lake `ocsf.authentication`, `process_activity`, `file_activity` | accounts, hosts, processes, hashes | Host-side pivots (Wazuh/Sysmon). |
| Lake `ocsf.detection_finding` | ipv4/host → `risk:alert` | Wazuh and Suricata alerts. |
| Lake `honeypot.events` | ipv4 → HASSH, command fingerprint, credentials, sha256, url | HASSH and command-fingerprint pivots already proven in `honeypot_report.py`. |
| Lake `cape.ioc`, `cape.detonation` | sha256 → fqdn/ipv4/url | Sandbox output. |
| IntelOwl | ipv4/fqdn/url/hash → reputation | **external egress**: TLP gate applies. Some analyzers are active. |
| MISP API | anything → events, galaxies | Bulk already in Synapse; API only for event context. |
| DFIR-IRIS | IOC → prior cases | Also the export target. |
| Corpus (reports, notes, cti-agent output) | document → every entity it mentions | `media:news` + `-(refs)>`. Extraction reuses cti-agent's validated extractor. Its "never fabricate" rule carries over. |

## 10. Build phases

Each phase ends with something usable and a check that proves it.

| Phase | Builds | Done when |
|---|---|---|
| **0 Contracts** (this commit) | schemas, example manifests, native-pivot derivation | examples validate; derivation reproduces the 584 / 1,982 / 88 counts |
| **1 Catalog** | catalog builder + `pivot routes FROM TO --max-hops N` + coverage report | lists the real routes from `inet:ipv4` to `risk:threat` across Synapse and two lake connectors; names the cookie gap |
| **2 Engine (CLI)** | loop, budgets, pruning, view-per-investigation, step log; connectors: Synapse, lake DNS, lake network, honeypot | a honeypot IP seeds an investigation that ends at a tagged node or reports exhaustion, inside budget, replayable |
| **3 GUI** | web app: graph canvas (Cytoscape.js), route explorer, evidence panel, timeline, case pane | an analyst can run phase 2's case by clicking |
| **4 Case + corroboration** | IRIS export, independence scoring, assessment record, merge proposal | an assessment with two or more independent routes lands in IRIS with its routes |
| **5 More sources** | IntelOwl (with egress gate), corpus, CAPE, auth/process | each added by manifest + mapping + fake only, with no engine change, which proves the contract |

## 11. Decisions still open

1. **View-per-investigation in the shared Cortex, or a separate Cortex for pivot?** Forks are
   cheap, but siem-core is the busiest host. Recommendation: forks in the existing Cortex
   until there is a measured problem.
2. **Promote JA3/JA4 to lake columns** (a homelab-infra writer change) before phase 2, or
   accept a slower `json_extract` pivot at first.
3. **Cookie visibility**: enable Zeek cookie logging for plaintext HTTP, or drop cookies as a
   network pivot and treat them as a host/browser artefact only.
4. **GUI build vs Optic**: Vertex's Optic UI is commercial. Phase 3 assumes building a thin UI.
