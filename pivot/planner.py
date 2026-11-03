"""Route planner: every ordered chain of pivots from the seeds to the goal, re-scored as
evidence confirms or denies each hop.

Two levels, kept apart on purpose:

* **Abstract routes** come from the catalog alone: a sequence of (connector, method) hops whose
  forms chain from a seed form to a goal form. They say what *could* be done, before any query.
* **Bound routes** follow the evidence: hop 1 is bound to the seed values; when a hop is
  confirmed, its result nodes become the next hop's inputs. A hop is decided by an observation
  batch whose connector, method and inputs match it.

Hop status: ``ready`` (can run now), ``pending`` (waits on an earlier hop), ``confirmed``
(returned unpruned nodes of the expected form), ``denied`` (ran, nothing found: negative
evidence for this binding), ``pruned`` (found only values too common to follow), ``error``,
``blocked`` (policy: external egress or active interaction not allowed) and
``needs_collection`` (the method is planned or unavailable; ``needs`` says what would enable it).

Route status follows from its hops, and its ``p_success`` is the product of the hit rates of the
hops not yet confirmed, so confirming a hop raises every route that runs through it and denying
one drops them to zero. That is the whole update rule; the ranking falls out of it.

Pure functions over plain dicts (manifests, observation batches): no I/O here.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

DEFAULT_HIT_RATE = 0.5


@dataclass(frozen=True)
class Method:
    connector: str
    name: str
    accepts: tuple[str, ...]
    emits: tuple[str, ...]
    egress: str
    interaction: str
    independence_group: str
    queries: int
    expected_ms: int
    availability: str = "available"
    needs: tuple[str, ...] = ()
    prior_hit_rate: float = DEFAULT_HIT_RATE
    acquirable: bool = False

    @property
    def key(self) -> str:
        return f"{self.connector}/{self.name}"


@dataclass(frozen=True)
class AbstractHop:
    method: Method
    from_form: str
    to_form: str


@dataclass
class Policy:
    max_hops: int = 4
    allow_external_egress: bool = False
    allow_active: bool = False
    max_routes: int = 500
    assume_acquired: tuple[str, ...] = ()
    include_acquirable: bool = False


@dataclass
class Goal:
    forms: tuple[str, ...]
    tag_prefix: str | None = None
    rung: str | None = None


@dataclass
class Evidence:
    """Observation batches plus the engine's pruning decisions, indexed for hop matching."""
    batches: list[dict] = field(default_factory=list)
    pruned: set[tuple[str, str]] = field(default_factory=set)  # (form, value)

    def find(self, method: Method, inputs: list[dict]) -> list[dict]:
        want = {_k(n) for n in inputs}
        out = []
        for b in self.batches:
            c = b["connector"]
            if c["id"] == method.connector and c["method"] == method.name:
                if want & {_k(n) for n in b["request"]["inputs"]}:
                    out.append(b)
        return out


def _k(node: dict) -> tuple[str, str]:
    v = node["value"]
    return node["form"], ",".join(map(str, v)) if isinstance(v, list) else str(v)


def acquire_need(connector_id: str) -> str:
    return f"acquire {connector_id}"


def load_methods(manifests: list[dict], assume_acquired: tuple[str, ...] = ()) -> list[Method]:
    """Acquirable sources become unavailable methods whose need is 'acquire <id>', unless the
    plan assumes them acquired (what-if)."""
    methods = []
    for m in manifests:
        acq = m.get("tier") == "acquirable"
        assumed = m["id"] in assume_acquired
        for meth in m["methods"]:
            availability = meth.get("availability", "available")
            needs = tuple(meth.get("needs", []))
            if acq and not assumed:
                availability, needs = "unavailable", (acquire_need(m["id"]),) + needs
            methods.append(Method(
                connector=m["id"], name=meth["name"],
                accepts=tuple(meth["accepts"]), emits=tuple(meth["emits"]["forms"]),
                egress=m["egress"], interaction=meth["interaction"],
                independence_group=m["independence_group"],
                queries=meth["cost"]["queries"], expected_ms=meth["cost"].get("expected_ms", 0),
                availability=availability, needs=needs,
                prior_hit_rate=meth.get("prior_hit_rate", DEFAULT_HIT_RATE), acquirable=acq))
    return methods


def enumerate_routes(methods: list[Method], seed_forms: set[str], goal: Goal,
                     policy: Policy) -> tuple[list[list[AbstractHop]], bool]:
    """Simple paths in form space (no form visited twice), seed form -> goal form, within
    max_hops. Returns (routes, truncated). Bounded by max_routes so a broad catalog cannot
    explode; routes are generated shortest-first so truncation drops the longest."""
    by_form: dict[str, list[tuple[Method, str]]] = {}
    for m in methods:
        for a in m.accepts:
            for b in m.emits:
                if a != b:
                    by_form.setdefault(a, []).append((m, b))
    goal_forms = set(goal.forms)
    dist = distance_to_goal(by_form, goal_forms)
    reach = lambda form, hops_left: dist.get(form, 1 << 30) <= hops_left  # noqa: E731
    routes: list[list[AbstractHop]] = []
    frontier = [[AbstractHop(m, s, b)] for s in sorted(seed_forms) for m, b in by_form.get(s, [])
                if reach(b, policy.max_hops - 1)]
    depth = 1
    truncated = False
    while frontier and depth <= policy.max_hops:
        nxt = []
        for path in frontier:
            last = path[-1]
            if last.to_form in goal_forms:
                routes.append(path)
                if len(routes) >= policy.max_routes:
                    return routes, True
                continue  # a route ends at the first goal form it reaches
            if depth == policy.max_hops:
                continue
            seen = {path[0].from_form} | {h.to_form for h in path}
            for m, b in by_form.get(last.to_form, []):
                if b not in seen and reach(b, policy.max_hops - depth - 1):
                    nxt.append(path + [AbstractHop(m, last.to_form, b)])
        frontier = nxt
        depth += 1
    return routes, truncated


def distance_to_goal(by_form: dict[str, list[tuple[Method, str]]], goal_forms: set[str]) -> dict[str, int]:
    """Fewest hops from each form to any goal form (reverse BFS). Lets enumeration drop any
    extension that cannot reach the goal in the hops left, which keeps deep identity routes
    tractable."""
    rev: dict[str, set[str]] = {}
    for a, outs in by_form.items():
        for _, b in outs:
            rev.setdefault(b, set()).add(a)
    dist = {g: 0 for g in goal_forms}
    queue = list(goal_forms)
    while queue:
        b = queue.pop(0)
        for a in rev.get(b, ()):
            if a not in dist:
                dist[a] = dist[b] + 1
                queue.append(a)
    return dist


def route_id(path: list[AbstractHop]) -> str:
    sig = "|".join(f"{h.method.key}:{h.from_form}>{h.to_form}" for h in path)
    return "r-" + hashlib.sha256(sig.encode()).hexdigest()[:10]


def _policy_block(m: Method, policy: Policy) -> str | None:
    if m.egress == "external" and not policy.allow_external_egress:
        return "external egress not allowed for this investigation"
    if m.interaction == "active" and not policy.allow_active:
        return "active interaction not allowed for this investigation"
    return None


def _goal_ok(node: dict, goal: Goal) -> bool:
    if goal.tag_prefix and node["form"] == "syn:tag":
        v = str(node["value"])
        return v == goal.tag_prefix or v.startswith(goal.tag_prefix + ".")
    return True


def bind_route(path: list[AbstractHop], seeds: list[dict], ev: Evidence, policy: Policy,
               goal: Goal, hit_rates: dict[str, float]) -> dict:
    hops, bound = [], [s for s in seeds if s["form"] == path[0].from_form]
    blocked_before = False
    for i, h in enumerate(path, 1):
        m = h.method
        p, p_src = (hit_rates[m.key], "measured") if m.key in hit_rates else (m.prior_hit_rate, "seed")
        hop = {"n": i, "connector": m.connector, "method": m.name, "from_form": h.from_form,
               "to_form": h.to_form, "p_hit": round(p, 4), "p_source": p_src}
        if m.availability != "available":
            hop.update(status="needs_collection", needs=list(m.needs),
                       reason=f"method is {m.availability}")
            hops.append(hop)
            blocked_before = True
            continue
        block = _policy_block(m, policy)
        if block:
            hop.update(status="blocked", reason=block,
                       needs=["allow external egress" if "egress" in block else "allow active interaction"])
            hops.append(hop)
            blocked_before = True
            continue
        if not bound or blocked_before:
            hop["status"] = "pending"
            hops.append(hop)
            bound = []
            continue
        hop["bound_inputs"] = bound
        batches = ev.find(m, bound)
        if not batches:
            hop["status"] = "ready"
            hops.append(hop)
            bound = []
            continue
        hop["evidence"] = [b["request"]["fingerprint"] for b in batches]
        if any(b.get("errors") for b in batches) and not any(b["nodes"] for b in batches):
            hop.update(status="error", reason="; ".join(e["message"] for b in batches for e in b["errors"]))
            hops.append(hop)
            bound = []
            continue
        found = [{"form": n["form"], "value": n["value"]} for b in batches for n in b["nodes"]
                 if n["form"] == h.to_form]
        final = i == len(path)
        if final:
            found = [n for n in found if _goal_ok(n, goal)]
        kept = [n for n in found if _k(n) not in ev.pruned]
        tried = {_k(n) for b in batches for n in b["request"]["inputs"]}
        untried = [n for n in bound if _k(n) not in tried]
        if not kept and untried:
            # Only some inputs have been tried and none paid off yet: still runnable for the rest.
            hop.update(status="ready", bound_inputs=untried,
                       reason=f"{len(bound) - len(untried)} of {len(bound)} input(s) tried, nothing yet")
            hops.append(hop)
            bound = []
            continue
        if kept:
            hop.update(status="confirmed", results=kept)
            bound = kept
        elif found:
            hop.update(status="pruned", reason=f"all {len(found)} result(s) too common to follow",
                       results=found)
            bound = []
        else:
            hop.update(status="denied",
                       reason="ran and found nothing" + (" matching the goal" if final else ""))
            bound = []
        hops.append(hop)

    statuses = [h["status"] for h in hops]
    if all(s == "confirmed" for s in statuses):
        status = "completed"
    elif any(s in ("denied", "pruned", "error") for s in statuses):
        status = "dead"
    elif "needs_collection" in statuses:
        status = "needs_collection"
    elif "blocked" in statuses:
        status = "blocked"
    elif "confirmed" in statuses:
        status = "in_progress"
    else:
        status = "viable"

    p = 0.0 if status == "dead" else 1.0
    if status != "dead":
        for h in hops:
            if h["status"] != "confirmed":
                p *= h["p_hit"]
    rem = [(hop, ah) for hop, ah in zip(hops, path) if hop["status"] != "confirmed"]
    needs = sorted({n for h in hops for n in h.get("needs", [])})
    route = {
        "id": route_id(path), "rank": 0, "status": status, "p_success": round(p, 4),
        "remaining_cost": {"queries": sum(ah.method.queries for _, ah in rem) if status != "dead" else 0,
                           "expected_ms": sum(ah.method.expected_ms for _, ah in rem) if status != "dead" else 0},
        "independence_groups": sorted({h.method.independence_group for h in path}),
        "hops": hops,
    }
    if needs:
        route["needs"] = needs
    return route


STATUS_ORDER = {"completed": 0, "in_progress": 1, "viable": 1, "needs_collection": 2, "blocked": 3, "dead": 4}
NO_NEW_GROUP_WEIGHT = 0.25


def mark_corroboration(routes: list[dict]) -> set[str]:
    """Once any route has completed, a route only raises confidence if it brings an
    independence group the completed routes do not already have (design 6.2)."""
    done = {g for r in routes if r["status"] == "completed" for g in r["independence_groups"]}
    for r in routes:
        if r["status"] != "completed":
            r["corroborates"] = (not done) or bool(set(r["independence_groups"]) - done)
    return done


def rank(routes: list[dict]) -> None:
    routes.sort(key=lambda r: (STATUS_ORDER[r["status"]], not r.get("corroborates", True),
                               len(r.get("needs", [])), -r["p_success"], r["remaining_cost"]["queries"], len(r["hops"]), r["id"]))
    for i, r in enumerate(routes, 1):
        r["rank"] = i


def next_actions(routes: list[dict], methods: dict[str, Method]) -> list[dict]:
    acts: dict[tuple, dict] = {}
    for r in routes:
        if r["status"] not in ("viable", "in_progress"):
            continue
        for h in r["hops"]:
            if h["status"] == "ready":
                key = (h["connector"], h["method"], tuple(sorted(_k(n) for n in h["bound_inputs"])))
                a = acts.setdefault(key, {"connector": h["connector"], "method": h["method"],
                                          "inputs": h["bound_inputs"], "unlocks_routes": [], "value": 0.0})
                a["unlocks_routes"].append(r["id"])
                a["value"] += r["p_success"] * (1.0 if r.get("corroborates", True) else NO_NEW_GROUP_WEIGHT)
                break
    out = []
    for a in acts.values():
        q = max(1, methods[f"{a['connector']}/{a['method']}"].queries)
        a["value"] = round(a["value"] / q, 4)
        out.append(a)
    out.sort(key=lambda a: (-a["value"], -len(a["unlocks_routes"]), a["connector"], a["method"]))
    return out


def diff(previous: dict | None, routes: list[dict]) -> list[dict]:
    if not previous:
        return []
    old = {r["id"]: r for r in previous["routes"]}
    changes = []
    for r in routes:
        o = old.get(r["id"])
        if o is None:
            changes.append({"route": r["id"], "from": None, "to": r["status"], "rank_from": None,
                            "rank_to": r["rank"], "because": "new route"})
            continue
        if o["status"] != r["status"]:
            moved = [h for h, oh in zip(r["hops"], o["hops"]) if h["status"] != oh["status"]
                     and h["status"] in ("confirmed", "denied", "pruned", "error")]
            why = "; ".join(f"hop {h['n']} {h['connector']}/{h['method']} {h['status']}"
                            + (f" ({h['reason']})" if h.get("reason") else "") for h in moved)
            changes.append({"route": r["id"], "from": o["status"], "to": r["status"],
                            "rank_from": o["rank"], "rank_to": r["rank"], "because": why or "re-ranked"})
    return changes


def acquisitions(routes: list[dict], manifests: list[dict]) -> list[dict]:
    meta = {m["id"]: m for m in manifests if m.get("tier") == "acquirable"}
    out = {}
    for r in routes:
        if r["status"] == "dead":
            continue
        missing = [n[len("acquire "):] for n in r.get("needs", []) if n.startswith("acquire ")]
        for cid in missing:
            a = out.setdefault(cid, {"connector": cid, "unlocks_routes": 0, "sole_blocker_routes": 0,
                                     "best_p": 0.0, "best_route": None})
            a["unlocks_routes"] += 1
            if len(missing) == 1 and len(r["needs"]) == 1:
                a["sole_blocker_routes"] += 1
            if r["p_success"] > a["best_p"]:
                a["best_p"], a["best_route"] = r["p_success"], r["id"]
    for cid, a in out.items():
        m = meta.get(cid)
        if m:
            a.update(title=m["title"], path=m["acquisition"]["path"], cost_band=m["acquisition"]["cost_band"])
    return sorted(out.values(), key=lambda a: (-a["sole_blocker_routes"], -a["unlocks_routes"], -a["best_p"], a["connector"]))


COST_ORDER = {"none": 0, "$": 1, "$$": 2, "$$$": 3}


def acquisition_sets(routes: list[dict], manifests: list[dict], limit: int = 10) -> list[dict]:
    """Smallest combinations of missing sources that would open at least one route. Higher
    rungs almost never hinge on one source, so this is the real shopping list."""
    meta = {m["id"]: m for m in manifests if m.get("tier") == "acquirable"}
    sets: dict[frozenset, dict] = {}
    for r in routes:
        if r["status"] != "needs_collection":
            continue
        other = [n for n in r.get("needs", []) if not n.startswith("acquire ")]
        if other:
            continue  # also needs a non-acquisition change; shown under requirements
        key = frozenset(n[len("acquire "):] for n in r["needs"])
        e = sets.setdefault(key, {"connectors": sorted(key), "routes": 0, "best_p": 0.0, "best_route": None})
        e["routes"] += 1
        if r["p_success"] > e["best_p"]:
            e["best_p"], e["best_route"] = r["p_success"], r["id"]
    for e in sets.values():
        bands = [meta[c]["acquisition"]["cost_band"] for c in e["connectors"] if c in meta]
        e["max_cost_band"] = max(bands, key=COST_ORDER.get) if bands else "none"
        e["paths"] = sorted({meta[c]["acquisition"]["path"] for c in e["connectors"] if c in meta})
    return sorted(sets.values(), key=lambda e: (len(e["connectors"]), COST_ORDER[e["max_cost_band"]],
                                                -e["best_p"], -e["routes"], e["connectors"]))[:limit]


def plan(manifests: list[dict], seeds: list[dict], goal: Goal, policy: Policy,
         evidence: Evidence | None = None, previous: dict | None = None,
         hit_rates: dict[str, float] | None = None, trigger: str = "initial",
         investigation_id: str | None = None, now: datetime | None = None) -> dict:
    methods = load_methods(manifests, policy.assume_acquired)
    evidence = evidence or Evidence()
    paths, truncated = enumerate_routes(methods, {s["form"] for s in seeds}, goal, policy)
    routes = [bind_route(p, seeds, evidence, policy, goal, hit_rates or {}) for p in paths]
    mark_corroboration(routes)
    rank(routes)
    by_status: dict[str, int] = {}
    for r in routes:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    unlock: dict[str, list[str]] = {}
    for r in routes:
        if r["status"] in ("needs_collection", "blocked"):
            for n in r.get("needs", []):
                if not n.startswith("acquire "):
                    unlock.setdefault(n, []).append(r["id"])
    requirements = sorted(({"need": n, "unlocks_routes": len(ids)} for n, ids in unlock.items()),
                          key=lambda x: (-x["unlocks_routes"], x["need"]))
    completed_groups = sorted({g for r in routes if r["status"] == "completed"
                               for g in r["independence_groups"]})
    out = {
        "schema": "pivot.plan/1",
        "revision": (previous["revision"] + 1) if previous else 0,
        "generated_at": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "trigger": trigger,
        "seeds": seeds,
        "goal": {"forms": list(goal.forms), **({"tag_prefix": goal.tag_prefix} if goal.tag_prefix else {}),
                 **({"rung": goal.rung} if goal.rung else {})},
        "policy": {"max_hops": policy.max_hops, "allow_external_egress": policy.allow_external_egress,
                   "allow_active": policy.allow_active, "max_routes": policy.max_routes,
                   "include_acquirable": policy.include_acquirable,
                   "assume_acquired": list(policy.assume_acquired)},
        "summary": {"routes": len(routes), "routes_truncated": truncated, "by_status": by_status,
                    "independent_groups_completed": completed_groups,
                    "requirements": requirements,
                    "acquisitions": acquisitions(routes, manifests),
                    "acquisition_sets": acquisition_sets(routes, manifests),
                    "best_route": routes[0]["id"] if routes and routes[0]["status"] != "dead" else None},
        "next_actions": next_actions(routes, {m.key: m for m in methods}),
        "routes": routes,
        "changes": diff(previous, routes),
    }
    if investigation_id:
        out["investigation_id"] = investigation_id
    return out


GLYPH = {"confirmed": "✔", "denied": "✘", "pruned": "≈", "error": "!", "ready": "▶",
         "pending": "·", "blocked": "⊘", "needs_collection": "◌"}


def render_text(p: dict, limit: int = 15) -> str:
    s = p["summary"]
    lines = [f"plan r{p['revision']} ({p['trigger']}): {s['routes']} routes "
             + ", ".join(f"{k} {v}" for k, v in sorted(s["by_status"].items()))
             + (" [truncated]" if s.get("routes_truncated") else "")]
    if s["independent_groups_completed"]:
        lines.append("  goal reached via independent groups: " + ", ".join(s["independent_groups_completed"]))
    if s.get("acquisitions"):
        lines.append("missing sources (sole = routes where it is the only thing missing):")
        for a in s["acquisitions"][:8]:
            lines.append(f"  + {a['connector']:<26} {a.get('path', '?'):<16} {a.get('cost_band', '?'):<4} "
                         f"sole {a['sole_blocker_routes']:<4} total {a['unlocks_routes']:<5} best p={a['best_p']}")
    if s.get("requirements"):
        lines.append("would unlock more routes:")
        for q in s["requirements"][:5]:
            lines.append(f"  ◌ {q['need']}  ({q['unlocks_routes']} route(s))")
    if p["changes"]:
        lines.append("changes:")
        for c in p["changes"]:
            lines.append(f"  {c['route']} {c['from']} -> {c['to']} (rank {c['rank_from']} -> {c['rank_to']}): {c['because']}")
    if p["next_actions"]:
        lines.append("next:")
        for a in p["next_actions"][:5]:
            vals = ", ".join(str(n["value"]) for n in a["inputs"])
            lines.append(f"  ▶ {a['connector']}/{a['method']}({vals})  advances {len(a['unlocks_routes'])} route(s), value {a['value']}")
    lines.append("routes:")
    for r in p["routes"][:limit]:
        chain = f" {r['hops'][0]['from_form']}"
        for h in r["hops"]:
            chain += f" ─{GLYPH[h['status']]} {h['connector']}/{h['method']}→ {h['to_form']}"
        flag = " (same sources as a completed route)" if r.get("corroborates") is False else ""
        lines.append(f"  #{r['rank']:<3} {r['status']:<16} p={r['p_success']:<6} {r['id']}{chain}{flag}")
        if r.get("needs"):
            lines.append(f"       needs: {'; '.join(r['needs'])}")
    if len(p["routes"]) > limit:
        lines.append(f"  … {len(p['routes']) - limit} more")
    return "\n".join(lines)


def render_rung(p: dict, rung: dict) -> str:
    """One block per ladder rung: is it reachable with what you have, and what to get first."""
    s = p["summary"]
    runnable = s["by_status"].get("viable", 0) + s["by_status"].get("in_progress", 0)
    lines = [f"== {rung['name']}: {rung['question']}",
             f"   {s['routes']} routes within {p['policy']['max_hops']} hops"
             + (" [truncated]" if s.get("routes_truncated") else "")
             + f"; runnable now {runnable}; "
             + ", ".join(f"{k} {v}" for k, v in sorted(s["by_status"].items()))]
    best = next((r for r in p["routes"] if r["status"] in ("viable", "in_progress", "completed")), None)
    if best:
        lines.append("   best runnable: " + _chain(best))
    else:
        lines.append("   nothing runnable with current sources")
    cheapest = next((r for r in p["routes"] if r["status"] == "needs_collection"), None)
    if cheapest:
        lines.append(f"   fewest missing ({len(cheapest['needs'])}): " + _chain(cheapest))
        lines.append("      needs: " + "; ".join(cheapest["needs"]))
    if s.get("acquisition_sets"):
        lines.append("   smallest source combinations that open a route (cheapest first):")
        for e in s["acquisition_sets"][:5]:
            lines.append(f"     + {' + '.join(e['connectors']):<62} max {e['max_cost_band']:<4} "
                         f"{e['routes']:>3} route(s), best p={e['best_p']}")
    return "\n".join(lines)


def _chain(r: dict) -> str:
    out = r["hops"][0]["from_form"]
    for h in r["hops"]:
        out += f" -{GLYPH[h['status']]} {h['connector']}/{h['method']}-> {h['to_form']}"
    return f"p={r['p_success']} " + out
