import copy
import hashlib
import json
import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from pivot.planner import Evidence, Goal, Policy, plan  # noqa: E402
import validate  # noqa: E402

IP = {"form": "inet:ipv4", "value": "203.0.113.7"}
GOAL = Goal(("syn:tag",), "cno.threat")


def m(name, accepts, emits, **kw):
    d = {"name": name, "accepts": accepts, "emits": {"forms": emits}, "interaction": kw.pop("interaction", "passive"),
         "time_semantics": "windowed", "cost": {"queries": 1, "expected_ms": 100}, "max_results": 10,
         "prior_hit_rate": kw.pop("p", 0.5)}
    d.update(kw)
    return d


def conn(cid, methods, egress="internal", group=None):
    return {"schema": "pivot.connector/1", "id": cid, "version": "0", "kind": "lake", "egress": egress,
            "independence_group": group or cid, "handling": {"default_tlp": "amber"}, "methods": methods}


CATALOG = [
    conn("dns", [m("ip_to_fqdn", ["inet:ipv4"], ["inet:fqdn"], p=0.8)]),
    conn("hp", [m("ip_to_hash", ["inet:ipv4"], ["hash:md5"], p=0.6)]),
    conn("syn", [m("tags", ["inet:fqdn", "hash:md5", "inet:ipv4"], ["syn:tag"], p=0.5)]),
    conn("ext", [m("rep", ["inet:fqdn"], ["syn:tag"])], egress="external"),
    conn("cookie", [m("ip_to_cookie", ["inet:ipv4"], ["inet:http:cookie"], availability="planned",
                      needs=["cookie logging"]),
                    m("cookie_tags", ["inet:http:cookie"], ["syn:tag"])]),
]


def fp(s):
    return "sha256:" + hashlib.sha256(s.encode()).hexdigest()


def batch(cid, meth, inputs, nodes, errors=()):
    return {"connector": {"id": cid, "version": "0", "method": meth},
            "request": {"inputs": inputs, "fingerprint": fp(cid + meth + json.dumps(inputs))},
            "nodes": [dict(ref=f"n{i}", **n) for i, n in enumerate(nodes)], "errors": list(errors)}


def route(p, *keys):
    for r in p["routes"]:
        if [f"{h['connector']}/{h['method']}" for h in r["hops"]] == list(keys):
            return r
    raise AssertionError(f"no route {keys}")


def run(evidence=None, policy=None, previous=None):
    return plan(copy.deepcopy(CATALOG), [IP], GOAL, policy or Policy(max_hops=3),
                evidence=evidence, previous=previous)


def test_enumerates_ordered_chains_without_revisiting_forms():
    p = run()
    for r in p["routes"]:
        forms = [r["hops"][0]["from_form"]] + [h["to_form"] for h in r["hops"]]
        assert len(forms) == len(set(forms))
        assert forms[-1] == "syn:tag"
        assert all(a["to_form"] == b["from_form"] for a, b in zip(r["hops"], r["hops"][1:]))
    route(p, "dns/ip_to_fqdn", "syn/tags")
    route(p, "syn/tags")


def test_initial_plan_first_hops_ready_rest_pending():
    r = route(run(), "dns/ip_to_fqdn", "syn/tags")
    assert [h["status"] for h in r["hops"]] == ["ready", "pending"]
    assert r["status"] == "viable" and r["p_success"] == pytest.approx(0.4)


def test_confirmation_binds_results_and_raises_route():
    ev = Evidence([batch("dns", "ip_to_fqdn", [IP], [{"form": "inet:fqdn", "value": "a.example"}])])
    r = route(run(ev), "dns/ip_to_fqdn", "syn/tags")
    assert r["status"] == "in_progress"
    assert r["hops"][0]["status"] == "confirmed"
    assert r["hops"][1]["status"] == "ready"
    assert r["hops"][1]["bound_inputs"] == [{"form": "inet:fqdn", "value": "a.example"}]
    assert r["p_success"] == pytest.approx(0.5)


def test_denial_kills_every_route_through_that_hop():
    ev = Evidence([batch("dns", "ip_to_fqdn", [IP], [])])
    p = run(ev)
    for r in p["routes"]:
        if r["hops"][0]["method"] == "ip_to_fqdn":
            assert r["status"] == "dead" and r["p_success"] == 0


def test_goal_tag_prefix_filters_final_hop():
    ev = Evidence([batch("syn", "tags", [IP], [{"form": "syn:tag", "value": "rep.misp"}])])
    r = route(run(ev), "syn/tags")
    assert r["status"] == "dead" and "matching the goal" in r["hops"][0]["reason"]
    ev = Evidence([batch("syn", "tags", [IP], [{"form": "syn:tag", "value": "cno.threat.prc.x"}])])
    assert route(run(ev), "syn/tags")["status"] == "completed"


def test_pruned_results_end_the_route():
    ev = Evidence([batch("dns", "ip_to_fqdn", [IP], [{"form": "inet:fqdn", "value": "cdn.example"}])],
                  pruned={("inet:fqdn", "cdn.example")})
    r = route(run(ev), "dns/ip_to_fqdn", "syn/tags")
    assert r["hops"][0]["status"] == "pruned" and r["status"] == "dead"


def test_partial_inputs_stay_ready_for_the_rest():
    two = [{"form": "inet:fqdn", "value": "a.example"}, {"form": "inet:fqdn", "value": "b.example"}]
    ev = Evidence([batch("dns", "ip_to_fqdn", [IP], two),
                   batch("syn", "tags", [two[0]], [])])
    r = route(run(ev), "dns/ip_to_fqdn", "syn/tags")
    assert r["hops"][1]["status"] == "ready"
    assert r["hops"][1]["bound_inputs"] == [two[1]]


def test_policy_blocks_external_and_names_the_unblock():
    p = run()
    r = route(p, "dns/ip_to_fqdn", "ext/rep")
    assert r["status"] == "blocked" and "allow external egress" in r["needs"]
    r = route(run(policy=Policy(max_hops=3, allow_external_egress=True)), "dns/ip_to_fqdn", "ext/rep")
    assert r["status"] == "viable"


def test_planned_method_shows_as_collection_requirement():
    p = run()
    r = route(p, "cookie/ip_to_cookie", "cookie/cookie_tags")
    assert r["status"] == "needs_collection" and r["needs"] == ["cookie logging"]
    assert {"need": "cookie logging", "unlocks_routes": 1} in p["summary"]["requirements"]


def test_after_a_completion_new_independent_sources_rank_first():
    ev = Evidence([batch("dns", "ip_to_fqdn", [IP], [{"form": "inet:fqdn", "value": "a.example"}]),
                   batch("syn", "tags", [{"form": "inet:fqdn", "value": "a.example"}],
                         [{"form": "syn:tag", "value": "cno.threat.prc.x"}])])
    p = run(ev)
    assert p["routes"][0]["status"] == "completed"
    assert set(p["summary"]["independent_groups_completed"]) == {"dns", "syn"}
    hp = route(p, "hp/ip_to_hash", "syn/tags")
    syn_only = route(p, "syn/tags")
    assert hp["corroborates"] and not syn_only["corroborates"]
    assert hp["rank"] < syn_only["rank"]


def test_revision_diff_explains_status_changes():
    p0 = run()
    ev = Evidence([batch("dns", "ip_to_fqdn", [IP], [])])
    p1 = run(ev, previous=p0)
    assert p1["revision"] == 1
    c = next(c for c in p1["changes"] if c["route"] == route(p1, "dns/ip_to_fqdn", "syn/tags")["id"])
    assert c["from"] == "viable" and c["to"] == "dead" and "dns/ip_to_fqdn denied" in c["because"]


def test_route_ids_are_stable_across_revisions():
    a = {r["id"] for r in run()["routes"]}
    b = {r["id"] for r in run(Evidence([batch("dns", "ip_to_fqdn", [IP], [])]))["routes"]}
    assert a == b


def test_plan_output_matches_schema():
    reg = validate.registry()
    v = validate.validator("plan.schema.json", reg)
    manifests = [yaml.safe_load(p.read_text()) for p in sorted((ROOT / "catalog/connectors").glob("*.yaml"))]
    p = plan(manifests, [IP], GOAL, Policy(max_hops=3))
    assert not list(v.iter_errors(p))
    assert p["summary"]["routes"] > 0


def test_repository_validates():
    assert validate.main() == 0


# --- acquirable sources, what-if, ladder -------------------------------------------------

def acq(cid, methods, path="commercial", cost="$$"):
    d = conn(cid, methods, egress="internal")
    d.update(tier="acquirable", title=cid, acquisition={"path": path, "cost_band": cost, "examples": ["x"]})
    return d


ACQ = [
    acq("pdns", [m("fqdn_ips", ["inet:fqdn"], ["inet:ipv4"]), m("ip_fqdns", ["inet:ipv4"], ["inet:fqdn"], p=0.7)]),
    acq("whois", [m("reg", ["inet:fqdn"], ["inet:email"], p=0.3)]),
    acq("legal", [m("sub", ["inet:email"], ["ps:person"], p=0.4)], path="legal_process", cost="none"),
]


def test_acquirable_source_is_a_named_missing_link():
    p = plan(copy.deepcopy(ACQ), [IP], Goal(("inet:email",)), Policy(max_hops=3))
    r = route(p, "pdns/ip_fqdns", "whois/reg")
    assert r["status"] == "needs_collection"
    assert r["needs"] == ["acquire pdns", "acquire whois"]
    assert p["summary"]["acquisition_sets"][0]["connectors"] == ["pdns", "whois"]


def test_what_if_assumed_source_becomes_runnable():
    pol = Policy(max_hops=3, assume_acquired=("pdns", "whois"))
    p = plan(copy.deepcopy(ACQ), [IP], Goal(("inet:email",)), pol)
    r = route(p, "pdns/ip_fqdns", "whois/reg")
    assert r["status"] == "viable" and [h["status"] for h in r["hops"]] == ["ready", "pending"]


def test_lab_route_ranks_above_one_needing_acquisition():
    p = plan(copy.deepcopy(CATALOG) + copy.deepcopy(ACQ), [IP], Goal(("inet:email",)), Policy(max_hops=3))
    lab = route(p, "dns/ip_to_fqdn", "whois/reg")
    both = route(p, "pdns/ip_fqdns", "whois/reg")
    assert len(lab["needs"]) < len(both["needs"]) and lab["rank"] < both["rank"]


def test_sole_blocker_counts_routes_missing_only_that_source():
    p = plan(copy.deepcopy(CATALOG) + copy.deepcopy(ACQ), [IP], Goal(("inet:email",)), Policy(max_hops=3))
    whois = next(a for a in p["summary"]["acquisitions"] if a["connector"] == "whois")
    assert whois["sole_blocker_routes"] >= 1 and whois["path"] == "commercial"


def test_goal_distance_pruning_keeps_every_route():
    from pivot.planner import enumerate_routes, load_methods
    import pivot.planner as pl
    methods = load_methods(copy.deepcopy(CATALOG) + copy.deepcopy(ACQ))
    goal = Goal(("ps:person",))
    pruned, _ = enumerate_routes(methods, {"inet:ipv4"}, goal, Policy(max_hops=4, max_routes=10**6))
    real = pl.distance_to_goal
    pl.distance_to_goal = lambda by_form, goals: {f: 0 for f in {"inet:ipv4", "inet:fqdn", "hash:md5", "syn:tag",
                                                                "inet:http:cookie", "inet:email", "ps:person"}}
    try:
        full, _ = enumerate_routes(methods, {"inet:ipv4"}, goal, Policy(max_hops=4, max_routes=10**6))
    finally:
        pl.distance_to_goal = real
    sig = lambda rs: {tuple(h.method.key for h in r) for r in rs}  # noqa: E731
    assert sig(pruned) == sig(full) and pruned


def test_real_acquirable_catalog_reaches_identity_only_via_legal_or_breach_data():
    manifests = [yaml.safe_load(p.read_text()) for d in ("connectors", "acquirable")
                 for p in sorted((ROOT / "catalog" / d).glob("*.yaml"))]
    p = plan(manifests, [IP], Goal(("ps:person",), rung="identity"),
             Policy(max_hops=6, allow_external_egress=True, include_acquirable=True, max_routes=20000))
    last = {r["hops"][-1]["connector"] for r in p["routes"]}
    assert last <= {"provider-legal-process", "breach-and-stealer-data"}, last
    v = validate.validator("plan.schema.json", validate.registry())
    assert not list(v.iter_errors(p))


def test_ladder_file_rungs_use_known_forms():
    rungs = yaml.safe_load((ROOT / "catalog" / "ladder.yaml").read_text())["rungs"]
    forms = validate.known_forms()
    assert [r["name"] for r in rungs] == ["cluster", "operator-accounts", "persona", "identity"]
    for r in rungs:
        assert set(r["forms"]) <= forms
