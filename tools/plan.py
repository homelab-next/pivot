#!/usr/bin/env python3
"""Produce or update a route plan.

    python3 tools/plan.py --seed inet:ipv4=203.0.113.7 --goal-form syn:tag --goal-tag cno.threat \\
        [--evidence DIR_OF_OBSERVATION_BATCHES] [--pruned form=value ...] \\
        [--previous plan.json] [--allow-external] [--allow-active] [--max-hops 4] \\
        [--out plan.json] [--text]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from pivot.planner import Evidence, Goal, Policy, plan, render_rung, render_text  # noqa: E402


def node(arg: str) -> dict:
    form, _, value = arg.partition("=")
    if not value:
        raise argparse.ArgumentTypeError(f"expected form=value, got {arg!r}")
    return {"form": form, "value": value}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=node, action="append", required=True)
    ap.add_argument("--goal-form", action="append")
    ap.add_argument("--rung", help="goal from catalog/ladder.yaml (cluster, operator-accounts, persona, identity)")
    ap.add_argument("--ladder", action="store_true", help="plan every rung and print a summary per rung")
    ap.add_argument("--acquirable", action="store_true", help="include catalog/acquirable (sources you could get)")
    ap.add_argument("--assume", action="append", default=[], help="what-if: treat this acquirable source as acquired")
    ap.add_argument("--goal-tag")
    ap.add_argument("--max-hops", type=int, default=4)
    ap.add_argument("--max-routes", type=int, default=None, help="default 500, or 20000 with --ladder")
    ap.add_argument("--allow-external", action="store_true")
    ap.add_argument("--allow-active", action="store_true")
    ap.add_argument("--evidence", type=pathlib.Path)
    ap.add_argument("--pruned", type=node, action="append", default=[])
    ap.add_argument("--previous", type=pathlib.Path)
    ap.add_argument("--trigger", default=None)
    ap.add_argument("--catalog", type=pathlib.Path, default=ROOT / "catalog" / "connectors")
    ap.add_argument("--out", type=pathlib.Path)
    ap.add_argument("--text", action="store_true")
    a = ap.parse_args()

    paths = sorted(a.catalog.glob("*.yaml"))
    if a.acquirable or a.assume:
        paths += sorted((ROOT / "catalog" / "acquirable").glob("*.yaml"))
    manifests = [yaml.safe_load(p.read_text()) for p in paths]
    known = {m["id"] for m in manifests}
    for cid in a.assume:
        if cid not in known:
            ap.error(f"--assume {cid}: no such connector")
    rungs = {r["name"]: r for r in yaml.safe_load((ROOT / "catalog" / "ladder.yaml").read_text())["rungs"]}

    def goal_for(name):
        r = rungs[name]
        return Goal(tuple(r["forms"]), r.get("tag_prefix"), name)

    max_routes = a.max_routes or (20000 if a.ladder else 500)
    policy = Policy(a.max_hops, a.allow_external, a.allow_active, max_routes,
                    tuple(a.assume), bool(a.acquirable or a.assume))
    if a.ladder:
        for name in rungs:
            p = plan(manifests, a.seed, goal_for(name), policy)
            print(render_rung(p, rungs[name]))
        return 0
    if a.rung:
        if a.rung not in rungs:
            ap.error(f"--rung must be one of {sorted(rungs)}")
        goal = goal_for(a.rung)
    elif a.goal_form:
        goal = Goal(tuple(a.goal_form), a.goal_tag)
    else:
        ap.error("give --goal-form, --rung or --ladder")
    batches = [json.loads(p.read_text()) for p in sorted(a.evidence.glob("*.json"))] if a.evidence else []
    ev = Evidence(batches=batches, pruned={(n["form"], n["value"]) for n in a.pruned})
    previous = json.loads(a.previous.read_text()) if a.previous else None
    trigger = a.trigger or (f"{len(batches)} batch(es)" if batches else "initial")
    p = plan(manifests, a.seed, goal, policy,
             evidence=ev, previous=previous, trigger=trigger)
    if a.out:
        a.out.write_text(json.dumps(p, indent=1, ensure_ascii=False) + "\n")
    if a.text or not a.out:
        print(render_text(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
