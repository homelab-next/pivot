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
from pivot.planner import Evidence, Goal, Policy, plan, render_text  # noqa: E402


def node(arg: str) -> dict:
    form, _, value = arg.partition("=")
    if not value:
        raise argparse.ArgumentTypeError(f"expected form=value, got {arg!r}")
    return {"form": form, "value": value}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=node, action="append", required=True)
    ap.add_argument("--goal-form", action="append", required=True)
    ap.add_argument("--goal-tag")
    ap.add_argument("--max-hops", type=int, default=4)
    ap.add_argument("--max-routes", type=int, default=200)
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

    manifests = [yaml.safe_load(p.read_text()) for p in sorted(a.catalog.glob("*.yaml"))]
    batches = [json.loads(p.read_text()) for p in sorted(a.evidence.glob("*.json"))] if a.evidence else []
    ev = Evidence(batches=batches, pruned={(n["form"], n["value"]) for n in a.pruned})
    previous = json.loads(a.previous.read_text()) if a.previous else None
    trigger = a.trigger or (f"{len(batches)} batch(es)" if batches else "initial")
    p = plan(manifests, a.seed, Goal(tuple(a.goal_form), a.goal_tag),
             Policy(a.max_hops, a.allow_external, a.allow_active, a.max_routes),
             evidence=ev, previous=previous, trigger=trigger)
    if a.out:
        a.out.write_text(json.dumps(p, indent=1, ensure_ascii=False) + "\n")
    if a.text or not a.out:
        print(render_text(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
