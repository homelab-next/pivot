#!/usr/bin/env python3
"""Validate connector manifests and example documents against the schemas, and check that
every form a manifest names exists in the pinned Synapse model (or is an extended _pivot: form).

    python3 tools/validate.py          # exit 0 = all valid
Needs: jsonschema>=4.18, pyyaml.
"""
from __future__ import annotations

import json
import pathlib
import sys

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
EXAMPLES = {
    "observation-batch": "observation-batch.schema.json",
    "investigation": "investigation.schema.json",
    "assessment": "assessment.schema.json",
    "plan": "plan.schema.json",
}


def registry() -> Registry:
    reg = Registry()
    for p in SCHEMAS.glob("*.schema.json"):
        doc = json.loads(p.read_text())
        res = Resource.from_contents(doc)
        reg = reg.with_resource(p.name, res).with_resource(doc["$id"], res)
    return reg


def validator(name: str, reg: Registry) -> Draft202012Validator:
    return Draft202012Validator(json.loads((SCHEMAS / name).read_text()), registry=reg)


def known_forms() -> set[str]:
    files = sorted((ROOT / "catalog" / "generated").glob("synapse-model-*.forms.txt"))
    if not files:
        sys.exit("no catalog/generated/synapse-model-*.forms.txt; run tools/derive_native_pivots.py")
    return set(files[-1].read_text().split())


def main() -> int:
    reg, forms, bad = registry(), known_forms(), 0
    mv = validator("connector-manifest.schema.json", reg)
    ids = set()
    manifests = sorted((ROOT / "catalog" / "connectors").glob("*.yaml")) + \
        sorted((ROOT / "catalog" / "acquirable").glob("*.yaml"))
    for p in manifests:
        doc = yaml.safe_load(p.read_text())
        errs = [f"{'/'.join(map(str, e.path))}: {e.message}" for e in mv.iter_errors(doc)]
        if doc.get("id") in ids:
            errs.append(f"duplicate connector id {doc['id']}")
        ids.add(doc.get("id"))
        for m in doc.get("methods", []):
            if doc.get("tier") == "acquirable" and m.get("availability"):
                errs.append(f"method {m['name']}: acquirable sources get availability from the tier")
            if m.get("availability", "available") != "available" and not m.get("needs"):
                errs.append(f"method {m['name']}: availability {m['availability']} requires 'needs'")
            for f in m.get("accepts", []) + m.get("emits", {}).get("forms", []):
                if f not in forms and not f.startswith("_pivot:"):
                    errs.append(f"method {m['name']}: unknown Synapse form {f}")
        bad += report(p, errs)
    for p in sorted((ROOT / "examples").rglob("*.json")):
        kind = next((k for k in EXAMPLES if p.name.startswith(k)), None)
        if kind is None and p.parent.name == "batches":
            kind = "observation-batch"
        if kind is None:
            bad += report(p, ["example name must start with one of " + ", ".join(EXAMPLES)])
            continue
        doc = json.loads(p.read_text())
        bad += report(p, [f"{'/'.join(map(str, e.path))}: {e.message}"
                          for e in validator(EXAMPLES[kind], reg).iter_errors(doc)])
    return 1 if bad else 0


def report(path: pathlib.Path, errs: list[str]) -> int:
    rel = path.relative_to(ROOT)
    if errs:
        print(f"FAIL {rel}")
        for e in errs:
            print(f"     {e}")
        return 1
    print(f"ok   {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
