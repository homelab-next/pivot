#!/usr/bin/env python3
"""Derive the in-graph half of the pivot catalog from the Synapse data model.

Every property whose type is itself a form is a pivot (A:prop -> B), and every light-edge
definition is a pivot (A -(verb)> B). Reading them from the model, rather than listing them by
hand, keeps the catalog in step with Synapse upgrades.

Needs the `synapse` package at the same version as the Cortex (siem-core runs 2.247.0):
    python3 -m venv .venv && .venv/bin/pip install synapse==2.247.0
    .venv/bin/python tools/derive_native_pivots.py --out catalog/generated

Writes:
    synapse-model-<ver>.forms.txt     every form, one per line (used by validate.py)
    native-pivots-<ver>.json          {"props": [...], "edges": [...], "counts": {...}}
No Cortex is started; the model is built straight from the core model modules.
"""
from __future__ import annotations

import argparse
import importlib
import json
import pathlib


def load_model():
    import synapse
    import synapse.datamodel as s_datamodel
    import synapse.lib.modules as s_modules

    defs = []
    for path in s_modules.coremods:
        modname, clsname = path.rsplit(".", 1)
        cls = getattr(importlib.import_module(modname), clsname)
        defs.extend(cls.getModelDefs(cls))
    model = s_datamodel.Model()
    model.addDataModels(defs)
    return model, ".".join(map(str, synapse.version))


def derive(model):
    props = []
    for fname, form in sorted(model.forms.items()):
        for pname, prop in sorted(form.props.items()):
            if pname.startswith("."):
                continue  # universal props (.seen, .created) are not pivots
            target = prop.type.name
            if target in model.forms:
                props.append({"from": target, "to": fname, "via": f"{fname}:{pname}"})
    edges = [{"n1": n1, "verb": verb, "n2": n2} for (n1, verb, n2) in sorted(
        model.edges, key=lambda e: (e[0] or "*", e[1], e[2] or "*"))]
    return props, edges


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="catalog/generated")
    args = ap.parse_args()
    model, ver = load_model()
    props, edges = derive(model)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"synapse-model-{ver}.forms.txt").write_text("\n".join(sorted(model.forms)) + "\n")
    counts = {"forms": len(model.forms), "prop_pivots": len(props), "edge_defs": len(edges)}
    (out / f"native-pivots-{ver}.json").write_text(json.dumps(
        {"synapse_version": ver, "counts": counts, "props": props, "edges": edges}, indent=1) + "\n")
    print(f"synapse {ver}: {counts}")


if __name__ == "__main__":
    main()
