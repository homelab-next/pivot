# pivot

Goal-directed investigation over linked security data: start from a seed (IP, JA4, cookie,
hash, report), follow every route through the available sources, and end with an assessment
whose confidence comes from how many **independent** routes reach it.

Synapse is the primary graph and its data model is the vocabulary. Every other source plugs in
as a connector that maps its data into Synapse forms.

**Status: contracts plus a working route planner** (no engine or UI yet). Read [`docs/design.md`](docs/design.md).

| Path | What |
|---|---|
| `docs/design.md` | the design: vocabulary, pivot catalog, loop, data shapes, phases |
| `schemas/` | JSON Schemas: observation batch (in), connector manifest, investigation and assessment (out) |
| `catalog/connectors/` | one manifest per source: what it accepts and emits, its egress, cost and gaps |
| `catalog/generated/` | Synapse forms and native pivots derived from the model (2.247.0) |
| `examples/` | one valid document per schema |
| `tools/derive_native_pivots.py` | regenerates `catalog/generated/` from an installed `synapse` package |
| `tools/validate.py` | validates manifests and examples; rejects forms not in the model |
| `pivot/planner.py`, `tools/plan.py` | route plan: every chain of pivots from seed to goal, hop status updated from evidence |
| `examples/scenario/` | one seed planned and re-planned across three revisions |
| `tests/` | planner tests (`pytest`) |

```bash
pip install -r requirements-dev.txt
python3 tools/validate.py
python3 -m pytest -q tests
python3 tools/plan.py --seed inet:ipv4=203.0.113.7 --goal-form syn:tag --goal-tag cno.threat --text
```
