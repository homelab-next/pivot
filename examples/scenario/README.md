# Scenario: a honeypot visitor, planned and re-planned

Seed `inet:ipv4=203.0.113.7`, goal: any `syn:tag` under `cno.threat` (an attribution), at most
3 hops, no external egress. The batches are invented example data. The plans are real output of
`tools/plan.py` over the real `catalog/connectors/`.

| Revision | Evidence | What changed |
|---|---|---|
| `plan-r0` | none | 106 candidate routes: 46 runnable, 60 blocked on external egress (IntelOwl). |
| `plan-r1` | 1: Synapse has no tags on the IP. 2: the honeypot saw one HASSH from it. | The direct-tag route is **dead**. The three routes through the HASSH are **in progress** and jump to the top, each now bound to that HASSH value. |
| `plan-r2` | 3: the IP served two TLS names; the CDN one is pruned as too common. 4: the other domain carries `cno.threat.crm.example_cluster`. | One route **completed** (network capture → Synapse). Ranking then favours routes through sources not used yet (honeypot), because only those add independent evidence. Routes that would only repeat network capture + Synapse are flagged and drop. |

```bash
P="python3 tools/plan.py --seed inet:ipv4=203.0.113.7 --goal-form syn:tag --goal-tag cno.threat --max-hops 3"
$P --out plan-r0.json
$P --evidence <dir with batches 01-02> --previous plan-r0.json --out plan-r1.json --text
$P --evidence <dir with batches 01-04> --pruned inet:fqdn=edge.cdn-provider.example \
   --previous plan-r1.json --out plan-r2.json --text
```

`plan-r*.txt` are the first lines of the text rendering of each revision.
