# Attribution ladder: from an AWS address to a name

The question here is not limited to the lab: **what links would it take to get from a piece of
activity to the people behind it, and which sources would supply them?** The planner answers
that mechanically once every source you *could* have is in the catalog. `catalog/acquirable/`
holds 21 such sources, each one a manifest with its links, how you would get it (free,
commercial, build it, membership, or law enforcement only), a cost band, real examples and
its legal constraints.

Worked example throughout: the actor operates from **AWS**.

```bash
# what is reachable today vs with everything you could get, rung by rung
python3 tools/plan.py --seed inet:ipv4=52.1.2.3 --ladder --acquirable --allow-external --max-hops 6
# what-if: which rungs open if you add the free sources
python3 tools/plan.py --seed inet:ipv4=52.1.2.3 --ladder --acquirable --allow-external --max-hops 6 \
  --assume cert-transparency --assume code-search --assume cloud-ranges \
  --assume aws-key-attribution --assume malware-config-extraction --assume persona-osint
```

The outputs are in `examples/aws/` (`ladder-today.txt`, `ladder-free-tier.txt`). Hit rates in the
manifests are seed guesses, so treat the `p=` values as relative, not as probabilities.

## 1. The ladder

Attribution is four different questions, each with its own evidence and its own bar.
`catalog/ladder.yaml` defines them as planner goals.

| Rung | Question | Goal forms | Independent sources before you say it |
|---|---|---|---|
| **cluster** | Is this activity part of something already tracked? | `#cno.threat.*` tag, `risk:threat` | 2 |
| **operator-accounts** | Which accounts does the operator control? | `inet:service:tenant` (AWS account), `inet:email`, `inet:web:acct`, `inet:service:account` | 2 |
| **persona** | Which consistent online identity runs those accounts? | `ps:persona`, `ps:contact` | 3 |
| **identity** | Which real person or organisation is behind it? | `ps:person`, `ou:org` | 3 |

Even the actor emailing you "it's me" would only be a **persona**-rung claim from a
self-interested source. False flags exist, so it would need corroboration like anything else.

## 2. What the planner says for an AWS seed (6 hops)

| Rung | With the lab today | Adding only free sources | What it takes |
|---|---|---|---|
| cluster | runnable (Synapse/MISP tags, honeypot, lake; IntelOwl if egress allowed) | more routes | passive DNS is the best single purchase |
| operator-accounts | **nothing runnable** | **runnable**: sample → embedded AWS key ID → AWS account ID | free/develop tier opens it |
| persona | **nothing runnable** | **runnable but weak** (best p≈0.04): domain → public code → commit identity → handle reuse | underground-forum intel is the strongest single source ($$$) |
| identity | nothing runnable | **still nothing runnable** | **every route ends in legal process** (or breach data for a lead) |

That last row is the honest answer to "how do I get there". For a private team the realistic
ceiling is a **well-evidenced persona plus a package good enough that law enforcement will
run the legal process**. The tool should help you build that package. It cannot replace the
subpoena.

## 3. The chains, in plain terms

These are the families of routes the planner enumerates. Each step names the catalog
connector that supplies it.

**A. Fan out the infrastructure (cluster rung).**
AWS IP, *in the window the actor held it* (`cloud-ranges` tells you it is EC2 and which region)
→ what the host served then: TLS cert, JARM, JA4S, SSH host key, favicon hash
(`internet-scan-history`) → every other host with the same fingerprint → their domains
(`passive-dns`) → more names on the same certs (`cert-transparency`). A reused SSH host key or
self-signed cert across instances is close to an operator signature. A C2 framework's default
JARM is not; it is shared by everyone who runs that framework.

**B. Follow the tooling into the AWS account (operator-accounts rung).**
IP → samples that talk to it (your honeypot, CAPE, `malware-repositories`) → config extraction
(`malware-config-extraction`: C2 config, build paths, wallets, **AWS access key IDs, S3 bucket
names**) → `sts:GetAccessKeyInfo` returns the **12-digit account ID** that owns the key
(`aws-key-attribution`; lookup only, never use the key) → everything that account shares
publicly: AMIs, EBS snapshots, buckets (`aws-public-resources`). This is the cheapest strong
chain in the whole catalog, and it is all free or build-it-yourself.

**C. Catch the operator logging in (operator-accounts → persona).**
Someone has to administer the C2. `upstream-netflow` (vetted, $$$) shows sessions to the
host and where they come from. Usually that is another layer (a VPN exit or a VPS), so the
chain repeats from there. `active-engagement` (canary tokens in honeypot bait, sinkholing
lapsed domains) makes the operator reveal their egress directly. It is active, so it needs
legal review.

**D. Registration and payment trails (operator-accounts → persona).**
Domains → registrant email (`whois-history`, mostly redacted since 2018; old records still
pay) → every domain registered with that email → the same email in public commits
(`code-search`), on forums, in breach records. Wallets from samples or ransom notes →
`crypto-tracing` → the **customer account at an exchange**, which is exactly what legal
process can reach.

**E. The market (persona rung).**
Tool or panel → ads and sales threads (`cybercrime-forums`) → seller account → its selectors
(Jabber/Telegram handles, payment addresses) → handle reuse across platforms
(`persona-osint`). Most cybercrime personas are built this way.

**F. Persona to person (identity rung).**
- `breach-and-stealer-data`: operators who infect their own machines leak saved logins and real
  IPs. This has historically produced strong leads, but it is a lead, never the sole basis for
  naming someone, and it needs legal and privacy review.
- `provider-legal-process`: AWS account billing/KYC, exchange KYC, email subscriber records.
  Only law enforcement can compel these; your deliverable is the evidence package.
- `behavioural-analysis` (working hours, language, keyboard layouts) supports a sponsor or
  nationality judgement and never identifies a person.

## 4. AWS-specific traps the plan has to respect

- **IP churn.** EC2 public IPs are recycled. Every pivot on an AWS IP is only valid inside the
  window the actor held it, and passive DNS or scan history outside that window describes
  someone else. *The planner does not model time windows on hops yet* (§6). Until it does,
  this is on the analyst.
- **The account may be a victim's.** Actors run infrastructure from compromised AWS accounts
  and stolen keys. A tenant ID proves "same account", not "actor's account". Corroborate before
  treating the operator-accounts rung as reached.
- **Shared fingerprints.** Default framework JARMs, CloudFront/API Gateway front ends and
  shared hosting make many unrelated hosts look alike. That is what the prevalence pruning in
  `design.md` §6.1 is for.
- **Disruption is not attribution.** An AWS abuse report gets the infrastructure taken down. It
  does not tell you who ran it, and it alerts them. Decide which you want first.

## 5. What to get, in order of cost

The planner's `acquisition_sets` lists the smallest combinations that open a route. Taken
together with section 2, a sensible order is:

| Tier | Sources | Opens |
|---|---|---|
| free / build | `cloud-ranges`, `cert-transparency`, `code-search`, `aws-key-attribution`, `aws-public-resources`, `malware-config-extraction` (CAPE already does part of this), `persona-osint`; free feeds (MalwareBazaar, ThreatFox, URLhaus, Mnemonic passive DNS) | operator-accounts via chain B; a weak persona route |
| $ | `community-sharing` (ISAC/MISP communities), urlscan.io for `web-tracking-ids`, `own-cloud-scanner` | other teams' clustering; tracking-ID reuse |
| $$ | `passive-dns`, `internet-scan-history`, `whois-history` | chain A properly, and the registration side of chain D |
| $$$ | `malware-repositories` (VT Enterprise retrohunt), `cybercrime-forums`, `upstream-netflow`, `breach-and-stealer-data`, `crypto-tracing` | the persona rung; leads toward identity |
| law enforcement | `provider-legal-process` | identity |

## 6. Limits of the planner today

- **It plans by type, not role.** An internal IP and an AWS IP are both `inet:ipv4`, so it will
  propose `lake.dns/host_queried_fqdn` (which only makes sense for internal hosts) on an AWS
  seed. Next fix: role-qualified inputs on methods (internal/external, cloud/residential).
- **No time windows on hops.** Critical for EC2 churn (§4). Next fix: carry the actor window
  from the seed through every windowed hop.
- **Hit rates are guesses** until step logs measure them.
- **Routes are capped** (20,000 per rung in ladder mode; the output says when it truncated). The
  cluster rung truncates at 6 hops, the others do not.
