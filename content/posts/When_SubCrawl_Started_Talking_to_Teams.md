---
title: "Ping Me Maybe - When SubCrawl Started Talking to Teams"
date: 2025-09-30
author: "Manuel Boll"
tags: ["Open Source","Threat Intelligence","Subcrawl", "TI", "Blue Team", "Teams", "OpenSource"]
image: "/img/posts/subcrawl_teams.svg"
images: ["/img/posts/subcrawl_teams.png"]
---

[SubCrawl](https://github.com/hpthreatresearch/subcrawl) from HP Threat Research is a fine bit of engineering: it crawls open directories, fingerprints what it finds against YARA and ClamAV, tags it against URLhaus and hands the results off to a storage backend. Out of the box those backends are a console printer, a SQLite writer, and a MISP connector. That is a "collect now, look later" setup — exactly right for the batch-research use case it was built for, and slightly wrong for the operational use case I kept ending up in.

Over the last few months I forked it ([kaeptenbalu/subcrawl](https://github.com/kaeptenbalu/subcrawl)) and made two changes to the storage layer. The `MISPStorage` module was rebuilt to be less noisy against a live instance; a new `TeamsStorage` was added so a scan can shout at a Teams channel while it is still running. Nothing in the crawler or the processing modules changed. This post is the reason for the fork and what those two modules actually do.

- - -

1\. Why the storage layer needed the work
-----------------------------------------

The upstream `MISPStorage` module does what it says: for every domain SubCrawl finds anything on, it opens a MISP event and writes attributes and tags into it. In a research batch that runs once and stops, this is fine. In a rolling collection that scans the same or overlapping targets repeatedly — the way this crawler ended up being used on my side — it produces two problems.

First, it duplicates. A domain that resurfaces on the next run becomes either another event, or another attribute inside the same event, depending on which path the code takes. Either way, the analysts looking at the MISP instance start losing time to noise. A week of runs against overlapping seed lists turns a clean event view into a scrollable graveyard.

Second, the "did anything actually happen" question gets buried. A scan can turn up a URLhaus tag on a domain that has been in the same feeds for a year, or it can turn up a fresh open-directory hosting a live payload. Both end up as one event, tagged with `finding`. If you are watching MISP for something to react to, you are watching the wrong pane of glass — MISP is where old findings retire, not where new ones announce themselves.

The console printer and default SQLite writer are quiet by design, and there was no output path at all for the operational case: *a scan just found something worth interrupting me for, right now, before it moves on to the next URL*. That is the gap `TeamsStorage` was written to fill.

- - -

2\. What changed in MISPStorage
-------------------------------

The updated module keeps the shape of the upstream code and rewrites the parts that were hurting on live data.

The rewrite adds:

- **Event caching per run.** A dictionary keyed by domain prevents re-fetching or re-creating the same MISP event twice inside one scan. On a batch that touches the same infrastructure across dozens of URLs, this cuts the MISP round-trips down to one per domain.
- **A tag pipeline that merges what the modules found.** URLhaus tags come first, YARA matches turn into `yara:<rulename>`, ClamAV hits add `clamav`, and payload-processing hits add `PayloadProcessing`. Anything that produces at least one of these adds `finding`, and the presence of `finding` is what downstream Splunk/MISP correlations filter on. Repetitions of the same tag on the same attribute are skipped instead of re-posted.
- **Adaptive event creation.** An event gets written when something *changes*: a new attribute, a new tag, a new payload hash. A rerun that finds the same thing it found last week no longer nudges the event, and no longer wakes up the correlation rules downstream of it.
- **Fault tolerance around URLhaus.** The upstream code will happily die on a slow URLhaus mirror or a malformed CSV row. The new version catches it, logs it, and continues — losing the URLhaus enrichment on one run is a much smaller problem than losing the whole run to it.

The MISP side still gets everything the collection sees. It just stops shouting the same thing twice.

![MISP](https://github.com/kaeptenbalu/kaeptenbalu.github.io/blob/main/assets/img/misp_subcrawl.png?raw=true)

- - -

3\. TeamsStorage — the operational path
---------------------------------------

MISP is the archive. `TeamsStorage` is what happens on the way there.

The module is a standard SubCrawl storage class (subclasses `DefaultStorage`, implements `store_result`) and does not depend on the MISP module in any way. It can be enabled on its own, or alongside `MISPStorage` when both an archive and a live notification path are wanted.

Per domain in the result set, the module walks the URL-content entries and pulls out four things:

```python
@dataclass
class Finding:
    domain: str
    teams_id: Optional[str]
    yara_tags: Set[str]
    clamav_tags: Set[str]
    payload_tags: Set[str]
    urlhaus_tags: Set[str]
    opendir_found: bool
    all_tags: Set[str]
```

Aggregation reuses the same rules as the MISP path: an `index of` in the title of an HTML response marks an open directory, YARA and ClamAV matches other than `NO_MATCHES` become tags, PayloadProcessing hits or non-empty `info` add `PayloadProcessing`, and URLhaus tags are joined in from the same CSV the upstream module already downloads. The optional `teams_id` field is a passthrough for whatever context the caller wanted attached — a case ID, a ticket ID, a channel routing hint — and comes off the URL-content object if present.

That gets rendered into a small Markdown block and POSTed straight to the Teams webhook:

```python
payload = {"text": message_text}
requests.post(self.teams_webhook_url, headers=headers, json=payload, timeout=15)
```

No adaptive cards, no attachments, no rich media. A message is one HTTP request against one URL, and the ceremony ends there. Adaptive cards are prettier, but they also give Teams more excuses to reject a message — malformed JSON in a card definition, a schema version the tenant hasn't caught up to, a rendering quirk that eats a field. The plain-text payload has stayed working across every tenant I have thrown at it, and on an alerting path reliability beats typography every time.

If there is no finding but a `teams_id` was attached, the module still sends a short "scan finished, nothing interesting" message. That is a deliberate choice: silence on a case-tagged run is ambiguous — did the scan run? did it die halfway through? did it just find nothing? — and an explicit "no findings" reply is less work for the person on the other end than the same three questions a day later.

![Teams](https://github.com/kaeptenbalu/kaeptenbalu.github.io/blob/main/assets/img/teams_subcrawl.png?raw=true)

- - -

4\. Wiring it up
----------------

Configuration is a single entry in `config.yml`:

```yaml
teams:
  webhook_url: "https://outlook.office.com/webhook/<your-webhook>"
```

Invocation stays the standard SubCrawl form. The storage arguments are a comma-separated list, so a scan can send to Teams, MISP, or both in the same run:

```bash
# Teams only
python3 subcrawl.py -f urls.txt -p YARAProcessing,ClamAVProcessing -s TeamsStorage

# Both, in the order they should run
python3 subcrawl.py -f urls.txt -p YARAProcessing,ClamAVProcessing -s MISPStorage,TeamsStorage
```

Timeouts are set conservatively (`15 s` for the Teams webhook, `20 s` for the URLhaus fetch), so a hung external service throttles the run rather than stalling it — a scan that finishes late and complete is worth more than one that finishes never.

- - -

5\. What the split buys you
---------------------------

The two modules split the responsibilities you actually have during an incident.

- **MISP** stays the source of truth. Anything the crawler finds ends up in an event that will still be there next month, correlations included.
- **Teams** is the interrupt. If something worth interrupting a human for turned up, the message arrives before the run has even finished, tagged with enough context (open-directory flag, YARA rule names, payload markers, URLhaus tags) to give the on-call a working hypothesis in the first ten seconds. What that hypothesis usually looks like: *open dir + a YARA hit for a stealer family = a fresh drop worth grabbing before it moves* is a slightly different reaction from *just a URLhaus tag on a domain that's been in the feeds for a year*, and the message has to say which one it is on sight.

SubCrawl is still the same crawler it always was. What changed is that the operational path and the archival path are now different paths, sized for what each of them has to be quick at.

- - -

### What this fork does not try to be

Two things worth naming explicitly, so nobody expects them:

- **Not a replacement for the upstream tool.** The processing modules, the crawler, the URL handling — all upstream code, unmodified. If HP ever wants to fold the ideas into upstream, that is a good day. Until then, this is a fork with two files that differ.
- **Not a full case-management surface.** The `teams_id` field is deliberately a passthrough. It's the hook that lets you route messages from a specific scan back to a specific channel or ticket, but the routing logic itself lives outside the crawler, where it belongs. Building a case tracker into a web crawler was not the goal.

- - -

If there is a third output path worth writing, it is probably a MISP-object producer that emits properly typed `url` / `payload-delivery` / `file` objects for the payload hits, so downstream correlations pick them up without any extra tagging. That is on the list. For now, the Teams module is what the scans on my side have been talking to for a couple of months, and it has been quieter than it looks — which, on an alerting path, is a compliment.
