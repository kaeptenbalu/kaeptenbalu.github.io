---
title: "Ping Me Maybe - When SubCrawl Started Talking to Teams"
date: 2025-09-30
author: "Manuel Boll"
tags: ["Subcrawl", "TI", "Blue Team", "Teams", "OpenSource"]
---

When you spend enough time with a research framework, you start having conversations with it.  
Sometimes those conversations go like this:

> **Me:** “Hey SubCrawl, could you just tell me when something juicy pops up?”  
> **SubCrawl:** “Sure. I’ll store it in SQLite or MISP for you.”  
> **Me:** “No, I mean like… _tell me_. Ping me.”  
> **SubCrawl:** “You want me to… talk?”

And that’s how _TeamsStorage_ was born.

- - -

1\. Why SubCrawl Needed a New Voice
-----------------------------------

The original [SubCrawl by HP Threat Research](https://github.com/hpthreatresearch/subcrawl) is a brilliant framework:  
it crawls open directories, fingerprints suspicious content, matches YARA and ClamAV rules, and stores results elegantly.

But in 2025, “store and analyze later” sometimes isn’t enough.  
If you’re knee-deep in operations sometime, you just want **real-time context**, not just a neat database.

Hence, my fork: [kaeptenbalu/subcrawl](https://github.com/kaeptenbalu/subcrawl).  
Same architecture, same philosophy — but with a few tweaks to make SubCrawl speak with you.

- - -

2\. The MISPStorage Evolution
-----------------------------

Let’s start with the older sibling — the MISP connector.

The original `MISPStorage` module was solid, but built for a world where you run a scan, go for coffee,  
and later import everything into your shiny MISP instance.

My updated version simply… **grew up**.

It now includes:

-   **Event caching**, so repeated domains don’t spam MISP with twins.
-   **tagging**, pulling Tags from URLhaus, YARA, ClamAV, Payload and TLSH.
-   **Adaptive findings logic**, creating events only when something genuinely interesting happens.
-   **Better error handling** — no more crying over one bad header field.

All of this keeps the original module’s spirit, just tuned for _real-world tempo_.  
It’s not “faster” or “better” in a marketing sense — it’s just **more conversational**.

![MISP](https://github.com/kaeptenbalu/kaeptenbalu.github.io/blob/main/assets/img/misp_subcrawl.png?raw=true).

- - -

3\. Introducing: TeamsStorage 🛰️
---------------------------------

Then there’s the extrovert in the family — `TeamsStorage`.

Where MISP is your sharing and knowledge library, TeamsStorage is your chatty assistant who bursts in shouting,

> “Hey, found an open directory full of PHP shells! You might wanna see this.”

Technically speaking, it’s a **new storage module** that sends results directly to Microsoft Teams via webhook.  
No servers, no dashboards, no MISP dependencies — just instant, formatted notifications.

Each message includes:

-   🧩 **Domain name**
-   🧬 **Detected findings** (YARA, ClamAV, Payloads)
-   🪪 **URLhaus tags**
-   📂 **Open directory detections**
-   (optionally) Associated `teams_id` metadata if present in results

All wrapped in tidy Markdown — because security alerts should be readable _and_ stylish.

![Teams](https://github.com/kaeptenbalu/kaeptenbalu.github.io/blob/main/assets/img/teams_subcrawl.png?raw=true).

- - -

4\. Under the Hood
------------------

The module is fully compatible with the SubCrawl core, implemented as a standard storage class.

It uses:

-   `dataclasses` for clean data aggregation
-   A dedicated `_analyze_url_content()` method to unify module results
-   Timeout-hardened requests to avoid hanging on external APIs
-   Simple JSON payloads for Teams (no fancy cards — because reliability > glitter)

Configuration is as simple as adding this to your `config.yml`:

```
teams:
  webhook_url: "https://outlook.office.com/webhook/your-webhook-url"
```

Then, run SubCrawl like this:

```
python3 subcrawl.py -f urls.txt -p YARAProcessing,ClamAVProcessing -s MISPStorage,TeamsStorage
```

That’s it. The next time SubCrawl hits something interesting, your Teams channel lights up faster than your caffeine tolerance.

- - -

5\. The Takeaway
----------------

SubCrawl didn’t change at its core — it just found new ways to speak. MISPStorage got a vocabulary upgrade; TeamsStorage got a microphone.

One stores intelligence; the other shares it. And together, they make sure no “Index of /backups” hides quietly again.

- - -

**Bottom line:**  
Threat intelligence shouldn’t only collect information — it should communicate it. Sometimes that means structured events. Sometimes, it just means a friendly ping saying:

“Hey, I think you’ll want to see this one.”

- - -

Tags: #subcrawl #misp #teams #cti #automation #opensource