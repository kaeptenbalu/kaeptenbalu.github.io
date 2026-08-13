---
title: "Volt Typhoon – Constructed Intelligence or Defeated Adversary?"
date: 2025-08-04
author: "Manuel Boll"
tags: ["Threat Intelligence","TI", "commentary"]
image: "/img/posts/volt_typhoon.svg"
images: ["/img/posts/volt_typhoon.png"]
---


In July 2025, NSA leadership told a New York audience that Volt Typhoon had **failed** to establish quiet, persistent access inside US critical infrastructure. Twelve months earlier the same agency was describing the same cluster in terms usually reserved for the closing chapter of a doctrine paper — a possibly existential cyber threat, a "dress rehearsal for digital warfare." Something in that story has to give.

The thing that gives, once you look closer, is the label. Volt Typhoon did not travel from apocalyptic threat to defeated adversary in a year. Volt Typhoon was never quite the thing the headlines had it be in the first place. It is a **construct** — a shorthand CTI writes over the top of behaviours it can observe — and the "defeat" line is what happens when the construct gets mistaken for the thing itself. Joe Slowik has been making this point for years, most recently in [The Beginning and Ending of Threat Actors](https://pylos.co/2025/08/29/the-beginning-and-ending-of-threat-actors/), and Volt Typhoon is the tidiest illustration of it yet.

- - -

1\. What Volt Typhoon actually names
------------------------------------

Volt Typhoon is a term Microsoft coined for a set of PRC-linked intrusions into US critical infrastructure. Unlike **Salt Typhoon**, which analysts have tied back to three known Chinese contractors, or **APT41**, where a US indictment names five individuals with photos on the wanted poster, the Volt Typhoon label sits on top of no known unit, no named contractor, and no charged person.

What it does sit on top of is a repeatable pattern: the same sectors targeted (energy, water, telecoms, transport), the same living-off-the-land tradecraft (`netsh`, `wmic`, PowerShell, no bespoke binaries where the built-in ones will do), the same taste for SOHO edge devices — Cisco, NetGear and Fortinet routers assembled into what Lumen later named the KV-Botnet — and operational objectives that map neatly onto PRC strategic interest in a contingency around Taiwan. That is the entire content of the label. "Volt Typhoon" means "we keep seeing this shape of activity, and it looks like it belongs to the same programme." It does not mean "there is a room in Chengdu with a nameplate on the door."

- - -

2\. How-centric vs who-centric attribution
------------------------------------------

CTI is a **how-centric** discipline. It clusters TTPs, infrastructure and malware families because those are the things a collection actually sees. It rarely reaches a specific unit, because that step demands sources CTI usually does not have: HUMINT, SIGINT, sealed indictments, treaty intel. When APT28 finally became "GRU Unit 26165" in public writing, the step happened inside a 2018 US indictment, not inside a vendor report. When APT41 became five names with photographs, the transition again happened in a courtroom filing.

Volt Typhoon has never had that step. There is no unit number attached to it, and the public reporting that would provide one has not appeared. The label therefore lives entirely inside the how-centric layer, and every claim about "defeating" or "defeating faster" implicitly happens in that layer too.

- - -

3\. Why "defeat" is the wrong verb
----------------------------------

When the NSA says Volt Typhoon failed, what is true underneath is narrower. The KV-Botnet was disrupted by a court-authorised FBI operation in early 2024. Joint advisories walked defenders through the specific living-off-the-land command sequences the cluster was leaning on. Some persistence footholds were burned; some hosts were cleaned; the stealth that made the earlier reporting alarming has been meaningfully degraded. These are real defensive wins and they are worth having.

What did not happen is that the operators went home. PRC strategic interest in US critical infrastructure has not shifted. The people, budgets, tasking and mission that produced the Volt Typhoon pattern are still in place, and the natural response to burned tradecraft in any mature programme is a rebuild rather than a retirement. Give it eighteen months and the same programme surfaces under a different colour of Typhoon, with a new loader, a different living-off-the-land recipe, and the same targeting deck.

Calling that "defeat" is a category error. What was defeated is a *label*. Whacking one mole does not close the fairground.

- - -

4\. Why this matters for defenders
----------------------------------

The practical problem is that resourcing decisions attach themselves to labels. Detections get built around a named actor. Board slides get written against a named actor. Budget lines get renewed against a named actor. When the label retires, the impression is that the risk retired with it — but the risk was never the name. The risk was the strategic interest and the capability behind it, and both of those outlive any given cluster label.

The useful defensive posture works the other way round: hunt for the behaviours, not the label. Detections wired against the specific `netsh portproxy` chains, the LSASS-access patterns, or the SOHO-router implant lifecycle that made up "Volt Typhoon" keep earning their keep after the reporting has moved on to Wave Typhoon or whatever the next name turns out to be. Detections wired against the string "Volt Typhoon" in a CTI report do not.

The same logic applies at the vendor layer. A rule named `VoltTyphoon_LoLBin_2024` retires with the label. A rule named `LoLBin_Recon_Sequence` keeps firing on the next cluster that reuses the same technique, because a well-run programme rotates callable code, not the taxonomy the defender has to reason about. Naming detections after the construct rather than the behaviour is one of the cheaper unforced errors on the blue side.

- - -

5\. The takeaway
----------------

Labels are hypotheses about clusters. They are useful for talking about the shape of activity, and they let separate reports about the same behaviour end up in the same file. They are not evidence that the behaviour has a single owner, and they are not the target of any real defensive win. Defeating a set of TTPs is not the same as defeating an adversary — adversaries adapt, TTPs rotate, only the strategic interest is durable.

Volt Typhoon is not dead. The construct has been retired ahead of schedule for reasons that read better in a Congressional hearing than in a threat model; the underlying mission has not moved. Accurate threat intelligence has to keep separating the two, or defenders spend the next budget cycle chasing a name while the operators are already halfway into the next one.

- - -

_Based on Joe Slowik's [The Beginning and Ending of Threat Actors](https://pylos.co/2025/08/29/the-beginning-and-ending-of-threat-actors/)._
