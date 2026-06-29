---
title: "One IP, 500 Suspects"
date: 2025-09-12
author: "Manuel Boll"
tags: ["Threat Hunting", "commentary", "Blue Team"]
image: "/img/posts/one_ip_500_suspects.svg"
---


I recently came across an article online and found it very interesting — it tackles **Carrier-Grade NAT (CGNAT)**, something that pops up regularly in threat intelligence and abuse handling.  
The author compared it to a cancer on the internet, and honestly, I can’t disagree.  
Here are my own impressions, why it’s such a problem, and why it makes **threat hunting** even harder.

- - -

1\. IPv6 vs. IPv4 CGNAT
-----------------------

The Vodafones argument is simple:  
_“We’re running out of IPv4 addresses, so CGNAT is necessary until IPv6 takes over.”_

In reality, CGNAT delays IPv6 adoption.  
Instead of investing in upgrades, ISPs conserve IPv4 space by hiding thousands of subscribers behind shared IPs. Then they charge extra for “real” addresses or even monetize saved IPv4 space.

The result: **short-term profits** for providers, **long-term damage** for everyone else.

- - -

2\. The Problems with CGNAT
---------------------------

CGNAT was never what IPv4 was designed for, and it comes with a heavy cost:

-   **Attribution nightmare**: Hundreds of subscribers share a single IP. Abuse reports need exact timestamps and source ports — assuming the ISP even logs this.
-   **No real consumer support**: Residential users rarely have the tools or help to identify the infected device behind the NAT.
-   **Opaque by design**: ISPs often hide their CGNAT use; very few label it clearly in rDNS.

So when abuse happens, responsibility blurs — and innocent users often pay the price.

- - -

3\. Why Hunters Hate CGNAT
--------------------------

For **threat hunting**, CGNAT is pure pain:

-   **IP reputation loses value**: One compromised machine can poison an IP shared by hundreds of users.
-   **Correlation breaks**: An IP tied to multiple malware families or campaigns might just be CGNAT noise.
-   **Blocking becomes risky**: Ban a single IP, and you might knock out hundreds of clean users. Ignore it, and malicious traffic flows freely.

What’s left is a **smokescreen** — great for attackers, terrible for defenders.

- - -

4\. Abuse and Threat Intelligence Impact
----------------------------------------

From an anti-abuse perspective, CGNAT is toxic:

-   Maintaining static whitelists is impractical.
-   Attribution becomes guesswork.
-   Abuse reports pile up with little chance of isolating the real offender.

If I were an attacker, CGNAT would be my perfect cover. Guess what?  
It already is.

- - -

Conclusion
----------

CGNAT doesn’t solve problems — it creates them.  
It slows down IPv6 adoption, erodes the value of IP-based intelligence, and gives attackers a hiding place.

For defenders, it means more noise, more false positives, and fewer reliable signals.  
For ISPs, it means bigger margins.

**One IP, 500 suspects — and defenders left guessing.**

- - -

Further Reading
---------------

-   [Volt Typhoon – Constructed Intelligence or Defeated Adversary?](/news/volt-typhoon-constructed-intelligence)
-   [Plague in Your PAM – Silent, Stealthy, Persistent](/news/plague-in-your-pam)
-   [LameHug – Russians Let GPT Do the Dirty Work](/news/lamehug-russians-gpt)