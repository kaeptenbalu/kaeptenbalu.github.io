---
title: "Telegram Threat-Intelligence Feed"
label: "Read-only REST API"
---

A read-only REST API providing structured threat intelligence on **Telegram bots abused by malware**: the bot tokens and exfiltration chats hard-coded in malware samples, validated against the Telegram Bot API and enriched with malware family, sandbox links and bot/chat metadata.

> **Classification: TLP:AMBER+STRICT.** Use the data **only within your own organization**, on a need-to-know basis, for lawful defensive or research purposes — **no onward sharing**. Keys are personal and must not be shared; access can be revoked at any time, and any unlawful use ends it immediately.

- **→ [API reference](/api/reference/)** — quick start, data model, pivoting, update schedule, endpoints, filter syntax, every field, error codes · [openapi.yaml](/api/openapi.yaml) for code generators, Postman or Insomnia
- **→ [MISP feed](/api/misp/)** — the same data as MISP events (one per bot), with setup guide, object template and taxonomy

## Requesting access

Access is granted to **vetted, trustworthy partners** only. Email **telegram@mboll.eu** with who you are and your intended use:

| Use case | Cost |
|---|---|
| **Research / non-commercial** | free of charge |
| **Commercial** | paid — contact for terms |

After approval you receive **your personal API key** by email. It works for the REST API at **`https://ti.mboll.eu`** and for the MISP feed — without a valid key every request is rejected.

Background on the ecosystem: [The Telegram Malware Ecosystem (ransom-isac.com)](https://ransom-isac.com/blog/the-telegram-malware-ecosystem/).
