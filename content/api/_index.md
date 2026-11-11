---
title: "Telegram Threat-Intelligence Feed"
label: "Read-only REST API"
---

A read-only REST API providing structured threat intelligence on **Telegram bots abused by malware**: the bot tokens and exfiltration chats hard-coded in malware samples, validated against the Telegram Bot API and enriched with malware family, sandbox links and bot/chat metadata.

> **Classification: TLP:AMBER+STRICT.** Use the data **only within your own organization**, on a need-to-know basis, for lawful defensive or research purposes — **no onward sharing**. Keys are personal and must not be shared; access can be revoked at any time, and any unlawful use ends it immediately.

**→ [API reference](/api/reference/)** — endpoints, parameters, filter syntax, every field and its caveats, error codes · [openapi.yaml](/api/openapi.yaml) for code generators, Postman or Insomnia.

## Requesting access

Access is granted to **vetted, trustworthy partners** only. Email **telegram@mboll.eu** with who you are and your intended use:

| Use case | Cost |
|---|---|
| **Research / non-commercial** | free of charge |
| **Commercial** | paid — contact for terms |

After approval you receive **your personal API key** by email. The API is served at **`https://ti.mboll.eu`** — without a valid key every request is rejected.

## Quick start

```bash
curl -G "https://ti.mboll.eu/v1/records" \
  -H "X-API-Key: YOUR_API_KEY" \
  --data-urlencode 'filter=created >= @todayStart' \
  --data-urlencode 'sort=-created' \
  --data-urlencode 'perPage=100'
```

**Versioning:** all paths live under `/v1`. Within `v1` the response format and field semantics stay stable — fields may be added, never silently changed; a breaking change would ship as `/v2` with an overlap period.

> **Already a partner?** The legacy path `/api/collections/Telegram/records` keeps working during the transition but is **deprecated** — please switch to `/v1/records` (same parameters, same response).

## Understanding the data

The collection is a **flat, denormalized feed**: **one record ≈ one observed link between a malware sample, a bot token and (where observed) a chat**, plus enrichment. Samples, bots and chats repeat across records, so treat the feed as an **edge list of a graph** (sample —uses→ bot —exfiltrates-to→ chat), not a flat table:

- **Sample ↔ Bot** — a sample may ship several tokens (fallback / rotation); a bot is reused across many builds and samples.
- **Bot ↔ Chat** — operators funnel **many bots into one chat/channel**.
- **Operator ↔ Bots** — the same creator (`admins`) runs many bots.

### Pivoting and clustering

The feed ships **no pre-computed cluster label** — commodity malware is used by many independent operators, so automatic transitive clustering chains unrelated actors together. **Correlate locally** over the natural join keys; your own labels then stay stable across days:

| Group by | Gives you |
|---|---|
| `malware_file_hash` | all bots a given sample used |
| bot ID (the number before `:` in `bot_token`) | all samples / builds using that bot — stable even if the operator rotates the token secret |
| `source_chat_id` | bots sharing a drop channel → same operator / campaign |
| `admins` (the `creator`) | operator attribution across bots |
| `relay_account` | Cloudflare Worker relays run by the same account |
| `webhook`, `menu_webapp_url`, `bot_description` | shared infrastructure, MaaS templates, seller handles, referral codes |

Where a record has been tied to a **named investigation or public report** by a bot, chat or token match, it carries `investigation_name` / `investigation_url`.

Background on the ecosystem: [The Telegram Malware Ecosystem (ransom-isac.com)](https://ransom-isac.com/blog/the-telegram-malware-ecosystem/).

## Update schedule

The pipeline runs **once per day, starting at 15:00 Europe/Berlin** (13:00 UTC in summer, 14:00 UTC in winter). On normal days it finishes around **midnight Berlin time**; with a large VirusTotal backlog it has run into the next morning. Enrichment fields are complete only after the last step. A small relay-discovery job may add a few records around 10:00 Berlin.

- **Recommended window: 10:30 – 12:30 UTC** — the previous run has finished, deduplication is complete and all enrichment is current.
- **Avoid pulling while the chain runs** — from 15:00 Berlin until roughly midnight Berlin.
- **Pull incrementally:** remember the newest `created` value you have seen and request `filter=created > "<that value>"` with `sort=created`.
