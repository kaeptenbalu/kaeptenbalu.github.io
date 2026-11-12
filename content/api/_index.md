---
title: "Telegram Threat-Intelligence Feed"
label: "Read-only REST API"
---

A read-only REST API providing structured threat intelligence on **Telegram bots abused by malware**: the bot tokens and exfiltration chats hard-coded in malware samples, validated against the Telegram Bot API and enriched with malware family, sandbox links and bot/chat metadata.

> **Classification: TLP:AMBER+STRICT.** Use the data **only within your own organization**, on a need-to-know basis, for lawful defensive or research purposes — **no onward sharing**. Keys are personal and must not be shared; access can be revoked at any time, and any unlawful use ends it immediately.

- **→ [API reference](/api/reference/)** — quick start, endpoints, parameters, filter syntax, every field, error codes · [openapi.yaml](/api/openapi.yaml) for code generators, Postman or Insomnia
- **→ [MISP feed](/api/misp/)** — the same data as MISP events (one per bot), with setup guide, object template and taxonomy

## Requesting access

Access is granted to **vetted, trustworthy partners** only. Email **telegram@mboll.eu** with who you are and your intended use:

| Use case | Cost |
|---|---|
| **Research / non-commercial** | free of charge |
| **Commercial** | paid — contact for terms |

After approval you receive **your personal API key** by email. It works for the REST API at **`https://ti.mboll.eu`** and for the MISP feed — without a valid key every request is rejected.

## Understanding the data

Everything starts with an **observation**: a malware sample in which a bot token — and, where observed, a chat ID — is hard-coded. Around it the data is organised in entities:

| Entity | Key | What it holds |
|---|---|---|
| **Sample** | `sha256` | first VirusTotal submission, malware family, sandbox link |
| **Bot** | `bot_id` (number before `:` in the token) | current username, description, commands, webhook — stable even if the operator rotates the token |
| **Token** | `token` | which bot it belongs to; **liveness re-checked daily** (alive / dead, first and last seen alive) |
| **Chat** | `chat_id` | the exfiltration chat: type, title, description, admins incl. usernames, member count; **re-checked daily** |
| **History** | `bot_id` / `chat_id` | changed webhooks, descriptions, titles, admins, chat migrations, … |

A **token + chat** pair is an exfiltration **channel**: everything a sample sends via this token ends up in this chat. Samples, bots and chats repeat across observations, so treat the data as a **graph** (sample —uses→ token —exfiltrates-to→ chat), not a flat table:

- **Sample ↔ Bot** — a sample may ship several tokens (fallback / rotation); a bot is reused across many builds and samples.
- **Bot ↔ Chat** — operators funnel **many bots into one chat/channel**.
- **Operator ↔ Bots** — the same creator (`admins`) runs many bots.

The REST API offers both views: **`/v1/records`** — one row per observation with sample, bot and chat data merged in — and the entity endpoints `/v1/samples`, `/v1/bots`, `/v1/tokens`, `/v1/chats`, `/v1/bot-history`, `/v1/chat-history`, joined by the keys above. The [MISP feed](/api/misp/) groups everything per bot and channel.

`private`, `bot_name` and `permissions` in `/v1/records` describe the token **at the time the sample was collected**; the current state of a token is in `/v1/tokens`.

### Pivoting and clustering

The data ships **no pre-computed cluster label** — commodity malware is used by many independent operators, so automatic transitive clustering chains unrelated actors together. **Correlate locally** over the natural join keys; your own labels then stay stable across days:

| Group by | Gives you |
|---|---|
| `malware_file_hash` / `sha256` | all bots a given sample used |
| `bot_id` | all samples / builds using that bot, across token rotations |
| `source_chat_id` / `chat_id` | bots sharing a drop channel → same operator / campaign |
| `admins` (the `creator`) | operator attribution across bots |
| `relay_account` | Cloudflare Worker relays run by the same account |
| `webhook`, `menu_webapp_url`, `bot_description` | shared infrastructure, MaaS templates, seller handles, referral codes |

Beware of **shared tokens**: some tokens appear in hundreds of samples across many malware families — builder defaults or leaked tokens used by independent actors. They are valid indicators, but not a basis for attribution (the MISP feed flags them as `shared-suspected`).

Where an observation has been tied to a **named investigation or public report** by a bot, chat or token match, it carries `investigation_name` / `investigation_url`.

Background on the ecosystem: [The Telegram Malware Ecosystem (ransom-isac.com)](https://ransom-isac.com/blog/the-telegram-malware-ecosystem/).

## Update schedule

All times Europe/Berlin (UTC+1 in winter, UTC+2 in summer).

| Time | What changes |
|---|---|
| **~10:00 – 12:00** | Token liveness re-check → `/v1/tokens` (status, last seen alive) |
| **~12:00 – 12:20** | Chat check → `/v1/chats`, `/v1/chat-history` |
| **15:00 – ~00:30** | Main pipeline: new observations, malware families, bot / chat enrichment, sandbox links → `/v1/records` and all entity endpoints |
| **~00:35** | MISP feed regenerated |

- **Recommended pull window: 01:00 – 14:30** — the previous run is complete and all enrichment is current. For the freshest token and chat status, pull `/v1/tokens` and `/v1/chats` after 12:30.
- **Avoid pulling while the main pipeline runs** (15:00 – ~00:30): observations exist before their enrichment is complete.
- **Pull incrementally:** remember the newest `created` value you have seen and request `filter=created > "<that value>"` with `sort=created`.
