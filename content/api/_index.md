---
title: "API"
---

# Telegram Threat-Intelligence Feed — API

A read-only REST API providing structured threat intelligence on **Telegram bots abused by malware**

> **Classification: TLP:AMBER+STRICT.** The data may be used **only within your own organization** on a need-to-know basis and **must not be shared onward**. Use is permitted for lawful defensive and research purposes only.

## Requesting access

The API is **not public**. Access is granted to **vetted, trustworthy partners** only.

To request access, email **telegram@mboll.eu** with who you are and your intended use:

| Use case | Cost |
|---|---|
| **Research / non-commercial** | free of charge |
| **Commercial** | paid — contact for terms |

After approval you receive **your personal endpoint URL** and **your personal API key** by email. The endpoint is intentionally not published here.

## Understanding the data

The collection is a **flat, denormalized feed**: **one record ≈ one observed link between a bot and a malware sample**, plus enrichment.

### Relationships (many-to-many)

- **Sample ↔ Bot** — a single sample may ship several tokens (fallback / rotation), and a single bot is reused across many builds and samples. Both `malware_file_hash` and `bot_token` recur across records.
- **Bot ↔ Chat** — bots exfiltrate to a `source_chat_id`; operators funnel **many bots into one chat/channel**.
- **Operator ↔ Bots** — the same creator (`admins`) runs many bots.

### How to pivot / cluster

| Group by | Gives you |
|---|---|
| `malware_file_hash` | all bots a given sample used |
| `bot_token` | all samples / builds using that bot (campaign lineage) |
| `source_chat_id` | bots sharing a drop channel → same operator / campaign |
| `admins` | operator attribution across bots |

Because bots, samples and chats repeat, treat the feed as an **edge list of a graph** (sample —uses→ bot —exfiltrates-to→ chat), not a flat table, when clustering campaigns or attributing operators.

### Caveats

- A `bot_token` may already be **dead / revoked** by the time you read it (tokens are validated when first collected).
- `first_seen` is the sample's **first VirusTotal submission** (its age) — not when we discovered it (that is `created`).
- Bot / chat metadata (`chat_name`, `admins`, `commands`, `webhook`, …) is present only where the bot was live and could be queried.

Background on the ecosystem: [The Telegram Malware Ecosystem (ransom-isac.com)](https://ransom-isac.com/blog/the-telegram-malware-ecosystem/).

## Authentication

Every request must include your key in the `X-API-Key` header. The API is **read-only** (only `GET` is allowed).

```bash
curl -H "X-API-Key: YOUR_API_KEY" \
  "https://YOUR-ENDPOINT/api/collections/Telegram/records?perPage=50"
```

- Missing / invalid key → `403 Forbidden`
- Rate limit exceeded → `429 Too Many Requests` (default: 120 requests/minute per key)
- Any non-`GET` method or other path → `403`

## Endpoint

```
GET  https://YOUR-ENDPOINT/api/collections/Telegram/records
GET  https://YOUR-ENDPOINT/api/collections/Telegram/records/{id}
```

`YOUR-ENDPOINT` is provided to you by email. All responses are JSON.

## Pagination

Results are paged — use `page` and `perPage` (max **500**).

```bash
curl -H "X-API-Key: YOUR_API_KEY" \
  "https://YOUR-ENDPOINT/api/collections/Telegram/records?page=1&perPage=200"
```

Envelope: `{ "page", "perPage", "totalItems", "totalPages", "items": [...] }`. Iterate `page` from `1` to `totalPages`.

## Filtering

Use the `filter` query parameter. Pass it URL-encoded, e.g. with `curl -G --data-urlencode`.

Operators: `=`  `!=`  `>`  `>=`  `<`  `<=`  `~` (contains); combine with `&&` / `||`; date macros `@now`, `@todayStart`, `@monthStart`, `@yearStart`.

```bash
# records added to the feed today
curl -G "https://YOUR-ENDPOINT/api/collections/Telegram/records" \
  -H "X-API-Key: YOUR_API_KEY" \
  --data-urlencode 'filter=created >= @todayStart'

# samples first seen on/after a date
curl -G "https://YOUR-ENDPOINT/api/collections/Telegram/records" \
  -H "X-API-Key: YOUR_API_KEY" \
  --data-urlencode 'filter=first_seen >= "2026-07-01 00:00:00"'

# a specific malware family, newest first
curl -G "https://YOUR-ENDPOINT/api/collections/Telegram/records" \
  -H "X-API-Key: YOUR_API_KEY" \
  --data-urlencode 'filter=families ~ "asyncrat"' \
  --data-urlencode 'sort=-created'
```

Rolling windows (e.g. "last 10 days") cannot be expressed as arithmetic in the filter — compute the date on your side and pass it as an absolute value.

## Sorting & field selection

- `sort=-created` (newest first) or `sort=first_seen`
- `fields=bot_name,bot_token,families,first_seen` to limit returned fields

## Rate limits

Each API key is limited to **120 requests per minute**. Budgets are per key and independent of other partners. Exceeding the limit returns **`429 Too Many Requests`** — back off and retry after roughly 60 seconds.

To stay well within the limit:
- page with `perPage=500` (a full pull of the feed is only ~25 requests), and
- for updates, query incrementally, e.g. `filter=created >= "<your last sync timestamp>"`.

Need a higher limit for your use case? Contact **telegram@mboll.eu**.

## Field reference

| Field | Description |
|---|---|
| `bot_name` | Telegram bot username |
| `bot_token` | Observed bot API token (`bot<id>:<secret>`) |
| `malware_file_hash` | SHA-256 of the malware sample using the bot |
| `source_chat_id` | Chat/channel the bot exfiltrates to, when observed |
| `families` | Malware family/families, e.g. `trojan.msil/asyncrat` |
| `threat_categories` | Category, e.g. `trojan`, `stealer` |
| `first_seen` | First submission of the sample to VirusTotal (sample age — **not** our discovery date) |
| `chat_name`, `admins`, `commands`, `webhook`, `bot_description`, `permissions`, `user_count`, `group_name` | Bot / chat metadata where available |
| `created` / `updated` | When the record entered / last changed in this feed |

## Example response

```json
{
  "page": 1,
  "perPage": 2,
  "totalItems": 12100,
  "totalPages": 6050,
  "items": [
    {
      "bot_name": "anuZSteel_bot",
      "bot_token": "bot8122935411:AAH...",
      "families": "trojan.msil/asyncrat",
      "threat_categories": "trojan",
      "first_seen": "2025-05-10 20:58:16.000Z"
    }
  ]
}
```

## Terms of use (summary)

- **TLP:AMBER+STRICT** — internal use within your organization only; **no onward disclosure**.
- Lawful **defensive / research** use only; any unlawful use terminates access immediately.
- Do not share your API key. Access is per-partner and can be revoked at any time.
- **Commercial** use requires a paid agreement; **research / non-commercial** use is free for vetted partners.

Access requests and questions: **telegram@mboll.eu**
