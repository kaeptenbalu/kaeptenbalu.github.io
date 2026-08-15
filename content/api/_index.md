---
title: "Telegram Threat-Intelligence Feed"
label: "Read-only REST API"
---

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
| `campaign_id` | pre-computed cluster label — every record with the same value is part of the same campaign (Union-Find over the joins below, run daily on our side) |
| `malware_file_hash` | all bots a given sample used |
| `bot_token` | all samples / builds using that bot (campaign lineage) |
| `source_chat_id` | bots sharing a drop channel → same operator / campaign |
| `admins` | operator attribution across bots |

Because bots, samples and chats repeat, treat the feed as an **edge list of a graph** (sample —uses→ bot —exfiltrates-to→ chat), not a flat table, when clustering campaigns or attributing operators.

### Caveats

- A `bot_token` may already be **dead / revoked** by the time you read it (tokens are validated when first collected).
- `first_seen` is the sample's **first VirusTotal submission** (its age) — not when we discovered it (that is `created`).
- Bot / chat metadata (`chat_name`, `admins`, `commands`, `webhook`, …) is present only where the bot was live and could be queried.
- `campaign_id` is **not stable across runs.** The Union-Find pass re-numbers every cluster from 1 on each run, so the record that was `campaign_id = 549` last week may be `312` this week. Use it to group records within a single response, not as a persistent identifier — if you need a stable handle for a campaign, pin it to one of the natural join keys (a chat, a creator ID, or a shared webhook).

Background on the ecosystem: [The Telegram Malware Ecosystem (ransom-isac.com)](https://ransom-isac.com/blog/the-telegram-malware-ecosystem/).

## Update schedule

The pipeline that produces this feed runs **once per day, starting at 13:00 UTC**, as a single chain.

**Chain runtime is variable.** In a typical week the whole thing finishes between 15:30 and 18:00 UTC (2.5 – 5 h). On days with a large VT backlog it can run into the night and, in the worst case observed so far, until roughly 09:00 UTC the following day. `campaign_id` is only complete after the *last* step, which is the very last stage of the chain.

### When to pull

- **Safe window: **10:00 – 12:59 UTC**, i.e. a couple of hours before the next chain kicks off at 13:00. At that point the previous day's chain is guaranteed to have finished on all observed runs, deduplication has completed, and `campaign_id` reflects the current state of the collection.
- **Avoid pulling between 13:00 and ~18:00 Berlin.**
- **Incremental pulls (`filter=created >= "<last sync>"`) are recomendet** if you only care about new rows and do your **own correlation locally**.

### If you need stable campaign IDs

Because the Union-Find pass re-labels every cluster from `1` on each run, the `campaign_id` you saw yesterday is not the same number as today's. Two options:

- **Full pull each day.** This is the simplest way to always have a consistent set of `campaign_id` values — but it means you cannot cache old snapshots by ID.
- **Local correlation (recommended for anything long-lived).** Ignore `campaign_id` and re-compute clusters on your side over the natural join keys (`bot_token`'s bot ID prefix, `source_chat_id`, `webhook`, `admins` creator, `malware_file_hash`, `bot_description`, menu URLs, referral codes). That way you only need to fetch new rows incrementally and your own cluster labels stay stable across days.

## Authentication

Every request must include your key in the `X-API-Key` header. The API is **read-only** (only `GET` is allowed).

```bash
curl -H "X-API-Key: YOUR_API_KEY" \
  "https://YOUR-ENDPOINT/api/collections/Telegram/records?perPage=50"
```

- Missing / invalid key → `403 Forbidden`
- Rate limit exceeded → `429 Too Many Requests` (default: 30 requests/minute per key — one request every 2 seconds)
- Any non-`GET` method or other path → `403`

## Endpoint

```
GET  https://api.mboll.eu/api/collections/Telegram/records
GET  https://api.mboll.eu/api/collections/Telegram/records/{id}
```

All responses are JSON.

## Pagination

Results are paged — use `page` and `perPage` (max **500**).

```bash
curl -H "X-API-Key: YOUR_API_KEY" \
  "https://api.mboll.eu/api/collections/Telegram/records?page=1&perPage=200"
```

## Filtering

Use the `filter` query parameter. Pass it URL-encoded, e.g. with `curl -G --data-urlencode`.

Operators: `=`  `!=`  `>`  `>=`  `<`  `<=`  `~` ; combine with `&&` / `||`; date macros `@now`, `@todayStart`, `@monthStart`, `@yearStart`.

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

# only records that were assigned to a campaign cluster (campaign_id is numeric,
# null for singletons / clusters of only one distinct sample hash)
curl -G "https://YOUR-ENDPOINT/api/collections/Telegram/records" \
  -H "X-API-Key: YOUR_API_KEY" \
  --data-urlencode 'filter=campaign_id != null' \
  --data-urlencode 'sort=campaign_id'
```

Rolling windows (e.g. "last 10 days") cannot be expressed as arithmetic in the filter — compute the date on your side and pass it as an absolute value.

## Sorting & field selection

- `sort=-created` (newest first), `sort=first_seen`, or `sort=campaign_id` to walk clusters in order
- `fields=bot_name,bot_token,families,first_seen,campaign_id` to limit returned fields

## Rate limits

Each API key is limited to **30 requests per minute**. Exceeding the limit returns **`429 Too Many Requests`** — back off and retry after roughly 60 seconds.

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
| `chat_name` | Chat title / first name from `getChat`. Present only where the bot was still a member and could be queried. |
| `user_count` | Member count from `getChatMemberCount`. **`0` means the count could not be retrieved (bot no longer in the chat, chat deleted, API error) — not that the chat has zero members.** Treat `0` as "unknown", not as a real value. |
| `admins` | Space-separated `userid:role` pairs from `getChatAdministrators`, e.g. `7862389560:administrator 6394819451:creator`. |
| `commands` | Registered slash-commands from `getMyCommands`. For a malware bot this is often a published list of C2 verbs. |
| `webhook` | Delivery URL from `getWebhookInfo` if the bot uses webhook mode. A non-empty value is a fresh IOC — a second piece of attacker infrastructure. |
| `bot_description` | Bot's own About text from `getMyDescription`. Often a service ad, seller handle, or MaaS template. |
| `permissions` | Bot's own `getMe` flags, stored verbatim as `can_read_all_group_messages=<true\|false> can_join_groups=<true\|false>`. |
| `campaign_id` | Integer campaign label from Union-Find clustering (records linked by shared bot ID, source chat, webhook, creator, sample hash, description, menu URL or referral code). `null` when the record is not part of a cluster with ≥ 2 distinct sample hashes. |
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
