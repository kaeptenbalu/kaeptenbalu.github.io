---
title: "MISP feed"
description: "Ingest the Telegram threat-intelligence feed into MISP: setup, object template, taxonomy and tags."
date: 2026-11-12
build:
  list: never
---

The data of the [Telegram Threat-Intelligence Feed](/api/) is also available as a **MISP feed**: one MISP event per Telegram bot, updated daily. Access uses **the same personal API key** as the REST API.

> **TLP:AMBER+STRICT** applies unchanged — keep the events inside your own organization (see [step 5](#5-add-the-feed)).

## What you get

| Element | Content |
|---|---|
| **Event** | One per Telegram bot (`Telegram bot <bot_id> (@username) used by malware for exfiltration`), dated to the earliest sample. |
| **Event report „Overview“** | Human-readable summary: tokens and their liveness, channels (token + chat) with sample counts and time span, malware families, infrastructure. |
| **`telegram-bot` object** | One per **channel** = token + exfiltration chat: token, bot username and description, chat ID, name and description, **all samples (SHA-256)** using this channel, webhook / WebApp URLs, relay hosts. |
| **`telegram-account` object** | Chat creator and admins (ID, username, name), linked to the channel — where known (group / channel chats only; for private chats the chat ID already is the operator's account). |
| **`url` attribute** | The Bot API endpoint `https://api.telegram.org/bot<token>/` hard-coded in the malware (detection indicator). |

Background on the data model — channels, token liveness, shared tokens, pivoting: [Understanding the data](/api/reference/#section/Understanding-the-data).

Events are **updated in place**: a new sample, token, webhook or a dead token changes the existing event (stable UUIDs), it never creates a duplicate. Items that disappear from the data are delivered as **deleted** for 30 days, so they are removed in your MISP as well. MISP only re-downloads events that actually changed.

## Setup

Tested with MISP 2.5.51. All commands run on your MISP server; adjust `/var/www/MISP` if your installation lives elsewhere.

### 1. Install the object template (draft v0.1)

The events use an **extended version of the official `telegram-bot` object template**. It adds the fields `sha256`, `bot-description`, `chat-name`, `chat-description`, `url` and `relay`.

> **Draft v0.1 — subject to change.** The template has **not yet been submitted** to the official [misp-objects](https://github.com/MISP/misp-objects) repository; it will be proposed there once it has proven itself in practice, and fields may still change until then. The file carries template version `3` so that MISP accepts it as an update of the official version 2. **A MISP object update can reset it to the official version** — repeat this step after updating your MISP objects.

```bash
F=/var/www/MISP/app/files/misp-objects/objects/telegram-bot/definition.json
sudo cp "$F" "$F.v2.bak"
curl -s https://www.mboll.eu/api/misp/telegram-bot/definition.json | sudo -u www-data tee "$F" >/dev/null
grep '"version"' "$F"          # must show 3
```

In MISP: **Global Actions → List Object Templates → Update Objects**. `telegram-bot` must now show version **3**; if not, open the template and click **Force update**.

Download: [telegram-bot/definition.json](/api/misp/telegram-bot/definition.json)

Without the template the events still import, but the new fields are not recognised as part of the template.

### 2. Install the taxonomy (optional)

The feed's own tags (token status, relay type, …) are defined in the taxonomy `mboll-telegram`. **This step is optional:** without it, MISP creates the tags automatically as free tags on import — they work for filtering and searching all the same. Installing the taxonomy adds the descriptions of each tag and makes them available in the tag picker:

```bash
D=/var/www/MISP/app/files/taxonomies/mboll-telegram
sudo -u www-data mkdir -p "$D"
curl -s https://www.mboll.eu/api/misp/mboll-telegram/machinetag.json | sudo -u www-data tee "$D/machinetag.json" >/dev/null
```

In MISP: **Event Actions → List Taxonomies → Update Taxonomies**, then **enable** `mboll-telegram`.

Download: [mboll-telegram/machinetag.json](/api/misp/mboll-telegram/machinetag.json)

### 3. Update galaxies

**Galaxies → List Galaxies → Update Galaxies** — so malware families (Malpedia) and MITRE ATT&CK techniques appear as galaxy clusters instead of plain tags.

### 4. Get your API key

Use the personal key you received for the REST API — there is no separate feed key. Without a valid key the feed answers `403`.

### 5. Add the feed

**Sync Actions → List Feeds → Add Feed**:

| Field | Value |
|---|---|
| Enabled | ✓ |
| Name | `mboll.eu Telegram TI` |
| Provider | `mboll.eu` |
| Input Source | `Network` |
| URL | `https://ti.mboll.eu/misp` (no trailing slash) |
| Source Format | `MISP Feed` |
| Headers | `X-API-Key: YOUR_API_KEY` |
| **Distribution** | **`Your organisation only`** — required by TLP:AMBER+STRICT |
| Caching enabled | optional — enables correlation of the feed against your own data without importing it |
| Auto Publish | optional — publishes events right after import / update |

Click **Submit**.

### 6. Preview and fetch

In **Sync Actions → List Feeds**, next to your feed:

1. **Preview** (eye icon) — shows the event index without importing anything. If you see the list, URL and key are correct.
2. **Fetch and store all feed data** (download icon) — imports the events. Afterwards they appear under **Event Actions → List Events** with the organisation `mboll.eu`.

> **First fetch:** the feed contains about 18,000 events. MISP downloads them one by one, which takes a while; depending on your background-worker limits (PHP `memory_limit` / `max_execution_time`) the job may stop before the end. Simply **run the fetch again** — already imported events are skipped. Afterwards only changed events are downloaded.

### 7. Fetch daily

The feed is regenerated **once a day around 00:35 Europe/Berlin**. Fetch it afterwards, e.g. with a cron job on the MISP server:

```bash
# m h dom mon dow  command   (user id 1 = your admin user, last argument = feed id or "all")
30 2 * * *  /var/www/MISP/app/Console/cake Server fetchFeed 1 <FEED_ID>
```

## Keeping it inside your organisation

- Keep the feed's **Distribution** at **Your organisation only**. Events with this distribution are not synchronised to other MISP instances.
- Every event carries **`misp:should-not-sync`**. MISP does not enforce this tag by itself — if your instance has sync partners, add the tag as an **exclusion in the push rules** of each server.
- **`PAP:AMBER`**: search for the indicators in your own data and services, but **do not use the bot tokens** against Telegram (no `getUpdates`, no messages, no webhook changes) — the operator would notice.

## Tags

| Tag | Where | Meaning |
|---|---|---|
| `tlp:amber+strict` | event | Internal use only, no onward sharing. |
| `PAP:AMBER` | event | Passive use and non-attributable lookups; no interaction with the bots. |
| `misp:should-not-sync` | event | Do not synchronise to other MISP instances. |
| `mboll-telegram:token-status="alive\|dead\|unknown"` | token, event | On a token: status of exactly this token at the latest daily check. On the event: `alive` if at least one token of the bot is alive. |
| `mboll-telegram:usage="shared-suspected"` | event | Many samples across several families use this token — likely a builder default or leaked token used by independent actors. **Do not attribute on this bot alone.** |
| `mboll-telegram:indicator-scope="operator-specific\|shared-service"` | URL | Whether a URL belongs to the operator or to a generic service (webhook relays, bot builders). |
| `mboll-telegram:relay-type="cloudflare-worker"` | relay | The sample reaches the Bot API through a Cloudflare Worker instead of `api.telegram.org`. |
| `mboll-telegram:source="vt-sandbox\|telegram-bot-api"` | attribute | How the value was obtained. |
| `misp-galaxy:malpedia="…"` | sample, event | Malware family — only where the VirusTotal label maps **unambiguously** to a Malpedia family. |
| `vt-label:"…"` | sample | VirusTotal's suggested label where no unambiguous family exists (often generic AV names). |
| `investigation:"…"` | sample, event | The sample was tied to a named investigation or public report by a bot, chat or token match — never by malware family alone. |
| `misp-galaxy:mitre-attack-pattern="…"` | event | Only techniques evidenced by the data: Exfiltration Over Web Service (T1567) and Web Service (T1102) always; Bidirectional Communication (T1102.002) if the sample polls commands; Proxy (T1090) if a relay is used. |

### Detection (`to_ids`)

`to_ids` is set for SHA-256 hashes, the Bot API endpoint URLs, operator-specific webhook / WebApp URLs and relay hosts. It is **not** set for generic services (e.g. webhook.site, pipedream, bot builders) — blocking those would hit harmless traffic.

## Technical details

The feed files (`manifest.json`, one `<uuid>.json` per event, `hashes.csv`) are listed in the [API reference](/api/reference/#tag/MISP-feed). Questions: **telegram@mboll.eu**
