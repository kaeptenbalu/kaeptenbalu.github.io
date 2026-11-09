---
title: "A Sinkhole for Telegram Webhooks: Architecture, Traffic and Three Cases"
date: 2026-11-09
author: "Manuel Boll"
tags: ["Research","Threat Intelligence","Telegram","Sinkhole","Caddy","PocketBase"]
description: "A Telegram webhook is just a URL. When the domain behind it changes hands, Telegram keeps delivering. I pointed a handful of domains that used to host criminal bot infrastructure at a small server and logged what arrived: 5.47 million updates from 32,781 bots in 40 days. This post covers how the sinkhole is built, what the traffic says about where these bots live, and three cases that are worth a closer look."
image: "/img/posts/webhook_sinkhole.svg"
images: ["/img/posts/webhook_sinkhole.png"]
---


A Telegram bot has to get its updates from somewhere. Either it asks for them with `getUpdates`, or it tells Telegram once, with `setWebhook`, where to send them, and from then on every message, button press and join request arrives as an HTTPS POST at that URL. The webhook is the convenient option, and it has one property nobody thinks about when they set it: Telegram does not care who owns the URL. It resolves the hostname, opens a TLS connection, and posts the update. If the domain has changed hands since `setWebhook` was called, the new owner gets the update.

I ended up owning a handful of domains that used to sit behind exactly that kind of setup. The webhooks of a few tens of thousands of bots still pointed at them, so I put a small server behind the DNS and started writing down what Telegram delivered. This post is about that server. It covers how it is built, what forty days of traffic look like in aggregate, and a few cases that are interesting without anybody in them being named.

**At a glance:**

- 40 days, 5,471,500 webhook deliveries, 32,781 distinct bots, 218,960 distinct chats.
- 78% of the bots carry their **full bot token in the webhook path**. Owning the domain gives you the token.
- On day one, two thirds of all messages were between one and 24 hours old. That was Telegram flushing its queue.
- Subdomains I did not know about doubled the daily volume the moment I added a wildcard.
- The population is overwhelmingly Arabic-speaking. The Chinese-language traffic looks almost entirely like spam *sent to bots*.
- One channel posts exactly 2,326 spreadsheets of "leads" every day. A second market sells sick notes that supposedly show up in the official Saudi health app.

No message content, no usernames, no chat titles, no sinkholed domains and no addresses of mine appear below. Every number in this post comes from a query against the raw logs or the corpus built from them, and I say which.

- - -

## 1. How a webhook ends up at my door

The mechanics are in the Bot API documentation, and three sentences from it carry the whole project.

The first is that the two delivery methods are mutually exclusive. A bot with a webhook set does not get updates from `getUpdates`, and while the webhook is set, Telegram treats the URL as the bot's only inbox.

The second is about what counts as delivered:

> In case of an unsuccessful request (a request with response HTTP status code different from 2XY), we will repeat the request and give up after a reasonable amount of attempts.

So any 2xx response consumes the update. Telegram does not keep a copy and the bot owner never sees it. A sinkhole that answers `200` is, from Telegram's point of view, a perfectly healthy bot backend.

The third is about storage:

> Incoming updates are stored on the server until the bot receives them either way, but they will not be kept longer than 24 hours.

That one shows up in the data on day one (section 3).

How does a bot's webhook end up on a domain that someone else can later own? Mostly through bot builders. These are platforms where you paste a token from BotFather, click a few buttons and get a working bot, and the platform calls `setWebhook` for you with a URL on its own domain. When that domain lapses, gets seized, or is simply abandoned, every bot ever created on the platform still points at it. The operators of those bots never typed the URL themselves, so most of them have no idea it is there.

- - -

## 2. The build

The server is deliberately boring. One small VPS, IPv4 only, a generic hostname, and four moving parts:

```
Telegram (149.154.160.0/20, 91.108.4.0/22)
        │  HTTPS POST /<whatever the bot builder chose>
        ▼
     Caddy  ── not Telegram? ──► 403
        │  on-demand TLS, ask endpoint decides which names get a cert
        ▼
  sinkhole (Python, 127.0.0.1)  ──►  one JSONL line per request
        │
        ├──► importer every 5 min  ──►  PocketBase (aggregates per bot/chat/day)
        └──► corpus builder        ──►  SQLite (one row per message, for analysis)
```

**Caddy** terminates TLS and does the only real access control. The sinkhole sites only answer the two networks Telegram documents for webhook delivery, plus localhost. Everything else gets a 403 and never reaches the application. The firewall mirrors that: apart from one unrelated collector endpoint, 443 is closed to everyone but the Telegram ranges. Port 80 has to stay open to everyone, because certificates are issued with HTTP-01 and the ACME validation servers have to be able to reach it.

**On-demand TLS** is what makes the setup work without knowing every hostname in advance. Bot builders like subdomains, and I did not have a list of them. With on-demand TLS, Caddy gets a certificate the first time a TLS handshake asks for a name. To stop that from turning into a certificate vending machine for random scanners, every request goes through a small `ask` endpoint first. It only says yes to one or two labels under the domains I actually hold, and every decision is logged. Wildcard DNS resolves `*.domain` and `*.*.domain` to the same box, and the Caddy catch-all covers both depths.

**The receiver** is about 160 lines of Python. It reads the body, writes one JSON line with timestamp, host, path, source address and the parsed update, and answers:

```python
if plausible_post:
    return JSONResponse({"ok": True})
```

That reply is the most important line in the whole project, for a reason that has nothing to do with logging. Telegram lets a webhook *answer* an update with a Bot API method call in the response body. A reply like `{"method": "sendMessage", "chat_id": …, "text": …}` gets executed as the bot. A sinkhole that echoes anything back stops being a passive observer and starts acting as tens of thousands of bots. `{"ok": true}` carries no `method`, so Telegram has nothing to execute. The reply has stayed exactly like this since the first request.

Two more details. The responses carry a fake `Server: nginx/1.18.0` header and Caddy strips `Via`, so nothing in the HTTP layer announces what is listening. And there is a purge path: a chat can be removed from the raw logs, the corpus and the database, and from then on the receiver still acknowledges updates from that chat but no longer writes them down.

Downstream, an importer aggregates the JSONL into PocketBase every five minutes (bots, chats, activity per day). A separate builder turns the raw lines into a SQLite corpus with one row per message, which is what the analysis below runs against. The raw JSONL is the source of truth and nothing deletes it automatically.

**Who else knocks.** For completeness, what does everyone who is *not* Telegram do? Over a 36-hour window of Caddy access logs, 269,241 requests reached the server. 99.4% of them came from the two Telegram ranges. The remaining 1,640 came from 612 addresses, and they are the usual background noise of any server on the internet: `/.git/config`, `/.env`, `wp-login.php`, a WordPress file-manager plugin, Laravel's `/livewire/update`, `/two-factor-challenge`, plus the regular visits from internet-wide scanners that announce themselves in the User-Agent. 1,554 of those requests ended at the redirect to HTTPS and 66 at the 403. The last 20 were Let's Encrypt fetching ACME challenges on port 80, which is the one thing that is supposed to get through.

- - -

## 3. Forty days of traffic

**Day one: Telegram empties its queue.** The first thing worth looking at is not what arrived but *when* it was written. Every message carries the Unix time it was sent, and the receiver logs the time it arrived, so the difference is the delivery delay.

| Delay between send and delivery | Day 1 | Day 2 | All 40 days |
|---|---|---|---|
| under 10 seconds | 45,107 | 93,953 | 4,682,918 |
| 10–60 seconds | 340 | 38 | 5,318 |
| 1 minute – 1 hour | 4,567 | 4 | 11,174 |
| 1 – 24 hours | 95,377 | 29 | 150,677 |
| 24 hours or more | 20 | 0 | 124 |

*(`message` and `channel_post` updates only. Source: raw logs, `received_ts − message.date`.)*

![Message age at delivery: on day 1, 66% of messages were 1 to 24 hours old; on day 2 practically all arrived within a minute](/img/posts/webhook_sinkhole/02_backlog.svg)

On day one, 66% of all messages were between one and twenty-four hours old. On day two, more than 99.9% arrived within ten seconds. The domains had been unreachable before the box came up, Telegram had been retrying, and once a valid TLS endpoint answered, the queue drained into it in one go. The upper edge of that backlog sits almost exactly at the 24 hours the documentation promises. The 124 messages that arrived more than a day late over the whole period are noise next to that.

This also gives a first lower bound on how long these bots had been broken without anyone fixing them. At least a day, for thousands of them, and Telegram had been keeping their mail.

**Volume.** 5,471,500 deliveries over 40 days. The median day saw 109,884, and the daily curve is flat apart from two events: the backlog on day one (163,411) and a step a few weeks in that I come back to further down.

![Webhook deliveries per day over 40 days, with the day-1 backlog and the step after the wildcard catch-all](/img/posts/webhook_sinkhole/01_daily.svg)

**What arrives.** Channel posts lead with 2.73 million, followed by messages at 2.12 million and edited channel posts at 365,262. Behind them come the service updates: 140,921 `my_chat_member`, 31,562 `chat_member` and 21,362 `chat_join_request`. A long tail includes 5,522 `business_message` updates, which only reach bots connected to a Telegram Business account. Those bots receive the private conversations of the business owner. The ratio says a lot about what these bots do. Most of them are not chatbots. They are admins of channels and groups, there to post, mirror, approve join requests and count members.

**Bots.** I count a bot as one identity per webhook route. If the path contains a full token, the bot ID in front of the colon is the identity. If it contains a numeric bot ID (`/bots/<id>/…`), that ID is the identity. Otherwise the identity is host plus path. That gives 32,781 bots:

| How the bot is identified in the URL | Bots | Requests |
|---|---|---|
| full `<bot_id>:<secret>` token in the path | 25,602 | 3,100,936 |
| numeric bot ID in the path | 7,115 | 1,255,907 |
| fixed path, one bot per route | 64 | 1,114,657 |

The distribution is extremely skewed. The busiest 1% of bots produce 67% of all traffic, the top ten alone 31%. The median bot sent five requests in forty days, and 17,258 bots, more than half, never sent more than five. Most of this population is dead weight: bots somebody created, used for a week and forgot, which still get the occasional `/start` from a stranger.

**Who stops?** 6,172 bots delivered at least one update on day one. Of those, 3,299 (53%) were still delivering on days 39 and 40. A bot that stops can mean many things: the operator noticed and moved the webhook, the bot was deleted or banned, or it simply went quiet. A bot that keeps delivering means something narrower. Its webhook has pointed at a server its owner does not control for six weeks, and nobody has changed it. I expected operators to notice faster. Most of them never look.

![Share of the 6,172 day-1 bots that still delivered on or after each day, 53% on day 39](/img/posts/webhook_sinkhole/03_survival.svg)

I also checked whether *new* bots were still being created against these webhook URLs, which would mean a bot builder was still live somewhere and handing out the dead domain. Bot IDs grow roughly with creation time, so a bot created after the sinkhole went up should carry an ID above everything seen on day one. Over 40 days that happened twice. The bots that appear later are not new, they are old bots that got their first update in a while.

**The day the traffic doubled.** A few weeks in, the daily volume roughly doubled overnight and stayed there. Nothing changed on Telegram's side. I had added the wildcard catch-all to Caddy, together with the second wildcard depth.

The effect is easy to measure, because the receiver logs the `Host` header. Within hours of the change, a handful of hostnames showed up that I had never seen before. On that first day, about eight times as many bots delivered for the first time as on a normal day in the week before. The new names have carried a large share of the traffic since.

In other words, for weeks the TLS handshakes for those names failed, Telegram retried, gave up after 24 hours, and those updates are gone. The lesson is not new, but it is rarely this measurable: if you take over a domain for a sinkhole, the apex and the subdomains you know about are a fraction of what is actually pointed at it. Wildcard DNS plus on-demand TLS with a strict `ask` check is the cheapest way to find the rest, and I should have started with it.

- - -

## 4. What owning the domain gives you

78% of the bots (25,602) have their full token in the webhook path, in the form `https://<host>/<bot_id>:<secret>`. That is not a sinkhole artefact. It is how a lot of bot frameworks and builders route updates: the token in the URL tells the backend which bot an update belongs to, and nobody needs to keep a mapping table.

It also means that whoever controls the hostname receives the token on every single request, in cleartext, in the access log. A Telegram bot token is not a session or a scoped key. It is the bot. With it you can send messages as the bot, read whatever the bot can read, change its webhook, and lock out the owner.

Telegram has offered a clean alternative since Bot API 6.1 in June 2022. `setWebhook` takes a `secret_token`, and every delivery then carries it in an `X-Telegram-Bot-Api-Secret-Token` header. The backend can verify that a request really came from the webhook it registered, and the URL no longer needs to contain anything secret. Most of the traffic here comes from builders that predate that parameter, or simply never adopted it.

What you are allowed to do with a token you receive this way is a legal question, not a technical one. I am not a lawyer, but as far as I know, in Germany using credentials that were not meant for you to get at data can run straight into §202a StGB, whether the access reads or writes and however the credentials reached you. Everything in this post is built only from what Telegram delivered to my server on its own.

**Losing the webhook does not stop a bot.** `my_chat_member` updates tell a bot how its own membership changed. In private chats they are blunt: `member → kicked` means the user blocked the bot, `kicked → member` means they unblocked it or pressed Start again.

| Transition (private chats) | Count |
|---|---|
| member → kicked (user blocked the bot) | 95,710 |
| kicked → member (user came back) | 41,961 |

95,710 blocks in forty days is a lot for bots that, from the sinkhole's side, never send anything. There are two plausible explanations and I cannot fully separate them. One is that users press Start, get no answer, and block the bot. The other is that the operators are still sending. A webhook only controls what comes *in*. Anyone with the token can keep calling `sendMessage` from anywhere, and a broadcast to a bot's subscriber list is exactly what makes thousands of people hit "block" within the same hour. Either way, losing the webhook does not stop a bot from sending, and the sinkhole has no way to see what goes out.

- - -

## 5. Who is on the other end

A sinkhole like this has no geolocation. Telegram delivers from its own networks, and there is no client IP in an update. What an update does carry is softer, and with a bit of care it is still useful.

**Client language.** The `from` object of an update often includes `language_code`, which is the interface language of the sender's Telegram app. It says nothing about nationality, and 43% of the 336,496 distinct human senders do not set it at all. Among the 190,354 who do:

![Interface language of 190,354 senders: ar 70.8%, en 20.3%, fr 2.7%, ru 2.0%, fa 0.8%, es 0.7%, my 0.4%, zh 0.3%, other 2.1%](/img/posts/webhook_sinkhole/04_languages.svg)

One small detail stands out in the tail: 292 senders use `ars`, the code for Najdi Arabic, the dialect of central Saudi Arabia, and 253 of them carry the full tag `ars-SA`.

Can you turn that into a map? Partly. A world language like Arabic, English, French, Spanish or Russian cannot be pinned to a country, and that covers 96% of everyone who sets a language at all. A language that is mainly spoken in one country is a different matter. `fa` points at Iran and Afghanistan, `my` at Myanmar, `uz` at Uzbekistan, and `pt-BR` says Brazil in its own tag. The map below draws exactly that and nothing more. Countries are shaded only where one of their main languages shows up, and the Arabic-speaking countries are hatched as a single region, because 134,755 senders with `ar` could be anywhere from Morocco to Oman.

![World map of sender app languages: Arabic-speaking countries hatched as one region with 134,755 senders, countries shaded by languages mainly spoken there, led by Persian 1,447, Burmese 784, Chinese 529, Uzbek 499 and Turkish 498](/img/posts/webhook_sinkhole/08_langmap.svg)

Read it as a lower bound for the tail, not as a census. The single-country languages add up to 6,637 senders, about 3.5% of those with a language set. Everything else on the map is the hatched block, which is the point. The time-of-day curve below is what narrows the Arabic block down.

**Script of the text.** For every chat with at least 20 letters of text, I took the dominant Unicode script. Arabic dominates 26,053 chats (519 more with a clear share of Persian-specific letters), Latin 15,759, CJK 9,291 and Cyrillic 304. The interesting part is how that splits by chat type. Channels are almost all Arabic (8,027 of 8,971). **CJK text is practically absent from channels and groups (3 chats) but dominates 9,288 private chats.** More on that below.

**Time of day.** Message volume by hour (UTC) for Arabic-language senders peaks at 18:00 and bottoms out at 03:00. In Riyadh time that is 21:00 and 06:00, a normal evening-heavy day for a population living around UTC+3. English, by contrast, is spread much more evenly over the day, which is what you get when "English" is the default setting of a lot of people who do not otherwise have much in common.

![Hourly message share for Arabic- and English-language senders in UTC, with Riyadh time; the Arabic curve peaks at 21:00 Riyadh](/img/posts/webhook_sinkhole/05_hours.svg)

Put together, the picture is consistent: overwhelmingly Arabic-speaking, with the Gulf, and Saudi Arabia in particular, at the centre. The groups and channels are Arabic, the timezone fits, and the case studies below point the same way. None of these signals is strong on its own. They agree with each other, and that is the claim.

**Bots get spam too.** The 9,288 Chinese-language private chats look like spam on every axis I can measure:

- **Client language does not match.** 86.6% of the senders in those chats report `en`, 0.8% report `zh`. That looks like accounts left on default settings, not like Chinese-speaking users.
- **They talk to many bots.** 54% of these chats show up with two or more different bots. For Arabic-language private chats that figure is 5%, for Latin-script ones 15%.
- **They advertise.** Across the corpus, private chats with five or more different bots contain a `t.me/` link or an `@handle` in 44% of their messages. For chats with exactly one bot it is 4%.

![Share of private chats reaching two or more bots: CJK 54%, Latin 15%, Arabic 5%](/img/posts/webhook_sinkhole/06_multibot.svg)

Across all scripts, 1,909 accounts wrote to five or more different bots in the sinkhole, and one of them to 386. Why would anyone spam a bot? Because a bot's private inbox is read by a human, the bot operator, and operators of bots in this ecosystem are exactly the audience for the services being advertised: account sellers, "bulk posting" services, anti-spam tools for bots, proxies. Whoever builds these campaigns harvests bot usernames and `/start`s every one of them. The sinkhole just happens to be on the receiving end of thousands of them at once.

The same industry shows up from the other side in the groups. Telegram added the ability to see "certain messages sent by other bots in groups" in Bot API 10.0 (May 2026), and since then group bots receive other bots' posts. In the first four weeks, the corpus contains 118,609 group messages authored by bots. 1,081 of those bot accounts follow one username template, a fixed prefix plus eight hex characters, and together they posted 18,472 messages into just five groups. 97% of them carry the same `@handle` in their display name, and 493 add 代发, Chinese for "posting on someone's behalf". That is not a community of bots. It looks like one service creating bots in bulk, posting for paying customers, and putting its own advert in the name of every bot it creates.

- - -

## 6. What is in the chats

To get from raw traffic to cases, every chat in the corpus (110,833 in the first four weeks) went through a three-step classification. Keyword lexicons and thresholds sorted out the chats with too little content. A language model then reviewed the candidates with the evidence messages attached. Finally I checked the results by hand, and everything I cite in a case was re-derived with SQL.

Most chats turn out to have nothing to classify. 69,058 have no text content at all, usually a `/start` and nothing else, and 30,305 have too little for any judgement. 7,321 have only a few messages, 3,269 are unremarkable and 84 stayed unclear. 796 chats were classified:

| Category | Chats |
|---|---|
| spam / marketing | 459 |
| investment fraud | 182 |
| document fraud | 24 |
| escort / sex-trade advertising | 21 |
| adult content | 19 |
| cybercrime marketplace | 14 |
| gambling | 10 |
| money laundering indicators | 4 |
| lead-list distribution (first case below) | 1 |
| drugs | 1 |
| not covered in this post | 61 |

The 61 at the bottom are two categories I am not going to discuss on a blog. They were handled separately, as was a small number of chats flagged for authorised manual review. The label "classified" is an assessment, not a verdict. The language model's part in it makes the borderline cases noisier than I would like, which is the reason the three cases below only use numbers I recomputed myself.

### The spreadsheet factory

One channel in the corpus stands out by being completely uninteresting to read and very interesting to count. It only posts files: 67,459 of them in the first four weeks, every one an `.xlsx`, every caption the same template of category, region and date.

The template parses cleanly, and the structure falls out immediately:

- **26 "home and auto" categories × 83 regions.** Homeowners, first-time buyers, foreclosure leads, expired listings, roofing, solar, HVAC, auto insurance shoppers, used car buyers, car warranty buyers and so on. The regions are US states, Canadian provinces, UK regions and Australian states.
- **42 "finance" categories × 4 countries.** Mortgage refinance, debt consolidation, credit repair, Medicare, life insurance, forex and stock traders, high-net-worth individuals, users of six named crypto exchanges, startup founders, CEOs. These only come at country level: USA, UK, Canada, Australia.

The region list has the fingerprints of a script that splits one big table by a region column. One of the US regions is literally called `Unknown`. The UK has a catch-all `England` next to the nine English regions. Canada's three territories are a single region, and so are Nova Scotia and Prince Edward Island.

![Tile map of the 83 regions covered by the lead-list channel in the USA, Canada, the UK and Australia, including Unknown-USA and England-UK](/img/posts/webhook_sinkhole/07_leadmap.svg)

26 × 83 + 42 × 4 = **2,326**. Grouped by the date in the caption, every one of the 28 dates in the window has exactly 2,326 files, with no day off and no missing combination. By delivery date it is exactly 2,326 on 22 of 27 days. Day one carried two batches because of the backlog from section 3, one later day carried a double batch as well, and three days had one or two extra posts. The posting window is just as rigid, 12:00 to 18:00 UTC. The files are small. On one sample day the 2,326 files ranged from 6 to 25 KB, median 15 KB, all with distinct file IDs. They were posted through a bot from an Arabic bot builder, which is the only reason the sinkhole saw them at all.

What I can say: this is a fully automated publishing operation that pushes about 37 MB of spreadsheets labelled as personal-data lead lists every day, aimed squarely at the people who run call-centre fraud, Medicare and insurance scams, fake roof and solar contractors, and "crypto recovery" schemes. What I cannot say is whether the files contain real people. I never downloaded a single one (the Bot API would only hand them out with the bot's token, see section 4), and a factory this regular could just as well be recycling the same old dump into fresh file names, or selling air. The category list itself is the interesting artefact. It reads like a catalogue of every scam that starts with a cold call.

### Sick notes as a service

The second case is regional, and it shows how ordinary community groups get used as an advertising surface.

In the first four weeks, 7,148 messages offered Saudi sick-leave certificates. They were spread over 81 chats (70 supergroups, 7 channels, 4 private chats) and posted from 562 different accounts. They contain 209 distinct Saudi mobile numbers. 69 of the accounts posted the offer in three or more groups.

What makes it more than generic spam is the product description. 5,129 of the 7,148 messages name *Sehhaty*, the Saudi Ministry of Health app, and 4,759 explicitly promise that the certificate will *appear* there, registered, rather than being a PDF with a stamp. Next to the plain sick note there are variants: leave for accompanying a sick relative (1,669 messages), medical reports (1,701), and certificates labelled as military (2,717).

The background matters here. According to the ministry, only Sehhaty may issue valid sick-leave reports. In March 2025 it warned that fake sick notes are a criminal offence for the issuer, the seller *and* the buyer, with up to a year in prison and a fine of up to SAR 100,000, and announced checks of sick leave against patient records ([Arabian Business](https://www.arabianbusiness.com/business/healthcare/saudi-arabia-issues-warning-over-fake-sick-leave-announces-26670-fine-and-jail-for-violators), [Gulf News](https://gulfnews.com/world/gulf/saudi/saudi-arabia-imposes-sr100000-fine-and-jail-time-for-issuing-fake-sick-leave-reports-1.500056932)). The sales pitch adapts to exactly that control. Once the only accepted proof is an entry in a government system, the product becomes the entry. Whether the sellers can actually deliver one, through an insider or a compromised clinic account, or whether "registered in Sehhaty" is just the sales line, is not something the sinkhole can answer. The claim is what the market believes buyers want.

Where it runs is the second half of the story. Only 19 of the 81 chats are dedicated document-fraud venues, and they carry 5,257 of the messages. The rest is spread across groups that are not about forgery at all. 35 of the 81 chats were classified as unremarkable, meaning their remaining content is ordinary group traffic, and the 415 sick-note ads in them sit among normal posts. Most of the posting happens in the Saudi daytime and evening, with the highest hour at 13:00 UTC (16:00 in Riyadh).

### The deposit-for-pump groups

The largest category of actual fraud in the corpus is investment fraud: 182 chats, almost all supergroups (179), with 96,017 messages in four weeks.

The classifier notes and my own review describe the same few formats. One is "VIP signal" channels that post buy targets, follow up with screenshots of four-digit percentage gains, and sell paid membership. The other, more direct, is groups that collect deposits for the "next pump round", post supposed payout receipts and thank-you messages from "investors", and promise returns of over 1,000%. 61% of the messages in these chats are photos, which fits a format that runs on screenshots of profits. The words for profit and gains appear in 25,052 messages, USDT in 8,651.

The groups do not write their own material. Of the 13,587 distinct texts longer than 40 characters, 28% appear in more than one of these chats, and 659 appear in five or more. That is mirroring, one source channel feeding a family of copy groups, each of which looks like an independent community to the people inside it.

- - -

## 7. Where it breaks

- **No ground truth on people.** `language_code` is an app setting and the script of a text is a proxy. Saying "Saudi-centred" rests on several weak signals that agree, not on one strong one.
- **I only see what the bots see.** A bot without admin rights in a group gets only commands and replies. The corpus is skewed towards bots with full read access and towards channels, so it is not a sample of Telegram.
- **Weeks lost for the hostnames I did not know.** Everything Telegram tried to deliver to them before the wildcard went in is gone.
- **"Last seen" is not "fixed".** The survival numbers in section 3 show how many bots kept delivering, not why the others stopped.
- **No files.** Nothing was downloaded. File sizes and names are metadata from the update, and anything I say about a file's content stays an inference.
- **Classification is assisted.** The category counts in section 6 include model judgements. The case studies do not depend on them.

- - -

## 8. What the sinkhole is

Nothing here is an exploit. A domain changed hands, Telegram kept doing exactly what its documentation says, and 160 lines of Python wrote it down. The interesting part is how much that reveals about the people who rely on someone else's infrastructure without ever looking at it. They put tokens in URLs because a bot builder did it for them. Their bots kept delivering for six weeks to a server they had never seen. Half of them, as far as the data shows, still have not noticed.

For defenders and platform people, the practical points are short. Use `secret_token`, and never put the bot token in the webhook URL. Check `getWebhookInfo` now and then, because `last_error_date` and a sudden drop in `pending_update_count` tell you a lot. And when a bot builder dies, its domain stays a single point of failure for every bot it ever created, long after the people who built it have moved on.

- - -

*If you run abuse or trust and safety for a platform that shows up in this data and want aggregate numbers for your part of it, get in touch.*
