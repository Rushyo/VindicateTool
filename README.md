# Vindicate

![Supported](https://img.shields.io/badge/supported-yes-brightgreen)
[![GitHub stars](https://img.shields.io/github/stars/Rushyo/VindicateTool.svg?style=social&label=Star&maxAge=2592000)](https://GitHub.com/Rushyo/complexkspinstaller/stargazers/)

An LLMNR/NBNS/mDNS Spoofing Detection Toolkit for network administrators

## What is Vindicate?

Vindicate is a tool which detects name service spoofing, often used by IT network attackers to steal credentials (e.g. Windows Active Directory passwords) from users. It's designed to detect the use of hacking tools such as [Responder](https://github.com/SpiderLabs/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh), [NBNSpoof](https://en.kali.tools/all/?tool=881&PageSpeed=noscript), and Metasploit's [LLMNR](https://www.rapid7.com/db/modules/auxiliary/spoof/llmnr/llmnr_response), [NBNS](https://www.rapid7.com/db/modules/auxiliary/spoof/nbns/nbns_response), and [mDNS](https://www.rapid7.com/db/modules/auxiliary/spoof/mdns/mdns_response) spoofers, whilst avoiding false positives. This can allow a Blue Team to quickly detect and isolate attackers on their network. It takes advantage of the Windows event log to quickly integrate with an Active Directory network, or its output can be piped to a log for other systems.

There's a diagram explaining spoofing attacks and how Vindicate works [on the wiki](https://github.com/Rushyo/VindicateTool/wiki/How-it-works).

Requires .NET Framework 4.5.2 

### What is LLMNR/NBNS/mDNS spoofing and why do I need to detect it?

* pentest.blog: [What is LLMNR & WPAD and How to Abuse Them During Pentest ?](https://pentest.blog/what-is-llmnr-wpad-and-how-to-abuse-them-during-pentest/)
* Aptive Consulting: [LLMNR / NBT-NS Spoofing Attack Network Penetration Testing](https://www.aptive.co.uk/blog/llmnr-nbt-ns-spoofing/)
* GracefulSecurity: [Stealing Accounts: LLMNR and NBT-NS Spoofing](https://www.gracefulsecurity.com/stealing-accounts-llmnr-and-nbt-ns-poisoning/)

TL;DR - Attackers might be stealing all sorts of credentials on your network (everything from Active Directory credentials to personal email accounts to database passwords) from right under your nose and you may be completely unaware it's happening.

### Licensing

Vindicate is copyright Danny 'Rushyo' Moules and provided under a GPLv3 license without warranty. See LICENSE.

## Quick Start

Download VindicateTool.

Open a non-elevated command prompt, or PowerShell prompt, and type the following in the `ReleaseBinaries` sub-folder:

```powershell
./VindicateCLI.exe
```

Vindicate will now search for LLMNR/NBNS/mDNS spoofing and report back.

If you see nothing happening, try using the `-v` flag to get more verbose output on what Vindicate is doing.

If there is spoofing going on, you may see something like this:

```
Received mDNS response from 192.168.1.24 claiming 192.168.1.24
Spoofing confidence level adjusted to Medium
Received LLMNR response from 192.168.1.24 claiming 192.168.1.24
Received NBNS response from 192.168.1.24 claiming 192.168.1.24
Detected active WPAD service at 192.168.1.24 claiming HTTP Code OK
Spoofing confidence level adjusted to Certain
Detected active WPAD service at 192.168.1.24 claiming HTTP Code OK
Detected active WPAD service at 192.168.1.24 claiming HTTP Code OK
Detected service on SMB TCP port at 192.168.1.24
Detected service on SMB TCP port at 192.168.1.24
Detected service on SMB TCP port at 192.168.1.24
```

This indicates an ongoing attack (in this case, Responder running with defaults).

Use ESC to close the application.

### Get more info

Use `-v` with VindicateCLI to get more verbose output.

### Setting the right IP address

Vindicate will try to auto-detect your IP address. If you have multiple network interfaces, this might provide an address on the wrong network. If so, use `-a` to enter the IP address you'd like to use.

### Enabling event log reporting

Open an elevated (Administrator) PowerShell prompt and type the following:

```powershell
New-EventLog -Source "VindicateCLI" -LogName "Vindicate"
```

Run the CLI app with `-e` to enable event logging. The service uses the Windows Event Log (or Mono equivalent) automatically.

Event logs are stored under `Applications and Services Log\Vindicate`.

## Service Installation

Run from an elevated PowerShell prompt (changing FULL\PATH\TO\ and ARGSHERE as appropriate):

```powershell
New-EventLog -Source "VindicateService" -LogName "Vindicate"
sc.exe create "VindicateService" DisplayName="Vindicate" start=auto binPath="FULL\PATH\TO\ReleaseBinaries\VindicateService.exe ARGSHERE" obj="NT Authority\NetworkService"
sc.exe start "VindicateService"
```

The service supports all flags the CLI app does except `-e` (event logs are always enabled). Don't forget to update the local firewall!

## Useful Stuff

### Build prerequisites

Requires .NET Framework 4.5.2 and Visual Studio 2015 or higher to build. Pre-compiled binaries are available under ReleaseBinaries.

### Firewall Configuration

Inbound:

* UDP Local 49501 <- Remote 5355 (LLMNR)
* UDP Local 49502 <- Remote 137 (NBNS)
* UDP Local 5353 <- Remote 5353 (mDNS)

Outbound:

* UDP Local 49501 -> Remote 5355 (LLMNR)
* UDP Local 49502 -> Remote 137 (NBNS)
* UDP Local 5353 -> Remote 5353 (mDNS)
* TCP Local 49152-65535* -> Remote 80 (WPAD)
* TCP Local 49152-65535* -> Remote 443 (WPAD)
* TCP Local 49152-65535* -> Remote 139 (SMB)

*Ephemeral ports. Given values assume Windows Vista+

### Important Event IDs

* 7 - This indicates that Vindicate has upgraded its confidence in an assessment that spoofing* is going on.
* 8 - Detected a WPAD (Web Proxy Auto-Detection) service at a spoofed* location.
* 11 - Detected an SMB (Server Message Block) service at a spoofed* location.
* 6 - Received a spoofed* response to a name lookup.

A full list can be found [on the wiki](https://github.com/Rushyo/VindicateTool/wiki/Event-IDs).

### Notes

* *By default, Vindicate uses lookup names that shouldn't exist in any network but look semi-realistic to an attacker who might be watching, to avoid false positives where you have real services that might rely on these name lookups. If systems with those names really do exist on your network, Vindicate will give false positives.
* Due to the above, Vindicate works best with custom flags that are tuned to your environment. Use `-h` to get help.
* As Vindicate uses a partial custom name service implementation written in .NET, it works even if multicast resolution is disabled on the client.
* Vindicate currently mostly relies on getting a WPAD response, with the SMB detection being very basic (it just checks if an SMB port is in use). If Vindicate is adopted and used I'll write an SMB client to properly verify SMB servers and increase Vindicate's confidence in its detection.
* Vindicate can detect mDNS spoofing (often associated with Mac OS), but this detection won't work on Windows if multicast resolution is enabled as a required port is in use by the operating system. Consider [disabling it](http://www.computerstepbystep.com/turn-off-multicast-name-resolution.html) for security reasons anyway (and reset the DNS Service to apply the changes).
* Vindicate does not require administrative permissions to run and is sad if you run it with high privileges.
* Vindicate can send false credentials to an attacker to frustrate their movements. Check out the `-u`, `-p`, and `-d` flags.
* Vindicate has been written with cross-platform use in mind, but has not been tested for this purpose yet. If this is desired, let me know with an issue and your platform.
