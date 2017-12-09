# Vindicate
An LLMNR/NBNS/mDNS Spoofing Detection Toolkit for network administrators

## What is Vindicate?

Vindicate is a tool which detects name service spoofing, often used by IT network attackers to steal credentials from users. It's designed to detect the use of hacking tools such as [Responder](https://github.com/SpiderLabs/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh), [NBNSpoof](http://www.mcgrewsecurity.com/tools/nbnspoof/), and [Metasploit's LLMNR spoofer](https://www.rapid7.com/db/modules/auxiliary/spoof/llmnr/llmnr_response) whilst avoiding false positives. This can allow a Blue Team to quickly detect and isolate attackers on their network. It takes advantage of the Windows event log to quickly integrate with an Active Directory network, or its output can be piped to a log for other systems.

### What is LLMNR/NBNS/mDNS spoofing and why do I need to detect it?

* pentest.blog: [What is LLMNR & WPAD and How to Abuse Them During Pentest ?](https://pentest.blog/what-is-llmnr-wpad-and-how-to-abuse-them-during-pentest/)
* Aptive Consulting: [LLMNR / NBT-NS Spoofing Attack Network Penetration Testing](https://www.aptive.co.uk/blog/llmnr-nbt-ns-spoofing/)
* GracefulSecurity: [Stealing Accounts: LLMNR and NBT-NS Spoofing](https://www.gracefulsecurity.com/stealing-accounts-llmnr-and-nbt-ns-poisoning/)

### Licensing

Vindicate is copyright Danny 'Rushyo' Moules and provided under a GPLv3 license without warranty. See LICENSE.

## Quick Start

Open a non-elevated command prompt, or PowerShell prompt, and type the following in the `VindicateTool\VindicateCLI\bin\Release` folder:

`./VindicateCLI.exe`

Vindicate will now search for LLMNR/NBNS/mDNS spoofing and report back.

### Get more info

Use `-v` to get more verbose output.

### Setting the right IP address

Vindicate will try to auto-detect your IP address. If you have multiple network interfaces, this might provide an address on the wrong network. If so, use `-a` to enter the IP address you'd like to use.

### Enabling event log reporting

Open an elevated (Administrator) PowerShell prompt and type the following:

`New-EventLog -Source "VindicateCLI" -LogName "Vindicate"`

Run the CLI app with `-e` to enable the event log. The service uses the Windows event log (or Mono equivalent) automatically.

Event logs are stored under `Applications and Services Log\Vindicate`.

## Service Installation

Run from an elevated PowerShell prompt (changing PATH\TO\ and ARGSHERE as appropriate):

`New-EventLog -Source "VindicateService" -LogName "Vindicate"`
`sc.exe create "VindicateService" DisplayName="Vindicate" start=auto binPath="`PATH\TO\\`VindicateService.exe" obj="NT Authority\NetworkService"`
`sc.exe start "VindicateService" "`ARGSHERE`"`

## Useful Stuff

### Important Event IDs

* 7 - This indicates that Vindicate has upgraded its confidence in an assessment that spoofing is going on.
* 8 - Detected a WPAD (Web Proxy Auto-Detection) service at a spoofed location.
* 11 - Detected an SMB (Server Message Block) service at a spoofed location.

### Notes

* As Vindicate uses a custom name service stack written in .NET, it works even if LLMNR and NETBIOS are disabled on the client. Since any responsible network administrator should be trying to remove these anyway, this means you can detect an attack you'd otherwise be immune to. Double win!
* Vindicate does not require administrative permissions to run and is sad if you run it with high privileges.
* Vindicate can send false credentials to an attacker to frustrate their movements. Check out the `-u`, `-p`, and `-d` flags.
* By default, Vindicate uses lookup names that shouldn't exist in any network but look semi-realistic to an attacker who might be watching, to avoid false positives where you have real services that might rely on these name lookups.
* Due to the above, Vindicate works best with custom flags that are tuned to your environment. Use `-h` to get help.
* Vindicate can detect mDNS spoofing (often associated with Mac OS), but by default this detection won't work on Windows as a required port is in use by the operating system.
* Vindicate has been written with cross-platform use in mind, but has not been tested for this purpose yet.