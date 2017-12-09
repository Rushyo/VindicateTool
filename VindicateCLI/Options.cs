/*
    Vindicate - An LLMNR/NBNS/mDNS Spoofing Detection Toolkit
    Copyright (C) 2017 Danny Moules

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/


using System;
using CommandLine;

namespace VindicateCLI
{
    internal class Options
    {
        [Option('l', "llmnr", DefaultValue = true, Required = false, 
            HelpText = "Whether to enable LLMNR requests.")]
        public Boolean UseLLMNR { get; set; }

        [Option("llmnr-port", DefaultValue = 49500, Required = false, HelpText = "LLMNR UDP port.")]
        public Int32 LLMNRPort { get; set; }

        [Option("llmnr-lookup", DefaultValue = "ProxySvc", Required = false, HelpText = "LLMNR lookup target name.")]
        public String LLMNRTarget { get; set; }

        [Option('n', "nbns", DefaultValue = true, Required = false,
            HelpText = "Whether to enable NETBIOS-NS requests.")]
        public Boolean UseNBNS { get; set; }

        [Option("nbns-port", DefaultValue = 49501, Required = false, HelpText = "NBNS UDP port.")]
        public Int32 NBNSPort { get; set; }

        [Option("nbns-lookup", DefaultValue = "wpad-proxy", Required = false, HelpText = "NBNS lookup target name.")]
        public String NBNSTarget { get; set; }

        [Option('m', "mdns", DefaultValue = true, Required = false,
            HelpText = "Whether to enable mDNS requests. Service is fixed to UDP port 5353. Conflicts with DNS client on Windows if multicast name resolution is enabled.")]
        public Boolean UsemDNS { get; set; }

        [Option("mdns-lookup", DefaultValue = "apple-tv", Required = false, HelpText = "mDNS lookup target name (.local will be added automatically).")]
        public String mDNSTarget { get; set; }

        [Option('w', "wpad", DefaultValue = true, Required = false,
            HelpText = "Whether to test spoofed system for WPAD behaviour. Performs a HTTP request on port 80.")]
        public Boolean UseWPADProbes { get; set; }

        [Option('s', "smb", DefaultValue = true, Required = false,
            HelpText = "Whether to test spoofed system for SMB behaviour. Opens a TCP connection to port 139 from an ephemeral port.")]
        public Boolean UseSMBProbes { get; set; }

        [Option('u', "user", DefaultValue = "Guest", Required = false, HelpText = "NTLM username to spoof. If set to blank, no NTLM authentication will be used")]
        public String NTLMUsername { get; set; }

        [Option('p', "pass", DefaultValue = null, Required = false, HelpText = "NTLM password to spoof. If omitted, application will generate an random uncrackable password.")]
        public String NTLMPassword { get; set; }

        [Option('d', "domain", DefaultValue = null, Required = false, HelpText = "NTLM domain to spoof. If omitted, no domain will be used.")]
        public String NTLMDomain { get; set; }

        [Option('a', "addr", DefaultValue = null, Required = false, HelpText = "Preferred IPv4 address to use. Used for determining broadcast address and serves as SMB test source address.")]
        public String PreferredIPv4Address { get; set; }

        [Option('e', "eventlog", DefaultValue = false, Required = false, HelpText = "Logging mode. False for console only. True for console + event log.")]
        public Boolean Logging { get; set; }

        [Option('f', "frequency", DefaultValue = 10000, Required = false, HelpText = "Frequency of name service requests (in milliseconds)")]
        public Int32 Frequency { get; set; }

        [Option('v', "verbose", DefaultValue = false, Required = false,
            HelpText = "Verbose mode. Outputs informational messages to console & logs.")]
        public Boolean Verbose { get; set; }
    }
}
