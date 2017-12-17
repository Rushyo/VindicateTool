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
using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace VindicateLib
{
    public class DetectorSettings
    {
        public Boolean UseLLMNR = true;
        public Boolean UseNBNS = true;
        public Boolean UsemDNS = true;
        public Boolean UseWPADProbes = true;
        public Boolean UseSMBProbes = true;
        public Boolean Verbose = true;
        public String LLMNRTarget = "wpad-proxy";
        public String NBNSTarget = "wpad-proxy";
        public String mDNSTarget = "apple-tv";
        public Int32 LLMNRPort = 49500;
        public Int32 NBNSPort = 49501;
        public Int32 mDNSPort = 5353;
        public String PreferredIPv4Address = null;
        public String NTLMUsername = "Guest";
        public String NTLMPassword = null;
        public String NTLMDomain = null;
        public Int32 SendRequestFrequency = 10000;
        
        [ExcludeFromCodeCoverage()]
        public Boolean SanityCheck()
        {
            if (!UseLLMNR && !UseNBNS && !UsemDNS)
                return false;

            if (UseLLMNR && String.IsNullOrEmpty(LLMNRTarget))
                return false;
            if (UseNBNS && String.IsNullOrEmpty(NBNSTarget))
                return false;
            if (UsemDNS && String.IsNullOrEmpty(mDNSTarget))
                return false;

            if (LLMNRPort <= 0 || LLMNRPort > 65535)
                return false;
            if (NBNSPort <= 0 || NBNSPort > 65535)
                return false;
            if (mDNSPort <= 0 || mDNSPort > 65535)
                return false;

            if (SendRequestFrequency < 100)
                return false;

            if (PreferredIPv4Address != null)
            {
                IPAddress addr;
                if (!IPAddress.TryParse(PreferredIPv4Address, out addr))
                    return false;
            }

            return true;
        }
    }
}